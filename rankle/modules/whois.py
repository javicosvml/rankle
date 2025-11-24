"""
WHOIS Lookup Module for Rankle

Performs WHOIS lookups without external API keys:
- Domain registration information
- Registrar details
- Creation/expiration dates
- Nameservers
- Registrant information (when available)
"""

import contextlib
import re
import socket
from datetime import UTC, datetime
from typing import Any

from config.settings import DEFAULT_TIMEOUT


# WHOIS servers for different TLDs
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "cc": "ccwhois.verisign-grs.com",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "nl": "whois.domain-registry.nl",
    "eu": "whois.eu",
    "be": "whois.dns.be",
    "ch": "whois.nic.ch",
    "at": "whois.nic.at",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "br": "whois.registro.br",
    "mx": "whois.mx",
    "ar": "whois.nic.ar",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "in": "whois.registry.in",
    "ru": "whois.tcinet.ru",
    "pl": "whois.dns.pl",
    "se": "whois.iis.se",
    "no": "whois.norid.no",
    "dk": "whois.dk-hostmaster.dk",
    "fi": "whois.fi",
    "cz": "whois.nic.cz",
    "sk": "whois.sk-nic.sk",
    "hu": "whois.nic.hu",
    "pt": "whois.dns.pt",
    "gr": "whois.ripe.net",
    "tr": "whois.nic.tr",
    "za": "whois.registry.net.za",
    "nz": "whois.srs.net.nz",
    "sg": "whois.sgnic.sg",
    "hk": "whois.hkirc.hk",
    "tw": "whois.twnic.net.tw",
    "kr": "whois.kr",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "ai": "whois.nic.ai",
    "tech": "whois.nic.tech",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "club": "whois.nic.club",
    "shop": "whois.nic.shop",
    "store": "whois.nic.store",
    "blog": "whois.nic.blog",
    "cloud": "whois.nic.cloud",
    # Default fallback
    "default": "whois.iana.org",
}


class WHOISLookup:
    """
    Performs WHOIS lookups using direct socket connections.

    No external API keys required - connects directly to WHOIS servers.
    """

    def __init__(self, domain: str, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize WHOIS lookup.

        Args:
            domain: Target domain to query
            timeout: Socket timeout in seconds
        """
        self.domain = domain
        self.timeout = timeout
        self.tld = self._get_tld(domain)

    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            # Handle country code second-level domains (e.g., co.uk)
            if len(parts) >= 3 and parts[-2] in [
                "co",
                "com",
                "org",
                "net",
                "gov",
                "edu",
            ]:
                return f"{parts[-2]}.{parts[-1]}"
            return parts[-1]
        return "com"

    def lookup(self) -> dict[str, Any]:
        """
        Perform WHOIS lookup.

        Returns:
            Dictionary with WHOIS information
        """
        results: dict[str, Any] = {
            "domain": self.domain,
            "available": False,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "status": [],
            "registrant": {},
            "admin": {},
            "tech": {},
            "raw": None,
            "whois_server": None,
        }

        try:
            # Get WHOIS server for TLD
            whois_server = self._get_whois_server()
            results["whois_server"] = whois_server

            # Query WHOIS server
            raw_data = self._query_whois(whois_server, self.domain)

            if raw_data:
                results["raw"] = raw_data

                # Check if domain is available
                if self._is_available(raw_data):
                    results["available"] = True
                    return results

                # Parse WHOIS data
                parsed = self._parse_whois(raw_data)
                results.update(parsed)

                # If we got a referral to another WHOIS server, query it
                referral = self._get_referral_server(raw_data)
                if referral and referral != whois_server:
                    referral_data = self._query_whois(referral, self.domain)
                    if referral_data:
                        results["raw"] = referral_data
                        parsed = self._parse_whois(referral_data)
                        results.update(parsed)

        except Exception as e:
            results["error"] = str(e)

        return results

    def _get_whois_server(self) -> str:
        """Get appropriate WHOIS server for the TLD."""
        # Check for exact TLD match
        if self.tld in WHOIS_SERVERS:
            return WHOIS_SERVERS[self.tld]

        # Check for second-level TLD (e.g., co.uk -> uk)
        if "." in self.tld:
            base_tld = self.tld.split(".")[-1]
            if base_tld in WHOIS_SERVERS:
                return WHOIS_SERVERS[base_tld]

        return WHOIS_SERVERS["default"]

    def _query_whois(self, server: str, query: str) -> str | None:
        """Query a WHOIS server directly via socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))

            # Some servers need specific query format
            if "denic.de" in server:
                query = f"-T dn,ace {query}\r\n"
            elif "jprs.jp" in server:
                query = f"{query}/e\r\n"
            else:
                query = f"{query}\r\n"

            sock.send(query.encode("utf-8"))

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            # Try different encodings
            for encoding in ["utf-8", "latin-1", "cp1252"]:
                with contextlib.suppress(UnicodeDecodeError):
                    return response.decode(encoding)

            return response.decode("utf-8", errors="ignore")

        except (TimeoutError, ConnectionRefusedError, OSError):
            return None

    def _is_available(self, raw_data: str) -> bool:
        """Check if domain appears to be available."""
        available_patterns = [
            r"no match",
            r"not found",
            r"no data found",
            r"no entries found",
            r"nothing found",
            r"domain not found",
            r"no object found",
            r"available for registration",
            r"status:\s*free",
            r"status:\s*available",
        ]

        raw_lower = raw_data.lower()
        return any(re.search(pattern, raw_lower) for pattern in available_patterns)

    def _get_referral_server(self, raw_data: str) -> str | None:
        """Extract referral WHOIS server from response."""
        patterns = [
            r"whois server:\s*(.+)",
            r"registrar whois server:\s*(.+)",
            r"refer:\s*(.+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                server = match.group(1).strip()
                # Clean up server name
                server = server.split()[0]  # Remove trailing text
                if server and "." in server:
                    return server

        return None

    def _parse_whois(self, raw_data: str) -> dict[str, Any]:
        """Parse WHOIS response into structured data."""
        result: dict[str, Any] = {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "status": [],
            "registrant": {},
            "admin": {},
            "tech": {},
        }

        # Registrar
        registrar_patterns = [
            r"registrar:\s*(.+)",
            r"sponsoring registrar:\s*(.+)",
            r"registrar name:\s*(.+)",
        ]
        for pattern in registrar_patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                result["registrar"] = match.group(1).strip()
                break

        # Creation date
        creation_patterns = [
            r"creation date:\s*(.+)",
            r"created:\s*(.+)",
            r"created on:\s*(.+)",
            r"registration date:\s*(.+)",
            r"domain registration date:\s*(.+)",
            r"registered:\s*(.+)",
            r"registered on:\s*(.+)",
        ]
        for pattern in creation_patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                result["creation_date"] = self._parse_date(match.group(1).strip())
                break

        # Expiration date
        expiry_patterns = [
            r"expir(?:y|ation) date:\s*(.+)",
            r"expires:\s*(.+)",
            r"expires on:\s*(.+)",
            r"expiration:\s*(.+)",
            r"registry expiry date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"renewal date:\s*(.+)",
        ]
        for pattern in expiry_patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                result["expiration_date"] = self._parse_date(match.group(1).strip())
                break

        # Updated date
        updated_patterns = [
            r"updated date:\s*(.+)",
            r"last updated:\s*(.+)",
            r"last modified:\s*(.+)",
            r"modified:\s*(.+)",
            r"changed:\s*(.+)",
        ]
        for pattern in updated_patterns:
            match = re.search(pattern, raw_data, re.IGNORECASE)
            if match:
                result["updated_date"] = self._parse_date(match.group(1).strip())
                break

        # Nameservers
        ns_patterns = [
            r"name server:\s*(.+)",
            r"nserver:\s*(.+)",
            r"nameserver:\s*(.+)",
            r"dns:\s*(.+)",
        ]
        nameservers = set()
        for pattern in ns_patterns:
            matches = re.findall(pattern, raw_data, re.IGNORECASE)
            for match in matches:
                ns = match.strip().lower().split()[0]
                if ns and "." in ns:
                    nameservers.add(ns)
        result["nameservers"] = sorted(nameservers)

        # Domain status
        status_patterns = [
            r"domain status:\s*(.+)",
            r"status:\s*(.+)",
        ]
        statuses = set()
        for pattern in status_patterns:
            matches = re.findall(pattern, raw_data, re.IGNORECASE)
            for match in matches:
                status = match.strip().split()[0]  # Get first word
                if status and status not in ["free", "available"]:
                    statuses.add(status)
        result["status"] = sorted(statuses)

        # Registrant info
        result["registrant"] = self._parse_contact(raw_data, "registrant")
        result["admin"] = self._parse_contact(raw_data, "admin")
        result["tech"] = self._parse_contact(raw_data, "tech")

        return result

    def _parse_contact(self, raw_data: str, contact_type: str) -> dict[str, str]:
        """Parse contact information from WHOIS data."""
        contact: dict[str, str] = {}

        patterns = {
            "name": [
                rf"{contact_type} name:\s*(.+)",
                rf"{contact_type}:\s*(.+)",
            ],
            "organization": [
                rf"{contact_type} organization:\s*(.+)",
                rf"{contact_type} org:\s*(.+)",
            ],
            "email": [
                rf"{contact_type} email:\s*(.+)",
                rf"{contact_type} e-mail:\s*(.+)",
            ],
            "country": [
                rf"{contact_type} country:\s*(.+)",
                rf"{contact_type} country code:\s*(.+)",
            ],
            "state": [
                rf"{contact_type} state:\s*(.+)",
                rf"{contact_type} state/province:\s*(.+)",
            ],
            "city": [
                rf"{contact_type} city:\s*(.+)",
            ],
        }

        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, raw_data, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    if value and value.lower() not in [
                        "redacted",
                        "data protected",
                        "not disclosed",
                    ]:
                        contact[field] = value
                    break

        return contact

    def _parse_date(self, date_str: str) -> str | None:
        """Parse various date formats from WHOIS data."""
        if not date_str:
            return None

        # Clean up date string
        date_str = date_str.strip()

        # Common date formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d.%m.%Y",
            "%Y/%m/%d",
            "%d/%m/%Y",
            "%Y%m%d",
            "%d-%m-%Y",
            "%b %d %Y",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ]

        for fmt in formats:
            with contextlib.suppress(ValueError):
                dt = datetime.strptime(date_str[:26], fmt)  # Truncate microseconds
                return dt.strftime("%Y-%m-%d")

        # Return original if parsing fails
        return date_str[:10] if len(date_str) >= 10 else date_str

    def get_days_until_expiry(self) -> int | None:
        """Calculate days until domain expiration."""
        result = self.lookup()
        expiry = result.get("expiration_date")

        if expiry:
            with contextlib.suppress(ValueError):
                expiry_date = datetime.strptime(expiry, "%Y-%m-%d")
                expiry_date = expiry_date.replace(tzinfo=UTC)
                now = datetime.now(UTC)
                return (expiry_date - now).days

        return None


def lookup_whois(domain: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Convenience function for WHOIS lookup.

    Args:
        domain: Target domain
        timeout: Socket timeout

    Returns:
        WHOIS lookup results
    """
    lookup = WHOISLookup(domain, timeout=timeout)
    return lookup.lookup()
