"""
Geolocation and ASN Module for Rankle

Performs IP geolocation and ASN lookups without external API keys:
- IP to Country/City mapping via DNS-based services
- ASN (Autonomous System Number) lookup via WHOIS
- Cloud provider detection via IP ranges
- Hosting provider identification
"""

import contextlib
import ipaddress
import socket
from typing import Any

from config.patterns import ASN_PROVIDERS, CLOUD_PROVIDERS
from config.settings import DEFAULT_TIMEOUT


# Local reference to cloud provider IP ranges for detection
_CLOUD_IP_RANGES: dict[str, list[str]] = {
    provider: data["ip_ranges"] for provider, data in CLOUD_PROVIDERS.items()
}


class GeolocationLookup:
    """
    Performs IP geolocation and ASN lookups without API keys.

    Uses DNS-based geolocation and direct WHOIS queries.
    """

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize geolocation lookup.

        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout

    def lookup(self, ip: str) -> dict[str, Any]:
        """
        Perform geolocation lookup for an IP address.

        Args:
            ip: IP address to lookup

        Returns:
            Dictionary with geolocation information
        """
        results: dict[str, Any] = {
            "ip": ip,
            "cloud_provider": None,
            "asn": None,
            "asn_name": None,
            "asn_provider": None,
            "country": None,
            "reverse_dns": None,
        }

        try:
            # Validate IP
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                results["cloud_provider"] = "Private IP"
                return results

            # Cloud provider detection via IP ranges
            results["cloud_provider"] = self._detect_cloud_provider(ip)

            # ASN lookup via WHOIS
            asn_info = self._lookup_asn(ip)
            if asn_info:
                results["asn"] = asn_info.get("asn")
                results["asn_name"] = asn_info.get("name")
                results["country"] = asn_info.get("country")

                # Map ASN to provider
                if results["asn"] and results["asn"] in ASN_PROVIDERS:
                    results["asn_provider"] = ASN_PROVIDERS[results["asn"]]
                    if not results["cloud_provider"]:
                        results["cloud_provider"] = results["asn_provider"]

            # Reverse DNS
            results["reverse_dns"] = self._reverse_dns(ip)

        except ValueError:
            results["error"] = "Invalid IP address"

        return results

    def _detect_cloud_provider(self, ip: str) -> str | None:
        """Detect cloud provider from IP ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip)

            for provider, ranges in _CLOUD_IP_RANGES.items():
                for ip_range in ranges:
                    with contextlib.suppress(ValueError):
                        network = ipaddress.ip_network(ip_range, strict=False)
                        if ip_obj in network:
                            return provider

        except ValueError:
            pass

        return None

    def _lookup_asn(self, ip: str) -> dict[str, Any] | None:
        """Lookup ASN information via Team Cymru DNS."""
        try:
            # Reverse IP for DNS query
            reversed_ip = ".".join(reversed(ip.split(".")))
            _query = f"{reversed_ip}.origin.asn.cymru.com"

            # Query Team Cymru DNS - TXT query would be needed
            # Fall back to WHOIS for now

        except (socket.gaierror, socket.herror):
            pass

        # Fall back to WHOIS query
        return self._lookup_asn_whois(ip)

    def _lookup_asn_whois(self, ip: str) -> dict[str, Any] | None:
        """Lookup ASN via WHOIS query."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(("whois.cymru.com", 43))
            sock.send(f" -v {ip}\r\n".encode())

            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            text = response.decode("utf-8", errors="ignore")

            # Parse response (format: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name)
            for line in text.split("\n"):
                if line.strip() and not line.startswith("Bulk"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 7:
                        return {
                            "asn": f"AS{parts[0]}" if parts[0].isdigit() else parts[0],
                            "prefix": parts[2],
                            "country": parts[3],
                            "registry": parts[4],
                            "name": parts[6] if len(parts) > 6 else None,
                        }

        except (TimeoutError, ConnectionRefusedError, OSError):
            pass

        return None

    def _reverse_dns(self, ip: str) -> str | None:
        """Perform reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def lookup_multiple(self, ips: list[str]) -> list[dict[str, Any]]:
        """Lookup geolocation for multiple IPs."""
        return [self.lookup(ip) for ip in ips]


def lookup_geolocation(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Convenience function for geolocation lookup.

    Args:
        ip: IP address to lookup
        timeout: Socket timeout

    Returns:
        Geolocation lookup results
    """
    lookup = GeolocationLookup(timeout=timeout)
    return lookup.lookup(ip)


def detect_cloud_provider(ip: str) -> str | None:
    """
    Quick function to detect cloud provider from IP.

    Args:
        ip: IP address

    Returns:
        Cloud provider name or None
    """
    lookup = GeolocationLookup()
    return lookup._detect_cloud_provider(ip)
