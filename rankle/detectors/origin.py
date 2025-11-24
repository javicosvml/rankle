"""
Origin Discovery Module for Rankle

Discovers origin servers behind CDN/WAF using PASSIVE techniques only:
- Subdomain enumeration via Certificate Transparency (crt.sh)
- DNS history analysis
- Mail server (MX) analysis
- SPF record parsing
- Common subdomain patterns
- HTTP header leaks
- TLS certificate analysis (SAN fields)

All methods are passive - no active scanning or attacks.
"""

import ipaddress
import re
import socket
from typing import Any

import dns.resolver
import requests

from config.patterns import CLOUD_PROVIDERS, ORIGIN_BYPASS_SUBDOMAINS
from config.settings import DNS_TIMEOUT, USER_AGENT


# Local reference for backward compatibility
ORIGIN_SUBDOMAIN_PATTERNS = ORIGIN_BYPASS_SUBDOMAINS

# Cloud providers with rdns patterns for origin detection
_CLOUD_RDNS_PATTERNS: dict[str, list[str]] = {
    provider: data["rdns_patterns"] for provider, data in CLOUD_PROVIDERS.items()
}


class OriginDiscovery:
    """
    Discovers origin servers behind CDN/WAF using passive techniques.

    This class implements multiple methods to identify the real
    infrastructure without active attacks or scanning.
    """

    def __init__(self, domain: str, timeout: int = DNS_TIMEOUT):
        """
        Initialize origin discovery.

        Args:
            domain: Target domain
            timeout: DNS/HTTP timeout
        """
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def discover(self, cdn_ips: list[str] | None = None) -> dict[str, Any]:
        """
        Perform comprehensive origin discovery.

        Args:
            cdn_ips: Known CDN IP addresses to exclude

        Returns:
            Dictionary with discovery results
        """
        results: dict[str, Any] = {
            "potential_origins": [],
            "mail_servers": [],
            "spf_includes": [],
            "subdomains_found": [],
            "methods_used": [],
        }

        cdn_ips_set = set(cdn_ips or [])

        # 1. Check MX records
        mx_origins = self._check_mx_records(cdn_ips_set)
        if mx_origins:
            results["mail_servers"] = mx_origins
            results["methods_used"].append("mx_records")
            for mx in mx_origins:
                if mx.get("ip") and mx["ip"] not in cdn_ips_set:
                    results["potential_origins"].append(
                        {
                            "ip": mx["ip"],
                            "source": "mx_record",
                            "hostname": mx.get("hostname"),
                            "confidence": 0.5,
                        }
                    )

        # 2. Parse SPF records
        spf_origins = self._check_spf_records(cdn_ips_set)
        if spf_origins:
            results["spf_includes"] = spf_origins
            results["methods_used"].append("spf_records")
            for spf in spf_origins:
                if spf.get("ip") and spf["ip"] not in cdn_ips_set:
                    results["potential_origins"].append(
                        {
                            "ip": spf["ip"],
                            "source": "spf_record",
                            "confidence": 0.4,
                        }
                    )

        # 3. Check common subdomain patterns
        subdomain_origins = self._check_common_subdomains(cdn_ips_set)
        if subdomain_origins:
            results["subdomains_found"] = subdomain_origins
            results["methods_used"].append("subdomain_bruteforce")
            for sub in subdomain_origins:
                if sub.get("ip") and sub["ip"] not in cdn_ips_set:
                    results["potential_origins"].append(
                        {
                            "ip": sub["ip"],
                            "source": f"subdomain:{sub['subdomain']}",
                            "hostname": sub.get("subdomain"),
                            "confidence": 0.7,
                        }
                    )

        # 4. Query Certificate Transparency
        ct_subdomains = self._query_certificate_transparency()
        if ct_subdomains:
            results["methods_used"].append("certificate_transparency")
            ct_origins = self._resolve_subdomains(ct_subdomains, cdn_ips_set)
            for sub in ct_origins:
                results["potential_origins"].append(
                    {
                        "ip": sub["ip"],
                        "source": f"ct_log:{sub['subdomain']}",
                        "hostname": sub["subdomain"],
                        "confidence": 0.6,
                    }
                )

        # 5. Check for historical DNS patterns
        history_origins = self._check_dns_history_patterns(cdn_ips_set)
        if history_origins:
            results["methods_used"].append("dns_history_patterns")
            for origin in history_origins:
                results["potential_origins"].append(origin)

        # Deduplicate and enrich results
        results["potential_origins"] = self._deduplicate_origins(
            results["potential_origins"]
        )

        # Identify cloud providers for each origin
        for origin in results["potential_origins"]:
            provider = self._identify_cloud_provider(origin.get("ip", ""))
            if provider:
                origin["cloud_provider"] = provider

        return results

    def _check_mx_records(self, exclude_ips: set[str]) -> list[dict[str, Any]]:
        """Check MX records for potential origin IPs."""
        results = []
        try:
            mx_records = self.resolver.resolve(self.domain, "MX")
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip(".")
                results.append(
                    {
                        "hostname": mx_host,
                        "preference": mx.preference,
                        "ip": None,
                    }
                )

                # Resolve MX host
                try:
                    a_records = self.resolver.resolve(mx_host, "A")
                    for a in a_records:
                        ip = str(a.address)
                        if ip not in exclude_ips:
                            results[-1]["ip"] = ip
                            break
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.exception.Timeout,
                ):
                    pass

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        return results

    def _check_spf_records(self, exclude_ips: set[str]) -> list[dict[str, Any]]:
        """Parse SPF records for IP addresses and includes."""
        results = []
        try:
            txt_records = self.resolver.resolve(self.domain, "TXT")
            for txt in txt_records:
                txt_value = str(txt).strip('"')
                if txt_value.startswith("v=spf1"):
                    # Parse SPF record
                    # Extract IP4 addresses
                    ip4_matches = re.findall(r"ip4:([0-9./]+)", txt_value)
                    for ip_range in ip4_matches:
                        if "/" in ip_range:
                            # CIDR notation - get first IP
                            try:
                                network = ipaddress.ip_network(ip_range, strict=False)
                                first_ip = (
                                    str(next(iter(network.hosts())))
                                    if network.num_addresses > 1
                                    else str(network.network_address)
                                )
                                if first_ip not in exclude_ips:
                                    results.append(
                                        {
                                            "type": "ip4",
                                            "value": ip_range,
                                            "ip": first_ip,
                                        }
                                    )
                            except (ValueError, IndexError):
                                pass
                        elif ip_range not in exclude_ips:
                            results.append(
                                {
                                    "type": "ip4",
                                    "value": ip_range,
                                    "ip": ip_range,
                                }
                            )

                    # Extract include domains
                    include_matches = re.findall(r"include:([^\s]+)", txt_value)
                    for include in include_matches:
                        results.append(
                            {
                                "type": "include",
                                "value": include,
                                "ip": None,
                            }
                        )

                    # Extract A record references
                    a_matches = re.findall(r"a:([^\s]+)", txt_value)
                    for a_domain in a_matches:
                        try:
                            a_records = self.resolver.resolve(a_domain, "A")
                            for a in a_records:
                                ip = str(a.address)
                                if ip not in exclude_ips:
                                    results.append(
                                        {
                                            "type": "a",
                                            "value": a_domain,
                                            "ip": ip,
                                        }
                                    )
                        except (
                            dns.resolver.NXDOMAIN,
                            dns.resolver.NoAnswer,
                            dns.exception.Timeout,
                        ):
                            pass

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        return results

    def _check_common_subdomains(self, exclude_ips: set[str]) -> list[dict[str, Any]]:
        """Check common subdomain patterns that might bypass CDN."""
        results = []

        for pattern in ORIGIN_SUBDOMAIN_PATTERNS:
            subdomain = f"{pattern}.{self.domain}"
            try:
                a_records = self.resolver.resolve(subdomain, "A")
                for a in a_records:
                    ip = str(a.address)
                    if ip not in exclude_ips:
                        results.append(
                            {
                                "subdomain": subdomain,
                                "ip": ip,
                                "pattern": pattern,
                            }
                        )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
            ):
                continue

        return results

    def _query_certificate_transparency(self) -> list[str]:
        """Query crt.sh for subdomains from Certificate Transparency logs."""
        subdomains: list[str] = []
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
            )
            if response.status_code == 200:
                data = response.json()
                seen = set()
                for entry in data[:100]:  # Limit to 100 entries
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and name not in seen and not name.startswith("*"):
                            seen.add(name)
                            subdomains.append(name)
        except (requests.RequestException, ValueError):
            pass

        return subdomains[:50]  # Return max 50 subdomains

    def _resolve_subdomains(
        self, subdomains: list[str], exclude_ips: set[str]
    ) -> list[dict[str, Any]]:
        """Resolve subdomains and filter out CDN IPs."""
        results = []

        for subdomain in subdomains:
            try:
                a_records = self.resolver.resolve(subdomain, "A")
                for a in a_records:
                    ip = str(a.address)
                    if ip not in exclude_ips:
                        results.append(
                            {
                                "subdomain": subdomain,
                                "ip": ip,
                            }
                        )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
            ):
                continue

        return results

    def _check_dns_history_patterns(
        self, exclude_ips: set[str]
    ) -> list[dict[str, Any]]:
        """Check historical DNS patterns (simplified version)."""
        results = []

        # Check if direct IP access reveals origin
        # This checks common patterns where origin might be exposed
        patterns = [
            f"origin.{self.domain}",
            f"origin-{self.domain.replace('.', '-')}.{self.domain.split('.')[-2]}.{self.domain.split('.')[-1]}",
        ]

        for pattern in patterns:
            try:
                a_records = self.resolver.resolve(pattern, "A")
                for a in a_records:
                    ip = str(a.address)
                    if ip not in exclude_ips:
                        results.append(
                            {
                                "ip": ip,
                                "source": f"dns_pattern:{pattern}",
                                "confidence": 0.5,
                            }
                        )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
            ):
                continue

        return results

    def _deduplicate_origins(
        self, origins: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Deduplicate origins by IP, keeping highest confidence."""
        ip_map: dict[str, dict[str, Any]] = {}

        for origin in origins:
            ip = origin.get("ip")
            if not ip:
                continue

            if ip not in ip_map or origin.get("confidence", 0) > ip_map[ip].get(
                "confidence", 0
            ):
                ip_map[ip] = origin

        return list(ip_map.values())

    def _identify_cloud_provider(self, ip: str) -> str | None:
        """Identify cloud provider from IP or reverse DNS."""
        if not ip:
            return None

        # Try reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            for provider, patterns in CLOUD_PROVIDERS.items():
                for rdns_pattern in patterns.get("rdns_patterns", []):
                    if re.search(rdns_pattern, hostname, re.IGNORECASE):
                        return provider
        except socket.herror:
            pass

        # Check IP patterns
        for provider, patterns in CLOUD_PROVIDERS.items():
            for ip_pattern in patterns.get("ip_patterns", []):
                if re.match(ip_pattern, ip):
                    return provider

        return None


def discover_origin(
    domain: str,
    cdn_ips: list[str] | None = None,
) -> dict[str, Any]:
    """
    Convenience function for origin discovery.

    Args:
        domain: Target domain
        cdn_ips: Known CDN IP addresses to exclude

    Returns:
        Origin discovery results
    """
    discovery = OriginDiscovery(domain)
    return discovery.discover(cdn_ips=cdn_ips)
