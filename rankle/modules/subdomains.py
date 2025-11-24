"""
Subdomain Discovery Module for Rankle

Discovers subdomains through passive techniques:
- Certificate Transparency logs (crt.sh)
- DNS zone analysis
- Common subdomain patterns
- Historical DNS data
"""

import contextlib
import re
from typing import Any

import dns.resolver
import requests

from config.patterns import COMMON_SUBDOMAINS
from config.settings import DEFAULT_TIMEOUT, DNS_TIMEOUT


# Extended subdomain list (adds to base COMMON_SUBDOMAINS)
_EXTENDED_SUBDOMAINS = COMMON_SUBDOMAINS + [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "secure",
    "vpn",
    "m",
    "shop",
    "ftp",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "app",
    "mobile",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "files",
    "download",
    "support",
    "help",
    "docs",
    "status",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "uat",
    "qa",
    "prod",
    "production",
    "internal",
    "intranet",
    "extranet",
    "gateway",
    "proxy",
    "lb",
    "load",
    "edge",
    "origin",
    "backend",
    "frontend",
    "web",
    "www2",
    "www3",
    "old",
    "new",
    "legacy",
    "v1",
    "v2",
    "v3",
    "cms",
    "wp",
    "wordpress",
    "cpanel",
    "whm",
    "plesk",
    "webmin",
    "dashboard",
    "panel",
    "login",
    "sso",
    "auth",
    "oauth",
    "id",
    "accounts",
    "account",
    "user",
    "users",
    "member",
    "members",
    "client",
    "clients",
    "customer",
    "customers",
    "partner",
    "partners",
    "vendor",
    "vendors",
    "employee",
    "staff",
    "hr",
    "careers",
    "jobs",
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "svn",
    "repo",
    "repository",
    "jenkins",
    "ci",
    "cd",
    "deploy",
    "build",
    "release",
    "jira",
    "confluence",
    "wiki",
    "kb",
    "knowledge",
    "forum",
    "community",
    "social",
    "chat",
    "slack",
    "teams",
    "meet",
    "zoom",
    "video",
    "stream",
    "live",
    "broadcast",
    "events",
    "calendar",
    "schedule",
    "booking",
    "reserve",
    "reservation",
    "payment",
    "pay",
    "checkout",
    "cart",
    "store",
    "ecommerce",
    "order",
    "orders",
    "invoice",
    "billing",
    "crm",
    "erp",
    "sales",
    "marketing",
    "analytics",
    "stats",
    "metrics",
    "report",
    "reports",
    "dashboard",
    "monitor",
    "monitoring",
    "health",
    "status",
    "uptime",
    "ping",
    "trace",
    "log",
    "logs",
    "syslog",
    "elk",
    "kibana",
    "grafana",
    "prometheus",
    "db",
    "database",
    "mysql",
    "postgres",
    "postgresql",
    "mongo",
    "mongodb",
    "redis",
    "cache",
    "memcache",
    "memcached",
    "elastic",
    "elasticsearch",
    "solr",
    "search",
    "mq",
    "queue",
    "rabbit",
    "rabbitmq",
    "kafka",
    "aws",
    "azure",
    "gcp",
    "cloud",
    "s3",
    "storage",
    "backup",
    "dr",
    "disaster",
    "recovery",
    "archive",
]


class SubdomainDiscovery:
    """
    Discovers subdomains using passive reconnaissance techniques.

    Combines Certificate Transparency logs, DNS analysis, and
    pattern-based discovery for comprehensive subdomain enumeration.
    """

    def __init__(self, domain: str, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize subdomain discovery.

        Args:
            domain: Target domain for subdomain discovery
            timeout: HTTP request timeout
        """
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = DNS_TIMEOUT

    def discover(self, include_dns_check: bool = True) -> dict[str, Any]:
        """
        Perform comprehensive subdomain discovery.

        Args:
            include_dns_check: Whether to verify subdomains resolve

        Returns:
            Dictionary with discovered subdomains
        """
        results: dict[str, Any] = {
            "subdomains": [],
            "total_found": 0,
            "sources": {},
            "live_count": 0,
            "by_category": {},
        }

        all_subdomains: set[str] = set()

        # 1. Certificate Transparency logs
        ct_subdomains = self._search_ct_logs()
        results["sources"]["certificate_transparency"] = len(ct_subdomains)
        all_subdomains.update(ct_subdomains)

        # 2. DNS-based discovery (NS, MX patterns)
        dns_subdomains = self._analyze_dns_records()
        results["sources"]["dns_records"] = len(dns_subdomains)
        all_subdomains.update(dns_subdomains)

        # 3. Common subdomain patterns (optional DNS resolution)
        if include_dns_check:
            common_subdomains = self._check_common_subdomains()
            results["sources"]["common_patterns"] = len(common_subdomains)
            all_subdomains.update(common_subdomains)

        # Remove main domain and empty entries
        all_subdomains.discard(self.domain)
        all_subdomains.discard(f"*.{self.domain}")
        all_subdomains = {s for s in all_subdomains if s and s != self.domain}

        # Build detailed subdomain list
        subdomain_details = []
        for subdomain in sorted(all_subdomains):
            detail = self._get_subdomain_details(subdomain, include_dns_check)
            subdomain_details.append(detail)
            if detail.get("is_live"):
                results["live_count"] += 1

            # Categorize
            category = self._categorize_subdomain(subdomain)
            if category not in results["by_category"]:
                results["by_category"][category] = []
            results["by_category"][category].append(subdomain)

        results["subdomains"] = subdomain_details
        results["total_found"] = len(all_subdomains)

        return results

    def _search_ct_logs(self) -> set[str]:
        """Search Certificate Transparency logs via crt.sh."""
        subdomains: set[str] = set()

        try:
            # Query crt.sh
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Split multiline entries (SAN)
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lower()
                            # Remove wildcards
                            subdomain = subdomain.lstrip("*.")
                            if subdomain.endswith(f".{self.domain}"):
                                subdomains.add(subdomain)
                            elif subdomain == self.domain:
                                continue
                except ValueError:
                    pass

        except requests.RequestException:
            pass

        return subdomains

    def _analyze_dns_records(self) -> set[str]:
        """Analyze DNS records for subdomain hints."""
        subdomains: set[str] = set()

        # Check MX records for mail subdomains
        with contextlib.suppress(Exception):
            mx_records = self.resolver.resolve(self.domain, "MX")
            for mx in mx_records:
                hostname = str(mx.exchange).rstrip(".")
                if hostname.endswith(f".{self.domain}"):
                    subdomains.add(hostname)

        # Check NS records
        with contextlib.suppress(Exception):
            ns_records = self.resolver.resolve(self.domain, "NS")
            for ns in ns_records:
                hostname = str(ns.target).rstrip(".")
                if hostname.endswith(f".{self.domain}"):
                    subdomains.add(hostname)

        # Check TXT records for subdomain hints
        with contextlib.suppress(Exception):
            txt_records = self.resolver.resolve(self.domain, "TXT")
            for txt in txt_records:
                txt_str = str(txt)
                # Look for domain references in SPF, etc.
                pattern = rf"([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})"
                matches = re.findall(pattern, txt_str, re.IGNORECASE)
                subdomains.update(m.lower() for m in matches)

        return subdomains

    def _check_common_subdomains(self, max_checks: int = 50) -> set[str]:
        """Check common subdomain patterns via DNS resolution."""
        found: set[str] = set()
        checked = 0

        for prefix in _EXTENDED_SUBDOMAINS:
            if checked >= max_checks:
                break

            subdomain = f"{prefix}.{self.domain}"
            if self._resolves(subdomain):
                found.add(subdomain)

            checked += 1

        return found

    def _resolves(self, subdomain: str) -> bool:
        """Check if subdomain resolves via DNS."""
        try:
            self.resolver.resolve(subdomain, "A")
            return True
        except Exception:  # noqa: S110
            pass

        try:
            self.resolver.resolve(subdomain, "AAAA")
            return True
        except Exception:  # noqa: S110
            pass

        return False

    def _get_subdomain_details(
        self, subdomain: str, check_live: bool = True
    ) -> dict[str, Any]:
        """Get detailed information about a subdomain."""
        detail: dict[str, Any] = {
            "subdomain": subdomain,
            "is_live": False,
            "ips": [],
            "cname": None,
        }

        if not check_live:
            return detail

        # Get A records
        try:
            answers = self.resolver.resolve(subdomain, "A")
            detail["ips"] = [str(rdata) for rdata in answers]
            detail["is_live"] = True
        except Exception:  # noqa: S110
            pass

        # Get CNAME
        try:
            answers = self.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                detail["cname"] = str(rdata.target).rstrip(".")
                detail["is_live"] = True
                break
        except Exception:  # noqa: S110
            pass

        # Get AAAA records
        try:
            answers = self.resolver.resolve(subdomain, "AAAA")
            ipv6 = [str(rdata) for rdata in answers]
            if ipv6:
                detail["ipv6"] = ipv6
                detail["is_live"] = True
        except Exception:  # noqa: S110
            pass

        return detail

    def _categorize_subdomain(self, subdomain: str) -> str:
        """Categorize subdomain by its prefix."""
        prefix = subdomain.replace(f".{self.domain}", "").split(".")[0].lower()

        categories = {
            "mail": ["mail", "smtp", "imap", "pop", "exchange", "webmail", "mx"],
            "api": ["api", "rest", "graphql", "ws", "websocket", "gateway"],
            "development": [
                "dev",
                "development",
                "staging",
                "test",
                "qa",
                "uat",
                "sandbox",
                "beta",
                "alpha",
                "demo",
            ],
            "infrastructure": [
                "ns",
                "dns",
                "vpn",
                "proxy",
                "lb",
                "cdn",
                "edge",
                "gateway",
                "firewall",
            ],
            "admin": [
                "admin",
                "panel",
                "dashboard",
                "cpanel",
                "whm",
                "plesk",
                "webmin",
                "management",
            ],
            "storage": [
                "cdn",
                "static",
                "assets",
                "media",
                "files",
                "images",
                "img",
                "download",
                "storage",
                "s3",
            ],
            "database": [
                "db",
                "database",
                "mysql",
                "postgres",
                "mongo",
                "redis",
                "elastic",
            ],
            "monitoring": [
                "monitor",
                "status",
                "health",
                "metrics",
                "grafana",
                "kibana",
                "prometheus",
            ],
            "auth": ["auth", "login", "sso", "oauth", "id", "identity", "accounts"],
            "web": ["www", "web", "portal", "site", "m", "mobile", "app"],
        }

        for category, prefixes in categories.items():
            if prefix in prefixes or any(p in prefix for p in prefixes):
                return category

        return "other"

    def get_live_subdomains(self) -> list[str]:
        """Get only subdomains that currently resolve."""
        results = self.discover(include_dns_check=True)
        return [s["subdomain"] for s in results["subdomains"] if s.get("is_live")]


def discover_subdomains(domain: str, include_dns_check: bool = True) -> dict[str, Any]:
    """
    Convenience function for subdomain discovery.

    Args:
        domain: Target domain
        include_dns_check: Whether to verify DNS resolution

    Returns:
        Subdomain discovery results
    """
    discovery = SubdomainDiscovery(domain)
    return discovery.discover(include_dns_check=include_dns_check)
