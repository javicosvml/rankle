"""
DNS enumeration and analysis module for Rankle
"""

import sys
from typing import Any


try:
    import dns.resolver
except ImportError:
    print("\n" + "=" * 80)
    print("❌ Missing required dependency: dnspython")
    print("=" * 80)
    print("\nPlease install required libraries:")
    print("  pip install dnspython")
    print("=" * 80 + "\n")
    sys.exit(1)

from config.settings import DNS_NAMESERVERS, DNS_TIMEOUT
from rankle.utils.helpers import truncate_list


class DNSAnalyzer:
    """DNS enumeration and configuration analysis"""

    def __init__(self, domain: str, timeout: int = DNS_TIMEOUT):
        """
        Initialize DNS analyzer

        Args:
            domain: Domain to analyze
            timeout: DNS query timeout
        """
        self.domain = domain
        self.timeout = timeout
        self.resolver = self._setup_resolver()

    def _setup_resolver(self) -> dns.resolver.Resolver:
        """
        Setup DNS resolver with custom nameservers

        Returns:
            Configured DNS resolver
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        resolver.nameservers = DNS_NAMESERVERS
        return resolver

    def analyze(self) -> dict[str, Any]:
        """
        Perform comprehensive DNS analysis

        Returns:
            Dictionary with DNS records
        """
        print("\n📡 Analyzing DNS Configuration...")

        dns_records = {
            "A": self._query_records("A"),
            "AAAA": self._query_records("AAAA"),
            "MX": self._query_mx_records(),
            "NS": self._query_records("NS"),
            "TXT": self._query_records("TXT"),
            "SOA": self._query_soa_record(),
            "CNAME": self._query_records("CNAME"),
        }

        self._print_results(dns_records)
        return dns_records

    def _query_records(self, record_type: str) -> list[str]:
        """
        Query DNS records of specific type

        Args:
            record_type: Type of DNS record (A, AAAA, NS, TXT, CNAME)

        Returns:
            List of record values
        """
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            return [str(rdata) for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            return []
        except Exception:
            return []

    def _query_mx_records(self) -> list[str]:
        """
        Query MX records with priority

        Returns:
            List of MX records with priority
        """
        try:
            answers = self.resolver.resolve(self.domain, "MX")
            return [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            return []
        except Exception:
            return []

    def _query_soa_record(self) -> str | None:
        """
        Query SOA record

        Returns:
            SOA record string or None
        """
        try:
            answers = self.resolver.resolve(self.domain, "SOA")
            if answers:
                soa = answers[0]
                return f"{soa.mname} {soa.rname} {soa.serial} {soa.refresh} {soa.retry} {soa.expire} {soa.minimum}"
            return None
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            return None
        except Exception:
            return None

    def _print_results(self, dns_records: dict[str, Any]):
        """
        Print DNS analysis results

        Args:
            dns_records: Dictionary with DNS records
        """
        if dns_records["A"]:
            print(f"   └─ IPv4 Addresses: {truncate_list(dns_records['A'])}")

        if dns_records["AAAA"]:
            print(f"   └─ IPv6 Addresses: {truncate_list(dns_records['AAAA'])}")

        if dns_records["MX"]:
            print(f"   └─ Mail Servers: {truncate_list(dns_records['MX'])}")
        else:
            print("   └─ Mail Servers: None configured")

        if dns_records["NS"]:
            print(f"   └─ Name Servers: {truncate_list(dns_records['NS'])}")

        if dns_records["TXT"]:
            txt_display = [
                txt[:60] + "..." if len(txt) > 60 else txt
                for txt in dns_records["TXT"][:3]
            ]
            txt_formatted = ", ".join([f'"{txt}"' for txt in txt_display])
            print(f"   └─ TXT Records: {txt_formatted}")

        if dns_records["SOA"]:
            print(f"   └─ Start of Authority: {dns_records['SOA']}")

        if dns_records["CNAME"]:
            print(f"   └─ CNAME Records: {truncate_list(dns_records['CNAME'])}")

    def get_cnames(self) -> list[str]:
        """
        Get CNAME records for the domain

        Returns:
            List of CNAME records
        """
        return self._query_records("CNAME")

    def get_ip_addresses(self) -> list[str]:
        """
        Get all IP addresses (IPv4 and IPv6)

        Returns:
            List of IP addresses
        """
        ips = []
        ips.extend(self._query_records("A"))
        ips.extend(self._query_records("AAAA"))
        return ips
