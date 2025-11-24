"""
CDN Detection Module for Rankle

Detects Content Delivery Networks through multiple passive techniques:
- HTTP Headers analysis
- DNS records (NS, CNAME)
- IP range ownership (ASN/WHOIS)
- Server-Timing headers
- TLS certificate analysis
"""

import ipaddress
import re
from typing import Any

import dns.resolver

from config.settings import DNS_TIMEOUT


# CDN Signatures Database
CDN_SIGNATURES: dict[str, dict[str, Any]] = {
    "Akamai": {
        "headers": {
            "server-timing": [r"ak_p", r"akamai"],
            "x-akamai-": [""],
            "akamai-origin-hop": [""],
            "x-cache": [r"TCP.*from.*akamai"],
            "x-akamai-transformed": [""],
        },
        "ns_patterns": [r"akam\.net", r"akamai\.com", r"akamaiedge\.net"],
        "cname_patterns": [
            r"\.akamai\.net",
            r"\.akamaiedge\.net",
            r"\.edgekey\.net",
            r"\.edgesuite\.net",
        ],
        "ip_ranges": [
            "23.32.0.0/11",
            "23.192.0.0/11",
            "96.16.0.0/15",
            "104.64.0.0/10",
            "184.24.0.0/13",
        ],
        "asn": ["AS20940", "AS16625"],
    },
    "Cloudflare": {
        "headers": {
            "cf-ray": [""],
            "cf-cache-status": [""],
            "server": [r"^cloudflare$"],
            "cf-request-id": [""],
            "cf-edge-cache": [""],
        },
        "ns_patterns": [r"cloudflare\.com"],
        "cname_patterns": [r"\.cdn\.cloudflare\.net", r"\.cloudflare\.com"],
        "ip_ranges": [
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            "104.16.0.0/13",
            "104.24.0.0/14",
            "108.162.192.0/18",
            "131.0.72.0/22",
            "141.101.64.0/18",
            "162.158.0.0/15",
            "172.64.0.0/13",
            "173.245.48.0/20",
            "188.114.96.0/20",
            "190.93.240.0/20",
            "197.234.240.0/22",
            "198.41.128.0/17",
        ],
        "asn": ["AS13335"],
    },
    "Fastly": {
        "headers": {
            "x-served-by": [r"cache-"],
            "x-cache": [r"HIT|MISS"],
            "x-cache-hits": [""],
            "x-fastly-request-id": [""],
            "fastly-debug-digest": [""],
            "via": [r"varnish"],
        },
        "ns_patterns": [r"fastly\.net"],
        "cname_patterns": [r"\.fastly\.net", r"\.fastlylb\.net"],
        "ip_ranges": [
            "23.235.32.0/20",
            "43.249.72.0/22",
            "103.244.50.0/24",
            "103.245.222.0/23",
            "103.245.224.0/24",
            "104.156.80.0/20",
            "140.248.64.0/18",
            "140.248.128.0/17",
            "146.75.0.0/17",
            "151.101.0.0/16",
            "157.52.64.0/18",
            "167.82.0.0/17",
            "167.82.128.0/20",
            "167.82.160.0/20",
            "167.82.224.0/20",
            "172.111.64.0/18",
            "185.31.16.0/22",
            "199.27.72.0/21",
            "199.232.0.0/16",
        ],
        "asn": ["AS54113"],
    },
    "AWS CloudFront": {
        "headers": {
            "x-amz-cf-id": [""],
            "x-amz-cf-pop": [""],
            "x-cache": [r".*CloudFront"],
            "via": [r"CloudFront"],
            "server": [r"CloudFront"],
        },
        "ns_patterns": [r"awsdns-"],
        "cname_patterns": [r"\.cloudfront\.net"],
        "ip_ranges": [],  # Dynamic, use ASN instead
        "asn": ["AS16509"],
    },
    "Azure CDN": {
        "headers": {
            "x-azure-ref": [""],
            "x-ms-ref": [""],
            "x-cache": [r"TCP_HIT|TCP_MISS"],
            "x-ec-custom-error": [""],
        },
        "ns_patterns": [r"azure-dns\."],
        "cname_patterns": [
            r"\.azureedge\.net",
            r"\.afd\.azureedge\.net",
            r"\.trafficmanager\.net",
        ],
        "ip_ranges": [],
        "asn": ["AS8075"],
    },
    "Google Cloud CDN": {
        "headers": {
            "x-goog-": [""],
            "via": [r"google"],
            "server": [r"^gws$", r"^gse$"],
            "x-guploader-uploadid": [""],
        },
        "ns_patterns": [r"googledomains\.com"],
        "cname_patterns": [
            r"\.c\.storage\.googleapis\.com",
            r"\.storage\.googleapis\.com",
        ],
        "ip_ranges": [],
        "asn": ["AS15169", "AS396982"],
    },
    "Imperva/Incapsula": {
        "headers": {
            "x-iinfo": [""],
            "x-cdn": [r"Incapsula", r"Imperva"],
            "x-protected-by": [r"Sqreen"],
        },
        "ns_patterns": [r"incapdns\.net"],
        "cname_patterns": [r"\.incapdns\.net", r"\.impervadns\.net"],
        "ip_ranges": [
            "45.64.64.0/22",
            "107.154.0.0/16",
            "192.230.64.0/18",
            "199.83.128.0/21",
        ],
        "asn": ["AS19551"],
    },
    "Sucuri": {
        "headers": {
            "x-sucuri-id": [""],
            "x-sucuri-cache": [""],
            "server": [r"Sucuri"],
        },
        "ns_patterns": [r"sucuridns\.com"],
        "cname_patterns": [r"\.sucuridns\.com"],
        "ip_ranges": [
            "192.88.134.0/23",
            "185.93.228.0/22",
            "66.248.200.0/22",
        ],
        "asn": [],
    },
    "KeyCDN": {
        "headers": {
            "server": [r"keycdn"],
            "x-cache": [r"HIT|MISS"],
            "x-shield": [""],
        },
        "ns_patterns": [],
        "cname_patterns": [r"\.kxcdn\.com"],
        "ip_ranges": [],
        "asn": [],
    },
    "StackPath/MaxCDN": {
        "headers": {
            "x-hw": [""],
            "server": [r"NetDNA", r"StackPath"],
            "x-cache": [""],
        },
        "ns_patterns": [r"stackpathdns\.com"],
        "cname_patterns": [r"\.stackpathdns\.com", r"\.netdna-cdn\.com"],
        "ip_ranges": [],
        "asn": ["AS33438"],
    },
    "Limelight": {
        "headers": {
            "server": [r"LLNW", r"Limelight"],
            "x-llnw-": [""],
        },
        "ns_patterns": [],
        "cname_patterns": [r"\.llnwd\.net", r"\.limelight\.com"],
        "ip_ranges": [],
        "asn": ["AS22822"],
    },
    "CDNetworks": {
        "headers": {
            "server": [r"CDNetworks"],
            "x-px-": [""],
        },
        "ns_patterns": [],
        "cname_patterns": [r"\.cdngc\.net", r"\.gccdn\.net"],
        "ip_ranges": [],
        "asn": [],
    },
    "Edgecast/Verizon": {
        "headers": {
            "server": [r"ECS", r"ECAcc"],
            "x-ec-custom-error": [""],
        },
        "ns_patterns": [],
        "cname_patterns": [r"\.systemcdn\.net", r"\.edgecastcdn\.net"],
        "ip_ranges": [],
        "asn": ["AS15133"],
    },
    "ArvanCloud": {
        "headers": {
            "server": [r"ArvanCloud"],
            "ar-powered-by": [r"Arvan"],
            "ar-sid": [""],
        },
        "ns_patterns": [r"arvancloud\.com"],
        "cname_patterns": [r"\.arvancdn\.com", r"\.arvancloud\.com"],
        "ip_ranges": [],
        "asn": [],
    },
    "BunnyCDN": {
        "headers": {
            "server": [r"BunnyCDN"],
            "cdn-pullzone": [""],
            "cdn-uid": [""],
            "cdn-requestid": [""],
        },
        "ns_patterns": [],
        "cname_patterns": [r"\.b-cdn\.net"],
        "ip_ranges": [],
        "asn": [],
    },
    "Netlify": {
        "headers": {
            "server": [r"Netlify"],
            "x-nf-request-id": [""],
        },
        "ns_patterns": [r"netlify\.com"],
        "cname_patterns": [r"\.netlify\.app", r"\.netlify\.com"],
        "ip_ranges": [],
        "asn": [],
    },
    "Vercel": {
        "headers": {
            "server": [r"Vercel"],
            "x-vercel-id": [""],
            "x-vercel-cache": [""],
        },
        "ns_patterns": [r"vercel-dns\.com"],
        "cname_patterns": [
            r"\.vercel\.app",
            r"\.vercel-dns\.com",
            r"cname\.vercel-dns\.com",
        ],
        "ip_ranges": ["76.76.21.0/24"],
        "asn": [],
    },
}


class CDNDetector:
    """
    Detects Content Delivery Networks using multiple passive techniques.

    Combines header analysis, DNS inspection, and IP range checking
    to provide high-confidence CDN detection.
    """

    def __init__(self, domain: str, timeout: int = DNS_TIMEOUT):
        """
        Initialize CDN detector.

        Args:
            domain: Target domain to analyze
            timeout: DNS query timeout in seconds
        """
        self.domain = domain
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def detect(
        self,
        headers: dict[str, str] | None = None,
        ips: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Perform comprehensive CDN detection.

        Args:
            headers: HTTP response headers (optional)
            ips: Resolved IP addresses (optional)

        Returns:
            Dictionary with detection results
        """
        results: dict[str, Any] = {
            "detected": False,
            "cdn": None,
            "confidence": 0.0,
            "evidence": [],
            "all_matches": [],
        }

        # Collect all evidence
        header_matches = self._check_headers(headers) if headers else []
        ns_matches = self._check_nameservers()
        cname_matches = self._check_cnames()
        ip_matches = self._check_ip_ranges(ips) if ips else []

        # Aggregate results
        all_evidence: dict[str, list[dict[str, Any]]] = {}

        for match in header_matches + ns_matches + cname_matches + ip_matches:
            cdn_name = match["cdn"]
            if cdn_name not in all_evidence:
                all_evidence[cdn_name] = []
            all_evidence[cdn_name].append(match)

        # Calculate confidence for each CDN
        cdn_scores: list[dict[str, Any]] = []
        for cdn_name, evidence_list in all_evidence.items():
            confidence = self._calculate_confidence(evidence_list)
            cdn_scores.append(
                {
                    "cdn": cdn_name,
                    "confidence": confidence,
                    "evidence": evidence_list,
                }
            )

        # Sort by confidence
        cdn_scores.sort(key=lambda x: x["confidence"], reverse=True)

        if cdn_scores and cdn_scores[0]["confidence"] >= 0.3:
            best_match = cdn_scores[0]
            results["detected"] = True
            results["cdn"] = best_match["cdn"]
            results["confidence"] = best_match["confidence"]
            results["evidence"] = best_match["evidence"]
            results["all_matches"] = cdn_scores

        return results

    def _check_headers(self, headers: dict[str, str]) -> list[dict[str, Any]]:
        """Check HTTP headers for CDN signatures."""
        matches = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for cdn_name, signatures in CDN_SIGNATURES.items():
            cdn_headers = signatures.get("headers", {})
            for header_pattern, value_patterns in cdn_headers.items():
                header_pattern_lower = header_pattern.lower()

                # Check for exact header or prefix match
                for header_name, header_value in headers_lower.items():
                    if header_pattern_lower.endswith("-"):
                        # Prefix match (e.g., "x-akamai-")
                        if header_name.startswith(header_pattern_lower):
                            matches.append(
                                {
                                    "cdn": cdn_name,
                                    "type": "header",
                                    "detail": f"{header_name}: {header_value[:50]}",
                                    "weight": 0.5,
                                }
                            )
                    elif header_name == header_pattern_lower:
                        # Exact header match
                        for pattern in value_patterns:
                            if not pattern:  # Empty pattern = just check header exists
                                matches.append(
                                    {
                                        "cdn": cdn_name,
                                        "type": "header",
                                        "detail": f"{header_name} header present",
                                        "weight": 0.4,
                                    }
                                )
                                break
                            if re.search(pattern, header_value, re.IGNORECASE):
                                matches.append(
                                    {
                                        "cdn": cdn_name,
                                        "type": "header",
                                        "detail": f"{header_name}: {header_value[:50]}",
                                        "weight": 0.5,
                                    }
                                )
                                break

        return matches

    def _check_nameservers(self) -> list[dict[str, Any]]:
        """Check DNS nameservers for CDN patterns."""
        matches = []
        try:
            ns_records = self.resolver.resolve(self.domain, "NS")
            ns_names = [str(ns.target).lower() for ns in ns_records]

            for cdn_name, signatures in CDN_SIGNATURES.items():
                for pattern in signatures.get("ns_patterns", []):
                    for ns_name in ns_names:
                        if re.search(pattern, ns_name, re.IGNORECASE):
                            matches.append(
                                {
                                    "cdn": cdn_name,
                                    "type": "nameserver",
                                    "detail": f"NS: {ns_name}",
                                    "weight": 0.6,
                                }
                            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        return matches

    def _check_cnames(self) -> list[dict[str, Any]]:
        """Check CNAME records for CDN patterns."""
        matches = []

        # Check both root domain and www
        targets = [self.domain, f"www.{self.domain}"]

        for target in targets:
            try:
                cname_records = self.resolver.resolve(target, "CNAME")
                for cname in cname_records:
                    cname_str = str(cname.target).lower()

                    for cdn_name, signatures in CDN_SIGNATURES.items():
                        for pattern in signatures.get("cname_patterns", []):
                            if re.search(pattern, cname_str, re.IGNORECASE):
                                matches.append(
                                    {
                                        "cdn": cdn_name,
                                        "type": "cname",
                                        "detail": f"CNAME: {cname_str}",
                                        "weight": 0.7,
                                    }
                                )
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
            ):
                pass

        return matches

    def _check_ip_ranges(self, ips: list[str]) -> list[dict[str, Any]]:
        """Check if IPs belong to known CDN ranges."""
        matches = []

        for ip_str in ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)

                for cdn_name, signatures in CDN_SIGNATURES.items():
                    for range_str in signatures.get("ip_ranges", []):
                        try:
                            network = ipaddress.ip_network(range_str, strict=False)
                            if ip_obj in network:
                                matches.append(
                                    {
                                        "cdn": cdn_name,
                                        "type": "ip_range",
                                        "detail": f"IP {ip_str} in {range_str}",
                                        "weight": 0.6,
                                    }
                                )
                        except ValueError:
                            continue
            except ValueError:
                continue

        return matches

    def _calculate_confidence(self, evidence: list[dict[str, Any]]) -> float:
        """
        Calculate confidence score from evidence.

        Uses weighted scoring with diminishing returns for multiple
        pieces of the same type of evidence.
        """
        if not evidence:
            return 0.0

        # Group by evidence type
        by_type: dict[str, list[float]] = {}
        for ev in evidence:
            ev_type = ev["type"]
            if ev_type not in by_type:
                by_type[ev_type] = []
            by_type[ev_type].append(ev["weight"])

        # Calculate score with diminishing returns
        total_score = 0.0
        for weights in by_type.values():
            # Take best weight, with diminishing bonus for additional evidence
            weights.sort(reverse=True)
            type_score = weights[0]
            for i, w in enumerate(weights[1:], 1):
                type_score += w * (0.5**i)  # Diminishing returns
            total_score += type_score

        # Cap at 1.0
        return min(1.0, total_score)

    def get_cdn_ips(self, cdn_name: str) -> list[str]:
        """Get known IP ranges for a specific CDN."""
        if cdn_name in CDN_SIGNATURES:
            ip_ranges: list[str] = CDN_SIGNATURES[cdn_name].get("ip_ranges", [])
            return ip_ranges
        return []


def detect_cdn(
    domain: str,
    headers: dict[str, str] | None = None,
    ips: list[str] | None = None,
) -> dict[str, Any]:
    """
    Convenience function for CDN detection.

    Args:
        domain: Target domain
        headers: HTTP response headers
        ips: Resolved IP addresses

    Returns:
        CDN detection results
    """
    detector = CDNDetector(domain)
    return detector.detect(headers=headers, ips=ips)
