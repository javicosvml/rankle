"""
Core scanner class for Rankle - Orchestrates all reconnaissance modules
"""

import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from config.settings import DEFAULT_TIMEOUT
from rankle.core.session import SessionManager
from rankle.detectors.cdn import CDNDetector
from rankle.detectors.origin import OriginDiscovery
from rankle.detectors.technology import TechnologyDetector
from rankle.detectors.waf import WAFDetector
from rankle.modules.dns import DNSAnalyzer
from rankle.modules.geolocation import GeolocationLookup
from rankle.modules.http_fingerprint import HTTPFingerprinter
from rankle.modules.security_headers import SecurityHeadersAuditor
from rankle.modules.ssl import SSLAnalyzer
from rankle.modules.subdomains import SubdomainDiscovery
from rankle.modules.whois import WHOISLookup
from rankle.utils.rate_limiter import get_rate_limiter
from rankle.utils.validators import validate_domain


if TYPE_CHECKING:
    from rankle.utils.rate_limiter import RateLimiter


class RankleScanner:
    """
    Main scanner class that orchestrates all reconnaissance modules

    This class follows the modular architecture pattern, delegating
    specific tasks to specialized modules while maintaining a clean
    interface for the user.
    """

    def __init__(
        self, domain: str, verbose: bool = False, timeout: int = DEFAULT_TIMEOUT
    ):
        """
        Initialize Rankle scanner

        Args:
            domain: Target domain to scan
            verbose: Enable verbose output
            timeout: Default timeout for HTTP requests

        Raises:
            ValueError: If domain format is invalid
        """
        if not validate_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        self.domain = domain
        self.verbose = verbose
        self.timeout = timeout
        self.scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        self.results: dict[str, Any] = {
            "domain": domain,
            "scan_timestamp": self.scan_timestamp,
            "scan_version": "1.0.0",
        }

        # Initialize session manager
        self.session = SessionManager(timeout=timeout)

        # Initialize rate limiter
        self._rate_limiter: RateLimiter = get_rate_limiter("normal")

        # Initialize modules (lazy initialization for performance)
        self._dns_analyzer: DNSAnalyzer | None = None
        self._cdn_detector: CDNDetector | None = None
        self._waf_detector: WAFDetector | None = None
        self._origin_discovery: OriginDiscovery | None = None
        self._technology_detector: TechnologyDetector | None = None
        self._ssl_analyzer: SSLAnalyzer | None = None
        self._security_headers_auditor: SecurityHeadersAuditor | None = None
        self._subdomain_discovery: SubdomainDiscovery | None = None
        self._whois_lookup: WHOISLookup | None = None
        self._geolocation_lookup: GeolocationLookup | None = None
        self._http_fingerprinter: HTTPFingerprinter | None = None

        # Cache for HTTP response data
        self._http_headers: dict[str, str] | None = None
        self._http_cookies: list[str] | None = None
        self._http_body: str | None = None
        self._resolved_ips: list[str] | None = None

    @property
    def dns_analyzer(self) -> DNSAnalyzer:
        """Lazy initialization of DNS analyzer"""
        if self._dns_analyzer is None:
            self._dns_analyzer = DNSAnalyzer(self.domain)
        return self._dns_analyzer

    @property
    def cdn_detector(self) -> CDNDetector:
        """Lazy initialization of CDN detector"""
        if self._cdn_detector is None:
            self._cdn_detector = CDNDetector(self.domain)
        return self._cdn_detector

    @property
    def waf_detector(self) -> WAFDetector:
        """Lazy initialization of WAF detector"""
        if self._waf_detector is None:
            self._waf_detector = WAFDetector(self.domain)
        return self._waf_detector

    @property
    def origin_discovery(self) -> OriginDiscovery:
        """Lazy initialization of origin discovery"""
        if self._origin_discovery is None:
            self._origin_discovery = OriginDiscovery(self.domain)
        return self._origin_discovery

    @property
    def technology_detector(self) -> TechnologyDetector:
        """Lazy initialization of technology detector"""
        if self._technology_detector is None:
            self._technology_detector = TechnologyDetector(self.domain)
        return self._technology_detector

    @property
    def ssl_analyzer(self) -> SSLAnalyzer:
        """Lazy initialization of SSL analyzer"""
        if self._ssl_analyzer is None:
            self._ssl_analyzer = SSLAnalyzer(self.domain, timeout=self.timeout)
        return self._ssl_analyzer

    @property
    def security_headers_auditor(self) -> SecurityHeadersAuditor:
        """Lazy initialization of security headers auditor"""
        if self._security_headers_auditor is None:
            self._security_headers_auditor = SecurityHeadersAuditor(self.domain)
        return self._security_headers_auditor

    @property
    def subdomain_discovery(self) -> SubdomainDiscovery:
        """Lazy initialization of subdomain discovery"""
        if self._subdomain_discovery is None:
            self._subdomain_discovery = SubdomainDiscovery(
                self.domain, timeout=self.timeout
            )
        return self._subdomain_discovery

    @property
    def whois_lookup(self) -> WHOISLookup:
        """Lazy initialization of WHOIS lookup"""
        if self._whois_lookup is None:
            self._whois_lookup = WHOISLookup(self.domain, timeout=self.timeout)
        return self._whois_lookup

    @property
    def geolocation_lookup(self) -> GeolocationLookup:
        """Lazy initialization of geolocation lookup"""
        if self._geolocation_lookup is None:
            self._geolocation_lookup = GeolocationLookup(timeout=self.timeout)
        return self._geolocation_lookup

    @property
    def http_fingerprinter(self) -> HTTPFingerprinter:
        """Lazy initialization of HTTP fingerprinter"""
        if self._http_fingerprinter is None:
            self._http_fingerprinter = HTTPFingerprinter(
                self.domain, timeout=self.timeout
            )
        return self._http_fingerprinter

    def run_full_scan(self) -> dict[str, Any]:
        """
        Run comprehensive reconnaissance scan

        This method executes all available reconnaissance modules
        in a logical order, storing results for each step.

        Returns:
            Dictionary containing all scan results
        """
        # 1. DNS Analysis (foundation for other modules)
        print("\n[1/8] DNS Analysis...")
        dns_results = self.analyze_dns()
        self.results["dns"] = dns_results

        # Cache resolved IPs for later use
        self._resolved_ips = dns_results.get("A", [])

        # 2. Fetch HTTP response for header/body analysis
        print("\n[2/8] Fetching HTTP Response...")
        self._fetch_http_data()

        # 3. SSL/TLS Analysis
        print("\n[3/8] Analyzing SSL/TLS Certificate...")
        ssl_results = self.analyze_ssl_certificate()
        self.results["ssl"] = ssl_results

        # 4. Technology Detection
        print("\n[4/8] Detecting Technologies...")
        tech_results = self.detect_technologies()
        self.results["technologies"] = tech_results

        # 5. CDN/WAF Detection
        print("\n[5/8] Detecting CDN/WAF...")
        cdn_waf_results = self.detect_cdn_waf()
        self.results["cdn"] = cdn_waf_results.get("cdn", {})
        self.results["waf"] = cdn_waf_results.get("waf", {})

        # 6. Security Headers Audit
        print("\n[6/8] Auditing Security Headers...")
        headers_results = self.audit_security_headers()
        self.results["security_headers"] = headers_results

        # 7. Origin Discovery (if CDN detected)
        if cdn_waf_results.get("cdn", {}).get("detected"):
            print("\n[7/8] Discovering Origin Infrastructure...")
            origin_results = self.discover_origin()
            self.results["origin"] = origin_results
        else:
            print("\n[7/8] Origin Discovery... (skipped - no CDN detected)")
            self.results["origin"] = {"potential_origins": []}

        # 8. Subdomain Discovery
        print("\n[8/8] Discovering Subdomains...")
        subdomain_results = self.discover_subdomains()
        self.results["subdomains"] = subdomain_results

        # Print comprehensive summary
        self._print_full_summary()

        return self.results

    def _fetch_http_data(self):
        """Fetch HTTP response data for analysis."""
        try:
            response = self.session.get(f"https://{self.domain}", timeout=self.timeout)
            self._http_headers = dict(response.headers)
            self._http_body = response.text[:100000]  # First 100KB
            self._http_cookies = list(response.cookies.keys())
            print(f"   Status: {response.status_code}")
        except Exception as e:
            if self.verbose:
                print(f"   HTTP fetch failed: {e}")
            self._http_headers = {}
            self._http_body = ""
            self._http_cookies = []

    def analyze_dns(self) -> dict[str, Any]:
        """
        Perform DNS enumeration and analysis

        Returns:
            Dictionary with DNS records
        """
        results = self.dns_analyzer.analyze()

        # Print summary
        if results.get("A"):
            print(f"   A Records: {len(results['A'])} found")
        if results.get("MX"):
            print(f"   MX Records: {len(results['MX'])} found")
        if results.get("NS"):
            print(f"   NS Records: {len(results['NS'])} found")

        return results

    def analyze_ssl_certificate(self) -> dict[str, Any]:
        """
        Analyze SSL/TLS certificate

        Returns:
            Dictionary with certificate information
        """
        results = self.ssl_analyzer.analyze()

        if results.get("valid"):
            cert = results.get("certificate", {})
            issuer = cert.get("issuer", {})
            issuer_name = issuer.get(
                "organizationName", issuer.get("commonName", "Unknown")
            )
            print(f"   Issuer: {issuer_name}")

            days = cert.get("days_until_expiry")
            if days is not None:
                if days < 0:
                    print(f"   Expiry: EXPIRED ({abs(days)} days ago)")
                elif days < 30:
                    print(f"   Expiry: WARNING - {days} days remaining")
                else:
                    print(f"   Expiry: {days} days remaining")

            if results.get("san_domains"):
                print(f"   SAN Domains: {len(results['san_domains'])} found")

            grade = results.get("security_grade", "N/A")
            print(f"   Security Grade: {grade}")
        else:
            print("   SSL analysis failed")

        return results

    def detect_technologies(self) -> dict[str, Any]:
        """
        Detect web technologies (CMS, frameworks, libraries)

        Returns:
            Dictionary with detected technologies
        """
        results = self.technology_detector.detect(
            headers=self._http_headers,
            cookies=self._http_cookies,
            body=self._http_body,
        )

        if results.get("detected"):
            technologies = results.get("technologies", [])
            print(f"   Found {len(technologies)} technologies:")
            for tech in technologies[:10]:  # Show top 10
                version = f" v{tech['version']}" if tech.get("version") else ""
                confidence = int(tech["confidence"] * 100)
                print(f"      - {tech['name']}{version} ({confidence}%)")

            # Show categories
            categories = results.get("categories", {})
            if categories:
                print(f"   Categories: {', '.join(categories.keys())}")
        else:
            print("   No technologies detected")

        return results

    def detect_cdn_waf(self) -> dict[str, Any]:
        """
        Detect CDN and WAF

        Returns:
            Dictionary with CDN/WAF detection results
        """
        results: dict[str, Any] = {"cdn": {}, "waf": {}}

        # Detect CDN
        cdn_result = self.cdn_detector.detect(
            headers=self._http_headers,
            ips=self._resolved_ips,
        )
        results["cdn"] = cdn_result

        if cdn_result.get("detected"):
            confidence = int(cdn_result.get("confidence", 0) * 100)
            print(f"   CDN: {cdn_result.get('cdn')} ({confidence}%)")
        else:
            print("   CDN: Not detected")

        # Detect WAF
        waf_result = self.waf_detector.detect(
            headers=self._http_headers,
            cookies=self._http_cookies,
            body=self._http_body,
        )
        results["waf"] = waf_result

        if waf_result.get("detected"):
            confidence = int(waf_result.get("confidence", 0) * 100)
            print(f"   WAF: {waf_result.get('waf')} ({confidence}%)")
        else:
            print("   WAF: Not detected")

        return results

    def audit_security_headers(self) -> dict[str, Any]:
        """
        Audit HTTP security headers

        Returns:
            Dictionary with security headers audit results
        """
        results = self.security_headers_auditor.audit(headers=self._http_headers)

        grade = results.get("grade", "F")
        score = results.get("score", 0)
        print(f"   Grade: {grade} ({score}/100)")

        summary = results.get("summary", {})
        present = summary.get("present_count", 0)
        missing = summary.get("missing_count", 0)
        print(f"   Headers: {present} present, {missing} missing")

        issues = len(results.get("issues", []))
        info_leaks = len(results.get("info_leaks", []))
        if issues:
            print(f"   Issues: {issues} found")
        if info_leaks:
            print(f"   Info Leaks: {info_leaks} headers expose information")

        return results

    def discover_origin(self) -> dict[str, Any]:
        """
        Discover origin infrastructure behind CDN/WAF

        Returns:
            Dictionary with origin discovery results
        """
        cdn_ips = self._resolved_ips or []
        results = self.origin_discovery.discover(cdn_ips=cdn_ips)

        if results.get("potential_origins"):
            origins = results["potential_origins"]
            print(f"   Found {len(origins)} potential origins:")
            for origin in origins[:5]:
                provider = origin.get("cloud_provider", "")
                provider_str = f" [{provider}]" if provider else ""
                print(f"      - {origin['ip']} ({origin['source']}){provider_str}")
        else:
            print("   No origin IPs discovered")

        return results

    def discover_subdomains(self) -> dict[str, Any]:
        """
        Discover subdomains via Certificate Transparency and DNS

        Returns:
            Dictionary with discovered subdomains
        """
        results = self.subdomain_discovery.discover(include_dns_check=True)

        total = results.get("total_found", 0)
        live = results.get("live_count", 0)
        print(f"   Found {total} subdomains ({live} live)")

        # Show sources
        sources = results.get("sources", {})
        if sources:
            for source, count in sources.items():
                if count > 0:
                    print(f"      - {source}: {count}")

        # Show categories
        categories = results.get("by_category", {})
        if categories:
            print(
                f"   Categories: {', '.join(f'{k}({len(v)})' for k, v in categories.items())}"
            )

        return results

    def lookup_whois(self) -> dict[str, Any]:
        """
        Perform WHOIS lookup

        Returns:
            Dictionary with WHOIS information
        """
        results = self.whois_lookup.lookup()

        if results.get("registrar"):
            print(f"   Registrar: {results['registrar']}")
        if results.get("creation_date"):
            print(f"   Created: {results['creation_date']}")
        if results.get("expiration_date"):
            print(f"   Expires: {results['expiration_date']}")
        if results.get("nameservers"):
            print(f"   Nameservers: {len(results['nameservers'])} found")
        if results.get("error"):
            print(f"   Error: {results['error']}")

        return results

    def analyze_geolocation(self) -> dict[str, Any]:
        """
        Analyze geolocation and hosting provider for resolved IPs

        Returns:
            Dictionary with geolocation information
        """
        ips = self._resolved_ips or []
        if not ips:
            print("   No IPs to analyze")
            return {"ips": []}

        results: dict[str, Any] = {"ips": []}

        for ip in ips[:5]:  # Limit to first 5 IPs
            geo_info = self.geolocation_lookup.lookup(ip)
            results["ips"].append(geo_info)

            provider = geo_info.get("cloud_provider") or geo_info.get("asn_provider")
            country = geo_info.get("country", "Unknown")
            asn = geo_info.get("asn", "")

            if provider:
                print(f"   {ip}: {provider} ({country}) {asn}")
            else:
                print(f"   {ip}: {country} {asn}")

        return results

    def fingerprint_http(self) -> dict[str, Any]:
        """
        Perform HTTP fingerprinting (methods, paths, signatures)

        Returns:
            Dictionary with HTTP fingerprinting results
        """
        results = self.http_fingerprinter.fingerprint()

        # Server info
        if results.get("server"):
            print(f"   Server: {results['server']}")

        # HTTP version
        if results.get("http_version"):
            print(f"   HTTP Version: {results['http_version']}")

        # HTTP/2 support
        if results.get("http2_support"):
            print("   HTTP/2: Supported")

        # Allowed methods
        methods = results.get("allowed_methods", [])
        if methods:
            print(f"   Methods: {', '.join(methods)}")

        # Exposed paths
        exposed = results.get("exposed_paths", [])
        if exposed:
            print(f"   Exposed Paths: {len(exposed)} found")
            for path_info in exposed[:5]:
                print(f"      - {path_info['path']} ({path_info['status']})")

        # Server signatures
        signatures = results.get("server_signatures", [])
        if signatures:
            print(f"   Signatures: {', '.join(signatures)}")

        # API endpoints
        api = results.get("api_endpoints", [])
        if api:
            print(f"   API Endpoints: {len(api)} found")

        return results

    def _print_full_summary(self):
        """Print comprehensive summary report with friendly formatting"""
        width = 70
        print("\n")
        print("┌" + "─" * (width - 2) + "┐")
        print("│" + " RECONNAISSANCE RESULTS ".center(width - 2) + "│")
        print("├" + "─" * (width - 2) + "┤")
        print(f"│  🎯 Target: {self.domain}".ljust(width - 1) + "│")
        print(f"│  ⏰ Time:   {self.scan_timestamp}".ljust(width - 1) + "│")
        print("└" + "─" * (width - 2) + "┘")

        # Infrastructure Section
        cdn = self.results.get("cdn", {})
        waf = self.results.get("waf", {})
        ssl_data = self.results.get("ssl", {})
        headers_data = self.results.get("security_headers", {})

        print("\n🏗️  INFRASTRUCTURE")
        print("─" * 40)
        # CDN
        if cdn.get("detected"):
            cdn_conf = int(cdn.get("confidence", 0) * 100)
            print(f"   CDN:     ✅ {cdn.get('cdn')} ({cdn_conf}%)")
        else:
            print("   CDN:     ❌ Not detected")
        # WAF
        if waf.get("detected"):
            waf_conf = int(waf.get("confidence", 0) * 100)
            print(f"   WAF:     🛡️  {waf.get('waf')} ({waf_conf}%)")
        else:
            print("   WAF:     ❌ Not detected")
        # SSL Grade
        if ssl_data.get("valid"):
            grade = ssl_data.get("security_grade", "N/A")
            grade_icon = (
                "🟢" if grade in ["A+", "A"] else "🟡" if grade in ["B", "C"] else "🔴"
            )
            print(f"   SSL:     {grade_icon} Grade {grade}")
        else:
            print("   SSL:     ⚠️  Not available")
        # Headers Grade
        h_grade = headers_data.get("grade", "N/A")
        h_score = headers_data.get("score", 0)
        h_icon = "🟢" if h_score >= 80 else "🟡" if h_score >= 50 else "🔴"
        print(f"   Headers: {h_icon} {h_grade} ({h_score}/100)")

        # Technologies Section
        tech = self.results.get("technologies", {})
        if tech.get("detected"):
            tech_list = tech.get("technologies", [])
            print(f"\n🔬 TECHNOLOGIES ({len(tech_list)} detected)")
            print("─" * 40)
            for t in tech_list[:8]:
                version = f" v{t['version']}" if t.get("version") else ""
                conf = int(t["confidence"] * 100)
                conf_icon = "🟢" if conf >= 80 else "🟡" if conf >= 50 else "🟠"
                print(f"   {conf_icon} {t['name']}{version} ({conf}%)")
            if len(tech_list) > 8:
                print(f"   ... +{len(tech_list) - 8} more")

        # Origin Discovery Section
        origin = self.results.get("origin", {})
        if origin.get("potential_origins"):
            origins = origin["potential_origins"]
            print(f"\n🎯 ORIGIN DISCOVERY ({len(origins)} potential IPs)")
            print("─" * 40)
            for o in origins[:5]:
                provider = o.get("cloud_provider", "")
                conf = int(o.get("confidence", 0) * 100)
                provider_str = f" [{provider}]" if provider else ""
                print(f"   📍 {o['ip']}{provider_str} ({conf}%)")
            if len(origins) > 5:
                print(f"   ... +{len(origins) - 5} more")

        # Subdomains Section
        subs = self.results.get("subdomains", {})
        total = subs.get("total_found", 0)
        live = subs.get("live_count", 0)
        if total > 0:
            print(f"\n🌐 SUBDOMAINS ({total} found, {live} live)")
            print("─" * 40)
            live_subs = [s for s in subs.get("subdomains", []) if s.get("is_live")][:6]
            for s in live_subs:
                ips = s.get("ips", [])
                ip_str = f" → {ips[0]}" if ips else ""
                print(f"   ✓ {s['subdomain']}{ip_str}")
            if total > 6:
                print(f"   ... +{total - 6} more")

        # DNS Summary
        dns = self.results.get("dns", {})
        if dns:
            a_count = len(dns.get("A", []))
            mx_count = len(dns.get("MX", []))
            ns_count = len(dns.get("NS", []))
            print(f"\n📡 DNS: {a_count} A | {mx_count} MX | {ns_count} NS records")

        print("\n" + "─" * width)

    def print_summary(self):
        """Print comprehensive summary report (alias)"""
        self._print_full_summary()

    def save_text_report(self, filepath: Path) -> bool:
        """
        Save results as text report

        Args:
            filepath: Path to save report

        Returns:
            True if successful, False otherwise
        """
        try:
            with Path(filepath).open("w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("RANKLE - Web Infrastructure Reconnaissance Report\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Domain: {self.domain}\n")
                f.write(f"Scan Time: {self.scan_timestamp}\n")
                f.write("=" * 80 + "\n\n")

                # Write DNS results
                if "dns" in self.results:
                    f.write("DNS ANALYSIS\n")
                    f.write("-" * 80 + "\n")
                    dns = self.results["dns"]
                    for record_type, values in dns.items():
                        if values:
                            f.write(f"{record_type}: {values}\n")
                    f.write("\n")

                # Write SSL results
                if "ssl" in self.results and self.results["ssl"].get("valid"):
                    f.write("SSL/TLS CERTIFICATE\n")
                    f.write("-" * 80 + "\n")
                    ssl_data = self.results["ssl"]
                    cert = ssl_data.get("certificate", {})
                    f.write(f"Issuer: {cert.get('issuer', {})}\n")
                    f.write(f"Valid Until: {cert.get('valid_until', 'N/A')}\n")
                    f.write(
                        f"Security Grade: {ssl_data.get('security_grade', 'N/A')}\n"
                    )
                    f.write(f"SAN Domains: {len(ssl_data.get('san_domains', []))}\n")
                    f.write("\n")

                # Write Technology results
                if "technologies" in self.results and self.results["technologies"].get(
                    "detected"
                ):
                    f.write("TECHNOLOGIES DETECTED\n")
                    f.write("-" * 80 + "\n")
                    for tech in self.results["technologies"].get("technologies", []):
                        version = f" v{tech['version']}" if tech.get("version") else ""
                        f.write(f"- {tech['name']}{version} ({tech['category']})\n")
                    f.write("\n")

                # Write CDN/WAF results
                f.write("INFRASTRUCTURE\n")
                f.write("-" * 80 + "\n")
                cdn = self.results.get("cdn", {})
                waf = self.results.get("waf", {})
                f.write(f"CDN: {cdn.get('cdn', 'Not detected')}\n")
                f.write(f"WAF: {waf.get('waf', 'Not detected')}\n")
                f.write("\n")

                # Write Security Headers results
                if "security_headers" in self.results:
                    f.write("SECURITY HEADERS AUDIT\n")
                    f.write("-" * 80 + "\n")
                    headers = self.results["security_headers"]
                    f.write(
                        f"Grade: {headers.get('grade', 'N/A')} ({headers.get('score', 0)}/100)\n"
                    )
                    f.write(f"Missing Headers: {len(headers.get('missing', []))}\n")
                    f.writelines(
                        f"  - {missing.get('header')}: {missing.get('severity')}\n"
                        for missing in headers.get("missing", [])
                    )
                    f.write("\n")

                # Write Subdomain results
                if "subdomains" in self.results:
                    f.write("SUBDOMAINS\n")
                    f.write("-" * 80 + "\n")
                    subs = self.results["subdomains"]
                    f.write(f"Total Found: {subs.get('total_found', 0)}\n")
                    f.write(f"Live: {subs.get('live_count', 0)}\n")
                    for sub in subs.get("subdomains", [])[:20]:
                        status = "LIVE" if sub.get("is_live") else "DEAD"
                        f.write(f"  - {sub['subdomain']} [{status}]\n")
                    f.write("\n")

            return True
        except Exception as e:
            print(f"Error saving text report: {e}")
            return False

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources"""
        if self.session:
            self.session.close()

    def __del__(self):
        """Cleanup on deletion"""
        if hasattr(self, "session") and self.session:
            with contextlib.suppress(Exception):
                self.session.close()
