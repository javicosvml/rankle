#!/usr/bin/env python3
"""
Rankle - Web Infrastructure Reconnaissance Tool
Named after Rankle, Master of Pranks from Magic: The Gathering

A comprehensive web infrastructure analyzer using pure Python libraries:
- DNS enumeration and configuration
- Subdomain discovery via Certificate Transparency
- Technology stack detection (CMS, frameworks, libraries)
- TLS/SSL certificate analysis
- HTTP security headers audit
- CDN and WAF detection
- Geolocation and hosting provider information
- WHOIS lookup

100% Open Source - No API keys required
"""

import sys
import json
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    import dns.resolver
    from bs4 import BeautifulSoup
except ImportError:
    print("\n" + "=" * 80)
    print("❌ Missing required dependencies")
    print("=" * 80)
    print("\nPlease install required libraries:")
    print("  pip install requests dnspython beautifulsoup4")
    print("\nOptional libraries for extended functionality:")
    print("  pip install python-whois ipwhois builtwith")
    print("=" * 80 + "\n")
    sys.exit(1)


class Rankle:
    """Web infrastructure reconnaissance tool"""

    def __init__(self, url):
        self.url = url
        self.domain = self._extract_domain(url)
        self.results = {}
        self.scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.session = self._create_session()

        # Validate domain
        if not self._validate_domain(self.domain):
            raise ValueError(f"Invalid domain format: {self.domain}")

    def _extract_domain(self, url):
        """Extract clean domain from URL"""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port if present
        domain = domain.split(":")[0]
        return domain

    def _validate_domain(self, domain):
        """Validate domain format"""
        pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))

    def _create_session(self):
        """Create requests session with realistic headers"""
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            }
        )
        return session

    def analyze_http_headers(self):
        """Analyze HTTP headers and detect technologies from headers"""
        print("🌐 Analyzing HTTP Headers and Technologies...")

        try:
            response = self.session.get(f"https://{self.domain}", timeout=45, allow_redirects=True)

            headers = {k.lower(): v for k, v in response.headers.items()}

            # Detect technologies from headers
            technologies = []
            server = headers.get("server", "Unknown")
            technologies.append(f"Web Server: {server}")

            if headers.get("x-powered-by"):
                technologies.append(f"Powered by: {headers['x-powered-by']}")

            if headers.get("x-aspnet-version"):
                technologies.append(f"ASP.NET: {headers['x-aspnet-version']}")

            if headers.get("x-generator"):
                technologies.append(f"Generator: {headers['x-generator']}")

            # Security headers analysis
            security = {
                "x-frame-options": headers.get("x-frame-options"),
                "x-content-type-options": headers.get("x-content-type-options"),
                "strict-transport-security": headers.get("strict-transport-security"),
                "content-security-policy": headers.get("content-security-policy"),
                "x-xss-protection": headers.get("x-xss-protection"),
                "referrer-policy": headers.get("referrer-policy"),
                "permissions-policy": headers.get("permissions-policy"),
            }

            self.results["status_code"] = response.status_code
            self.results["headers"] = headers
            self.results["technologies"] = technologies
            self.results["security_headers"] = {k: v for k, v in security.items() if v}

            print(f"   └─ Status Code: {response.status_code}")
            print(f"   └─ Server: {server}")
            for tech in technologies[1:]:
                print(f"   └─ {tech}")

            return headers, response

        except requests.exceptions.SSLError as e:
            print(f"   └─ SSL Error: {str(e)}")
            return {}, None
        except requests.exceptions.RequestException as e:
            print(f"   └─ Error: {str(e)}")
            return {}, None

    def find_origin_infrastructure(self):
        """
        Try to find origin infrastructure behind WAF/CDN using passive techniques
        ETHICAL METHODS ONLY - No active attacks
        """
        print("\n🔎 Discovering Origin Infrastructure (behind WAF/CDN)...")

        origin_ips = set()
        origin_hostnames = set()
        methods_found = []

        # Method 1: Historical DNS records from subdomain enumeration
        if "subdomains" in self.results:
            print("   └─ Method 1: Checking subdomains for origin IPs...")
            for subdomain in self.results.get("subdomains", [])[:20]:
                try:
                    # Look for common non-CDN subdomains
                    if any(
                        keyword in subdomain.lower()
                        for keyword in ["origin", "direct", "admin", "vpn", "mail", "ftp", "cpanel"]
                    ):
                        import dns.resolver

                        answers = dns.resolver.resolve(subdomain, "A")
                        for rdata in answers:
                            ip = str(rdata)
                            # Check if it's different from main domain IPs
                            main_ips = self.results.get("dns", {}).get("A", [])
                            if ip not in main_ips:
                                origin_ips.add(ip)
                                origin_hostnames.add(subdomain)
                                methods_found.append("subdomain_scan")
                except:
                    pass

        # Method 2: MX records (mail servers often reveal origin network)
        if "dns" in self.results and self.results["dns"].get("MX"):
            print("   └─ Method 2: Analyzing MX records for origin network...")
            try:
                mx_records = self.results["dns"]["MX"]
                for mx in mx_records[:3]:
                    mx_host = mx.split()[-1].rstrip(".")
                    try:
                        import dns.resolver

                        answers = dns.resolver.resolve(mx_host, "A")
                        for rdata in answers:
                            ip = str(rdata)
                            origin_ips.add(ip)
                            methods_found.append("mx_records")
                            # Get ASN for this IP to identify hosting
                            try:
                                import requests

                                geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
                                if "org" in geo:
                                    print(f"      • MX IP: {ip} ({geo.get('org', 'Unknown')})")
                            except:
                                pass
                    except:
                        pass
            except:
                pass

        # Method 3: TXT/SPF records may reveal origin IPs
        if "dns" in self.results and self.results["dns"].get("TXT"):
            print("   └─ Method 3: Parsing SPF/TXT records...")
            txt_records = self.results["dns"]["TXT"]
            for txt in txt_records:
                # Look for SPF records with IP addresses
                if "v=spf1" in txt.lower() or "ip4:" in txt.lower():
                    import re

                    # Extract IPs from SPF
                    ips = re.findall(r"ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", txt)
                    for ip_range in ips:
                        ip = ip_range.split("/")[0]
                        origin_ips.add(ip)
                        methods_found.append("spf_records")
                        print(f"      • SPF IP: {ip}")

        # Method 4: Check SSL certificate SAN for origin domains
        if "tls" in self.results and self.results["tls"].get("san_domains"):
            print("   └─ Method 4: Checking SSL SANs for direct-access domains...")
            san_domains = self.results["tls"]["san_domains"]
            for san in san_domains[:10]:
                if any(keyword in san.lower() for keyword in ["origin", "direct", "admin", "-backend", "-api"]):
                    try:
                        import dns.resolver

                        answers = dns.resolver.resolve(san, "A")
                        for rdata in answers:
                            ip = str(rdata)
                            origin_ips.add(ip)
                            origin_hostnames.add(san)
                            methods_found.append("ssl_san")
                    except:
                        pass

        # Method 5: Check for common bypasses (www vs non-www, different protocols)
        print("   └─ Method 5: Testing common origin access patterns...")
        test_domains = []
        base = self.domain.replace("www.", "")

        # Generate test patterns
        test_domains.extend([f"origin.{base}", f"direct.{base}", f"admin.{base}", f"backend.{base}", f"api.{base}"])

        for test_domain in test_domains[:5]:
            try:
                import dns.resolver

                answers = dns.resolver.resolve(test_domain, "A")
                for rdata in answers:
                    ip = str(rdata)
                    main_ips = self.results.get("dns", {}).get("A", [])
                    if ip not in main_ips:
                        origin_ips.add(ip)
                        origin_hostnames.add(test_domain)
                        methods_found.append("pattern_discovery")
                        print(f"      • Found: {test_domain} → {ip}")
            except:
                pass

        # Analyze origin IPs to detect hosting
        origin_providers = []
        if origin_ips:
            print(f"\n   📍 Potential Origin IPs Found: {len(origin_ips)}")
            for ip in list(origin_ips)[:5]:
                try:
                    provider, confidence, hostname = self.detect_cloud_provider(ip)
                    if provider != "Unknown":
                        origin_providers.append(
                            {"ip": ip, "provider": provider, "confidence": confidence, "hostname": hostname}
                        )
                        print(f"      • {ip} → {provider} ({confidence} confidence)")
                except:
                    print(f"      • {ip}")

        # Store results
        origin_info = {
            "found": len(origin_ips) > 0,
            "methods_used": list(set(methods_found)),
            "origin_ips": list(origin_ips),
            "origin_hostnames": list(origin_hostnames),
            "origin_providers": origin_providers,
        }

        self.results["origin_infrastructure"] = origin_info

        if not origin_ips:
            print("   └─ No alternative infrastructure found (strong WAF/CDN)")

        return origin_info

    def enumerate_subdomains_crtsh(self):
        """
        Enumerate subdomains using Certificate Transparency logs
        Queries crt.sh without requiring API keys - 100% passive
        """
        print("\n🔍 Enumerating Subdomains via Certificate Transparency...")

        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()

        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Can have multiple subdomains per line
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower().replace("*.", "")
                        if subdomain and self.domain in subdomain:
                            subdomains.add(subdomain)

                subdomain_list = sorted(list(subdomains))
                self.results["subdomains"] = subdomain_list
                print(f"   └─ Found: {len(subdomains)} subdomains")

                # Display first 10
                for sub in subdomain_list[:10]:
                    print(f"      • {sub}")
                if len(subdomains) > 10:
                    print(f"      ... and {len(subdomains) - 10} more")

                return subdomain_list
            else:
                print(f"   └─ crt.sh returned status code: {response.status_code}")
                return []

        except Exception as e:
            print(f"   └─ Error: {str(e)}")
            return []

    def analyze_dns(self):
        """
        Comprehensive DNS enumeration using dnspython
        No external dependencies required
        """
        print("\n📡 Analyzing DNS Configuration...")

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        base_domain = self.domain.replace("www.", "")
        dns_records = {}

        record_types = {
            "A": "IPv4 Addresses",
            "AAAA": "IPv6 Addresses",
            "MX": "Mail Servers",
            "NS": "Name Servers",
            "TXT": "TXT Records",
            "SOA": "Start of Authority",
            "CNAME": "Canonical Name",
        }

        for record_type, description in record_types.items():
            try:
                # Use base_domain for organizational records
                query_domain = base_domain if record_type in ["MX", "NS", "TXT", "SOA"] else self.domain

                answers = resolver.resolve(query_domain, record_type)

                if record_type == "MX":
                    dns_records[record_type] = [f"{rdata.preference} {rdata.exchange}" for rdata in answers]
                else:
                    dns_records[record_type] = [str(rdata) for rdata in answers]

                # Display results
                records_display = ", ".join(dns_records[record_type][:3])
                if len(dns_records[record_type]) > 3:
                    records_display += f" ... (+{len(dns_records[record_type]) - 3})"
                print(f"   └─ {description}: {records_display}")

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dns_records[record_type] = []
            except dns.exception.Timeout:
                dns_records[record_type] = []
                print(f"   └─ {description}: Timeout")
            except Exception as e:
                dns_records[record_type] = []

        self.results["dns"] = dns_records
        return dns_records

    def analyze_tls_certificate(self):
        """
        Analyze TLS/SSL certificate using Python's ssl module
        No external tools required - pure Python
        """
        print("\n🔒 Analyzing TLS/SSL Certificate...")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

            # Extract certificate information
            tls_info = {
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "version": cert.get("version"),
                "serial_number": cert.get("serialNumber"),
                "valid_from": cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
                "san_domains": [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"],
                "cipher_suite": cipher,
                "tls_version": version,
            }

            issuer_org = tls_info["issuer"].get("organizationName", "N/A")
            print(f"   └─ Issuer: {issuer_org}")
            print(f"   └─ Valid Until: {tls_info['valid_until']}")
            print(f"   └─ TLS Version: {version}")
            print(f"   └─ Cipher: {cipher[0] if cipher else 'N/A'}")

            if tls_info["san_domains"]:
                print(f"   └─ SANs: {len(tls_info['san_domains'])} domains")
                for san in tls_info["san_domains"][:5]:
                    print(f"      • {san}")
                if len(tls_info["san_domains"]) > 5:
                    print(f"      ... and {len(tls_info['san_domains']) - 5} more")

            self.results["tls"] = tls_info
            return tls_info

        except socket.timeout:
            print(f"   └─ Connection timeout")
            return None
        except ssl.SSLError as e:
            print(f"   └─ SSL Error: {str(e)}")
            return None
        except Exception as e:
            print(f"   └─ Error: {str(e)}")
            return None

    def advanced_fingerprinting(self, response=None):
        """
        Advanced fingerprinting using multiple techniques
        """
        print("\n🔬 Advanced Infrastructure Fingerprinting...")

        fingerprint_results = {
            "http_methods": [],
            "server_fingerprint": {},
            "api_endpoints": [],
            "exposed_files": [],
            "http_response_patterns": {},
            "cookie_analysis": {},
            "error_pages": {},
            "technology_headers": {},
            "framework_detection": {},
        }

        try:
            if response is None:
                response = self.session.get(f"https://{self.domain}", timeout=30)

            # 1. HTTP Methods Testing (OPTIONS, HEAD, TRACE)
            print("   └─ Testing HTTP methods...")
            methods_to_test = ["OPTIONS", "HEAD", "TRACE", "PUT", "DELETE", "PATCH"]
            allowed_methods = []

            for method in methods_to_test:
                try:
                    resp = self.session.request(method, f"https://{self.domain}", timeout=5)
                    if resp.status_code not in [405, 501]:
                        allowed_methods.append(method)
                except:
                    pass

            if allowed_methods:
                fingerprint_results["http_methods"] = allowed_methods
                print(f"      • Allowed methods: {', '.join(allowed_methods)}")

            # 2. Server Signature Analysis
            print("   └─ Analyzing server signature...")
            server_header = response.headers.get("Server", "")
            x_powered_by = response.headers.get("X-Powered-By", "")

            # Extract version numbers from Server header
            version_patterns = {
                "Apache": r"Apache/(\d+\.\d+\.\d+)",
                "Nginx": r"nginx/(\d+\.\d+\.\d+)",
                "IIS": r"Microsoft-IIS/(\d+\.\d+)",
                "LiteSpeed": r"LiteSpeed/(\d+\.\d+\.\d+)",
                "Tomcat": r"Apache Tomcat/(\d+\.\d+\.\d+)",
                "Node.js": r"Node\.js/(\d+\.\d+\.\d+)",
                "Express": r"Express/(\d+\.\d+\.\d+)",
            }

            for tech, pattern in version_patterns.items():
                match = re.search(pattern, server_header, re.IGNORECASE)
                if match:
                    fingerprint_results["server_fingerprint"][tech] = match.group(1)
                    print(f"      • {tech} version: {match.group(1)}")

            # 3. Common API Endpoints Discovery
            print("   └─ Probing common API endpoints...")
            api_endpoints = [
                "/api",
                "/api/v1",
                "/api/v2",
                "/graphql",
                "/rest",
                "/swagger",
                "/api-docs",
                "/openapi.json",
                "/.well-known/security.txt",
                "/robots.txt",
                "/sitemap.xml",
                "/health",
                "/status",
                "/metrics",
                "/actuator",
                "/.git/config",
                "/.env",
                "/config.json",
                "/wp-json",
                "/api/users",
                "/api/config",
            ]

            found_endpoints = []
            for endpoint in api_endpoints[:15]:  # Test first 15
                try:
                    test_url = f"https://{self.domain}{endpoint}"
                    resp = self.session.head(test_url, timeout=3, allow_redirects=False)
                    if resp.status_code in [200, 201, 301, 302, 403]:
                        found_endpoints.append(
                            {
                                "endpoint": endpoint,
                                "status": resp.status_code,
                                "content_type": resp.headers.get("Content-Type", "Unknown"),
                            }
                        )
                        print(f"      • Found: {endpoint} [{resp.status_code}]")
                except:
                    pass

            fingerprint_results["api_endpoints"] = found_endpoints

            # 4. Exposed Sensitive Files
            print("   └─ Checking for exposed files...")
            sensitive_files = [
                "/phpinfo.php",
                "/info.php",
                "/.htaccess",
                "/web.config",
                "/composer.json",
                "/package.json",
                "/yarn.lock",
                "/.DS_Store",
                "/backup.sql",
                "/database.sql",
                "/.git/HEAD",
                "/.svn/entries",
                "/CVS/Entries",
            ]

            exposed = []
            for file_path in sensitive_files[:10]:
                try:
                    test_url = f"https://{self.domain}{file_path}"
                    resp = self.session.head(test_url, timeout=3)
                    if resp.status_code == 200:
                        exposed.append(file_path)
                        print(f"      ⚠️  Exposed: {file_path}")
                except:
                    pass

            fingerprint_results["exposed_files"] = exposed

            # 5. Cookie Analysis
            print("   └─ Analyzing cookies...")
            cookies = response.cookies
            cookie_info = {}

            for cookie in cookies:
                cookie_info[cookie.name] = {
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite", "None"),
                }

                # Identify technology by cookie name
                cookie_techs = {
                    "PHPSESSID": "PHP",
                    "JSESSIONID": "Java/Tomcat",
                    "ASP.NET_SessionId": "ASP.NET",
                    "__cfduid": "Cloudflare",
                    "_ga": "Google Analytics",
                    "wordpress_": "WordPress",
                    "drupal": "Drupal",
                }

                for pattern, tech in cookie_techs.items():
                    if pattern.lower() in cookie.name.lower():
                        print(f"      • {cookie.name} → {tech}")
                        if "detected_from_cookies" not in fingerprint_results:
                            fingerprint_results["detected_from_cookies"] = []
                        fingerprint_results["detected_from_cookies"].append(tech)

            fingerprint_results["cookie_analysis"] = cookie_info

            # 6. Error Page Fingerprinting
            print("   └─ Fingerprinting error pages...")
            error_urls = [
                "/this-page-does-not-exist-404",
                "/admin/secret",
                "/test.php?id=1'",  # SQL injection attempt for error detection
            ]

            for error_url in error_urls[:1]:  # Just test 404
                try:
                    test_url = f"https://{self.domain}{error_url}"
                    resp = self.session.get(test_url, timeout=5)

                    # Analyze error page content
                    error_patterns = {
                        "Apache": ["Apache", "apache2"],
                        "Nginx": ["nginx"],
                        "IIS": ["Microsoft-IIS", "Internet Information Services"],
                        "Tomcat": ["Apache Tomcat"],
                        "Django": ["DisallowedHost", "Django"],
                        "Flask": ["Werkzeug", "Flask"],
                        "Express": ["Express"],
                        "Rails": ["Ruby on Rails", "ActionController"],
                    }

                    error_text = resp.text.lower()
                    for tech, patterns in error_patterns.items():
                        if any(pattern.lower() in error_text for pattern in patterns):
                            if "error_page_tech" not in fingerprint_results:
                                fingerprint_results["error_page_tech"] = []
                            if tech not in fingerprint_results["error_page_tech"]:
                                fingerprint_results["error_page_tech"].append(tech)
                                print(f"      • Error page reveals: {tech}")
                except:
                    pass

            # 7. Technology-Specific Headers
            print("   └─ Analyzing technology-specific headers...")
            tech_headers = {
                "X-AspNet-Version": "ASP.NET",
                "X-AspNetMvc-Version": "ASP.NET MVC",
                "X-Powered-By": "Various",
                "X-Generator": "CMS/Framework",
                "X-Drupal-Cache": "Drupal",
                "X-Drupal-Dynamic-Cache": "Drupal",
                "X-Varnish": "Varnish Cache",
                "X-Nginx-Cache-Status": "Nginx",
                "X-Cache": "Caching Layer",
                "CF-Cache-Status": "Cloudflare",
                "X-Amz-Cf-Id": "Amazon CloudFront",
                "X-Azure-Ref": "Microsoft Azure",
            }

            detected_headers = {}
            for header, tech in tech_headers.items():
                if header in response.headers:
                    detected_headers[header] = {"technology": tech, "value": response.headers[header]}
                    print(f"      • {header}: {response.headers[header][:50]}")

            fingerprint_results["technology_headers"] = detected_headers

            # 8. Response Time Analysis (can indicate technology)
            print("   └─ Response time analysis...")
            try:
                import time

                start = time.time()
                self.session.head(f"https://{self.domain}", timeout=10)
                response_time = (time.time() - start) * 1000
                fingerprint_results["response_time_ms"] = round(response_time, 2)
                print(f"      • Response time: {response_time:.2f}ms")
            except:
                pass

            # Store results
            self.results["advanced_fingerprint"] = fingerprint_results

            return fingerprint_results

        except Exception as e:
            print(f"   └─ Error during fingerprinting: {str(e)}")
            return fingerprint_results

    def detect_technologies(self, response=None):
        """
        Detect web technologies including CMS, frameworks, and libraries
        Analyzes HTML content and performs fingerprinting
        """
        print("\n🔧 Detecting Web Technologies...")

        try:
            if response is None:
                response = self.session.get(f"https://{self.domain}", timeout=60)

            html = response.text
            soup = BeautifulSoup(html, "html.parser")
            html_lower = html.lower()

            # Primary CMS detection
            cms = self._detect_cms(html_lower, soup)

            # If CMS not detected, try alternative detection methods
            if cms == "Unknown":
                cms = self._detect_cms_advanced(response, soup)

            technologies = {
                "cms": cms,
                "frameworks": self._detect_js_frameworks(html_lower),
                "analytics": self._detect_analytics(html_lower),
                "cdn": self._detect_cdn_libraries(html_lower),
                "server_side": [],
                "libraries": self._detect_libraries(html_lower, soup),
            }

            # Meta generator tag
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                technologies["server_side"].append(f"Generator: {generator['content']}")

            # Display results
            print(f"   └─ CMS: {technologies['cms']}")

            if technologies["frameworks"]:
                print(f"   └─ JavaScript Frameworks: {', '.join(technologies['frameworks'])}")

            if technologies["analytics"]:
                print(f"   └─ Analytics: {', '.join(technologies['analytics'][:3])}")

            if technologies["cdn"]:
                print(f"   └─ CDN/Libraries: {', '.join(technologies['cdn'][:3])}")

            if technologies["libraries"]:
                print(f"   └─ Libraries: {', '.join(technologies['libraries'][:5])}")

            self.results["technologies_web"] = technologies
            return technologies

        except Exception as e:
            print(f"   └─ Error: {str(e)}")
            return None

    def _detect_cms_advanced(self, response, soup):
        """Advanced CMS detection using multiple techniques"""
        cms = "Unknown"

        # Check robots.txt for CMS hints
        try:
            robots_response = self.session.get(f"https://{self.domain}/robots.txt", timeout=5)
            if robots_response.status_code == 200:
                robots_text = robots_response.text.lower()

                if any(
                    indicator in robots_text for indicator in ["/core/", "/sites/", "drupal", "/user/", "/admin/?q="]
                ):
                    print(f"   └─ CMS Detection: Found Drupal hints in robots.txt")
                    return "Drupal"
                elif any(indicator in robots_text for indicator in ["/wp-admin", "/wp-content", "/wp-includes"]):
                    return "WordPress"
                elif any(indicator in robots_text for indicator in ["/administrator/", "/components/"]):
                    return "Joomla"
        except:
            pass

        # Check specific URLs that CMSs typically have
        common_paths = {
            "Drupal": [
                "/core/misc/drupal.js",
                "/sites/default/files/",
                "/user/login",
                "/core/themes/stable/css/system/components/ajax-progress.module.css",
                "/core/install.php",
                "/update.php",
            ],
            "WordPress": ["/wp-admin/", "/wp-login.php", "/wp-content/plugins/", "/xmlrpc.php"],
            "Joomla": ["/administrator/", "/components/com_content/", "/media/jui/js/"],
        }

        # Try accessing common paths (with timeout)
        for cms_name, paths in common_paths.items():
            for path in paths[:2]:  # Only check first 2 to save time
                try:
                    test_url = f"https://{self.domain}{path}"
                    test_response = self.session.head(test_url, timeout=5, allow_redirects=False)
                    # If we get 200, 301, 302, 403 (forbidden but exists), it's likely there
                    if test_response.status_code in [200, 301, 302, 403]:
                        print(f"   └─ CMS Detection: Found {cms_name} path: {path}")
                        return cms_name
                except:
                    pass

        # Check for specific HTML/CSS classes and IDs
        if soup.find(attrs={"class": re.compile(r"drupal|views-|block-|node-|page-node")}):
            return "Drupal"

        if soup.find(attrs={"id": re.compile(r"drupal-|block-")}):
            return "Drupal"

        if soup.find(attrs={"data-drupal-selector": True}):
            return "Drupal"

        # Check for WordPress indicators
        if soup.find(attrs={"class": re.compile(r"wp-|wordpress")}):
            return "WordPress"

        return cms

    def _detect_libraries(self, html_lower, soup):
        """Detect common JavaScript libraries and frameworks"""
        libraries = []

        # Check for common libraries in script tags
        scripts = soup.find_all("script", src=True)

        library_patterns = {
            "jQuery": r"jquery",
            "Bootstrap": r"bootstrap",
            "React": r"react",
            "Vue": r"vue",
            "Angular": r"angular",
            "Lodash": r"lodash",
            "Moment.js": r"moment",
            "D3.js": r"d3\.js|d3\.min",
            "Three.js": r"three\.js|three\.min",
            "Chart.js": r"chart\.js",
            "Axios": r"axios",
            "Swiper": r"swiper",
            "Slick": r"slick",
            "AOS": r"aos\.js",
            "GSAP": r"gsap|tweenmax",
            "Modernizr": r"modernizr",
            "Popper.js": r"popper",
        }

        for script in scripts:
            src = script.get("src", "").lower()
            for lib_name, pattern in library_patterns.items():
                if re.search(pattern, src) and lib_name not in libraries:
                    libraries.append(lib_name)

        return libraries

    def _detect_cms(self, html_lower, soup):
        """Detect Content Management System from HTML"""
        cms_patterns = {
            "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/", r"wp-emoji"],
            "Drupal": [
                r"drupal",
                r"sites/default",
                r"sites/all",
                r"misc/drupal\.js",
                r"/core/misc/drupal",
                r"/core/themes/",
                r"/core/modules/",
                r"drupal\.settings",
                r"drupal\.js",
                r"drupal-ajax",
                r"data-drupal-",
                r"/modules/contrib/",
                r"/themes/contrib/",
                r"drupal-render-placeholder",
            ],
            "Joomla": [r"joomla", r"option=com_", r"joomla!"],
            "Magento": [r"magento", r"mage/cookies", r"skin/frontend"],
            "Shopify": [r"shopify", r"cdn.shopify.com", r"shopifycdn"],
            "Wix": [r"wix.com", r"parastorage", r"static.wixstatic.com"],
            "Squarespace": [r"squarespace", r"static.squarespace.com"],
            "Ghost": [r"ghost.io", r"ghost.min.js"],
            "Hugo": [r"generated by hugo"],
            "Jekyll": [r"jekyll"],
            "Webflow": [r"webflow.com", r"webflow.io"],
            "PrestaShop": [r"prestashop"],
            "OpenCart": [r"opencart"],
            "TYPO3": [r"typo3", r"typo3conf"],
            "Concrete5": [r"concrete5", r"ccm_"],
            "ModX": [r"modx"],
        }

        for cms_name, patterns in cms_patterns.items():
            if any(re.search(pattern, html_lower) for pattern in patterns):
                # Try to detect version
                version = None

                if cms_name == "WordPress":
                    meta = soup.find("meta", attrs={"name": "generator"})
                    if meta and "wordpress" in meta.get("content", "").lower():
                        version = meta.get("content")
                        return version

                if cms_name == "Drupal":
                    # Try to get Drupal version
                    meta = soup.find("meta", attrs={"name": "generator"})
                    if meta and "drupal" in meta.get("content", "").lower():
                        return meta.get("content")

                    # Check for Drupal version in various patterns
                    version_match = re.search(r"drupal[.\s]+(\d+(?:\.\d+)*)", html_lower)
                    if version_match:
                        return f"Drupal {version_match.group(1)}"

                return cms_name

        return "Unknown"

    def _detect_js_frameworks(self, html_lower):
        """Detect JavaScript frameworks"""
        frameworks = []

        patterns = {
            "React": [r"react", r"_react", r"react-dom"],
            "Vue.js": [r"vue\.js", r"__vue__", r"vue\.min\.js"],
            "Angular": [r"angular", r"ng-app", r"ng-version"],
            "jQuery": [r"jquery"],
            "Next.js": [r"next\.js", r"__next", r"_next/"],
            "Nuxt": [r"nuxt", r"__nuxt"],
            "Svelte": [r"svelte"],
            "Ember.js": [r"ember"],
            "Backbone.js": [r"backbone"],
            "Alpine.js": [r"alpine"],
        }

        for fw_name, fw_patterns in patterns.items():
            if any(re.search(pattern, html_lower) for pattern in fw_patterns):
                frameworks.append(fw_name)

        return frameworks

    def _detect_analytics(self, html_lower):
        """Detect analytics and tracking tools"""
        analytics = []

        patterns = {
            "Google Analytics": r"google-analytics\.com|gtag\(|ga\(",
            "Google Tag Manager": r"googletagmanager\.com|gtm\.js",
            "Matomo": r"matomo|piwik",
            "Hotjar": r"hotjar",
            "Facebook Pixel": r"facebook\.net/.*\/fbevents\.js|connect\.facebook\.net",
            "Mixpanel": r"mixpanel",
            "Segment": r"segment\.com|analytics\.js",
            "Plausible": r"plausible\.io",
            "Fathom": r"fathom",
            "Cloudflare Analytics": r"cloudflareinsights",
        }

        for analytics_name, pattern in patterns.items():
            if re.search(pattern, html_lower):
                analytics.append(analytics_name)

        return analytics

    def _detect_cdn_libraries(self, html_lower):
        """Detect CDN and external libraries"""
        cdns = []

        patterns = {
            "Cloudflare CDN": r"cdnjs\.cloudflare\.com",
            "jsDelivr": r"cdn\.jsdelivr\.net",
            "unpkg": r"unpkg\.com",
            "Google CDN": r"ajax\.googleapis\.com",
            "Microsoft CDN": r"ajax\.aspnetcdn\.com",
            "jQuery CDN": r"code\.jquery\.com",
            "Bootstrap CDN": r"stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com",
            "FontAwesome": r"fontawesome|font-awesome",
        }

        for cdn_name, pattern in patterns.items():
            if re.search(pattern, html_lower):
                cdns.append(cdn_name)

        return cdns

    def detect_cdn_waf(self, headers, cnames=None):
        """Detect CDN and Web Application Firewall"""
        print("\n🚀 Detecting CDN and WAF...")

        cdn_indicators = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status", "__cf"],
            "Fastly": ["fastly", "x-fastly", "x-timer"],
            "Akamai": ["akamai", "akamaighost", "akamaitechnologies", "edgesuite", "edgekey"],
            "Amazon CloudFront": ["cloudfront", "x-amz-cf", "x-cache"],
            "TransparentEdge": ["transparentedge", "edge2befaster", "edgetcdn", "tp-cache", "tedge", "x-edge"],
            "KeyCDN": ["keycdn"],
            "StackPath": ["stackpath", "netdna"],
            "Varnish": ["varnish", "x-varnish", "via.*varnish"],
            "Incapsula": ["incapsula", "visid_incap", "x-cdn: incapsula"],
            "Sucuri": ["sucuri", "x-sucuri", "cloudproxy"],
            "BunnyCDN": ["bunnycdn", "bunny.net"],
            "Netlify": ["netlify", "x-nf-"],
            "Azure CDN": ["azureedge", "azure-cdn"],
            "Google Cloud CDN": ["gcdn", "google-cdn"],
            "MaxCDN": ["maxcdn"],
            "CDN77": ["cdn77"],
            "jsDelivr": ["jsdelivr"],
        }

        waf_indicators = {
            "Cloudflare WAF": ["cf-ray", "cloudflare"],
            "Akamai WAF": ["akamai", "akamaighost"],
            "Sucuri WAF": ["sucuri", "cloudproxy"],
            "Incapsula/Imperva": ["incapsula", "visid_incap", "imperva"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "AWS WAF": ["x-amzn-waf", "x-amzn-requestid", "awselb", "x-amzn-trace-id", "x-amz-apigw"],
            "Barracuda": ["barracuda", "barra"],
            "F5 BIG-IP ASM": ["bigip", "f5", "f5-trace"],
            "Fortinet FortiWeb": ["fortiweb", "fortigate"],
            "Wordfence": ["wordfence"],
            "Cloudflare Bot Management": ["cf-ray", "cloudflare-nginx"],
            "PerimeterX": ["perimeterx", "_px", "px-"],
            "Reblaze": ["reblaze", "rbzid"],
            "TransparentEdge WAF": ["transparentedge", "tedge"],
            "Wallarm": ["wallarm"],
            "Radware": ["radware"],
            "Citrix NetScaler": ["netscaler", "citrix"],
            "DataDome": ["datadome"],
        }

        detected_cdns = []
        detected_wafs = []
        detection_methods = []

        # Search in headers
        headers_str = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()

        for cdn_name, indicators in cdn_indicators.items():
            if any(re.search(indicator, headers_str) for indicator in indicators):
                if cdn_name not in detected_cdns:
                    detected_cdns.append(cdn_name)

        for waf_name, indicators in waf_indicators.items():
            if any(re.search(indicator, headers_str) for indicator in indicators):
                if waf_name not in detected_wafs:
                    detected_wafs.append(waf_name)
                    detection_methods.append(f"{waf_name} (header signature)")

        # Search in CNAMEs if provided
        if cnames:
            cnames_str = " ".join(cnames).lower()
            for cdn_name, indicators in cdn_indicators.items():
                if any(re.search(indicator, cnames_str) for indicator in indicators):
                    if cdn_name not in detected_cdns:
                        detected_cdns.append(cdn_name)

        # Get IP and check if it belongs to known CDN ranges
        dns_records = self.results.get("dns", {})
        if dns_records.get("A"):
            ip = dns_records["A"][0]
            cdn_from_ip = self._detect_cdn_by_ip(ip)
            if cdn_from_ip and cdn_from_ip not in detected_cdns:
                detected_cdns.append(cdn_from_ip)

        # Active WAF detection with test payloads
        active_waf = self._active_waf_detection()
        if active_waf and active_waf not in detected_wafs:
            detected_wafs.append(active_waf["name"])
            detection_methods.append(f"{active_waf['name']} (active detection: {active_waf['method']})")

        cdn_result = ", ".join(detected_cdns) if detected_cdns else "Not detected"
        waf_result = ", ".join(detected_wafs) if detected_wafs else "Not detected"

        print(f"   └─ CDN: {cdn_result}")
        print(f"   └─ WAF: {waf_result}")
        if detection_methods:
            for method in detection_methods:
                print(f"      • {method}")

        self.results["cdn"] = cdn_result
        self.results["waf"] = waf_result
        self.results["waf_detection_methods"] = detection_methods

        return cdn_result, waf_result

    def _active_waf_detection(self):
        """
        Active WAF detection using test payloads
        ETHICAL: Only uses non-intrusive detection payloads
        """
        print("   └─ Running active WAF detection tests...")

        # Test payloads that trigger WAF responses
        test_payloads = [
            {
                "name": "XSS Detection",
                "param": "?test=<script>alert(1)</script>",
                "expected_blocks": ["AWS WAF", "Cloudflare WAF", "ModSecurity"],
            },
            {
                "name": "SQL Injection Detection",
                "param": "?id=1' OR '1'='1",
                "expected_blocks": ["AWS WAF", "Cloudflare WAF", "ModSecurity"],
            },
            {
                "name": "Path Traversal Detection",
                "param": "?file=../../../etc/passwd",
                "expected_blocks": ["AWS WAF", "Cloudflare WAF"],
            },
            {
                "name": "Command Injection Detection",
                "param": "?cmd=|cat /etc/passwd",
                "expected_blocks": ["AWS WAF", "ModSecurity"],
            },
        ]

        # Get baseline response
        try:
            baseline = self.session.get(f"https://{self.domain}", timeout=10, allow_redirects=False)
            baseline_status = baseline.status_code
            baseline_headers = {k.lower(): v for k, v in baseline.headers.items()}
        except Exception as e:
            print(f"      • Baseline request failed: {str(e)}")
            return None

        # Test each payload
        for payload_test in test_payloads[:2]:  # Limit to first 2 tests
            try:
                test_url = f"https://{self.domain}/{payload_test['param']}"
                response = self.session.get(test_url, timeout=10, allow_redirects=False)

                # Check for WAF indicators
                status = response.status_code
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                resp_text = response.text.lower() if len(response.text) < 10000 else ""

                # AWS WAF specific indicators
                aws_waf_indicators = [
                    status == 403,  # Common block status
                    status == 405,
                    "x-amzn-requestid" in resp_headers,
                    "x-amzn-errortype" in resp_headers,
                    "x-amz-apigw-id" in resp_headers,
                    "awselb" in str(resp_headers),
                    "x-amzn-trace-id" in resp_headers,
                    "request blocked" in resp_text,
                    "aws waf" in resp_text,
                    "access denied" in resp_text and "cloudfront" in str(resp_headers),
                ]

                if sum(aws_waf_indicators) >= 2:
                    print(f"      ✓ AWS WAF detected via {payload_test['name']}")
                    return {
                        "name": "AWS WAF",
                        "method": payload_test["name"],
                        "status": status,
                        "confidence": "high" if sum(aws_waf_indicators) >= 3 else "medium",
                    }

                # Cloudflare WAF indicators
                if status == 403 and any(k.startswith("cf-") for k in resp_headers.keys()):
                    print(f"      ✓ Cloudflare WAF detected via {payload_test['name']}")
                    return {
                        "name": "Cloudflare WAF",
                        "method": payload_test["name"],
                        "status": status,
                        "confidence": "high",
                    }

                # Generic WAF detection
                if status in [403, 406, 419, 429, 501] and status != baseline_status:
                    # Check response body for WAF signatures
                    waf_signatures = {
                        "AWS WAF": ["aws", "cloudfront", "access denied", "forbidden"],
                        "ModSecurity": ["mod_security", "modsecurity", "not acceptable"],
                        "Generic WAF": ["web application firewall", "security policy", "request blocked"],
                    }

                    for waf_name, signatures in waf_signatures.items():
                        if any(sig in resp_text for sig in signatures):
                            print(f"      ✓ {waf_name} detected via {payload_test['name']}")
                            return {
                                "name": waf_name,
                                "method": payload_test["name"],
                                "status": status,
                                "confidence": "medium",
                            }

            except requests.exceptions.RequestException:
                pass
            except Exception as e:
                print(f"      • Test failed: {str(e)}")

        print("      • No WAF detected via active testing")
        return None

    def _detect_cdn_by_ip(self, ip):
        """Try to detect CDN by IP address using reverse DNS"""
        try:
            import socket

            hostname = socket.gethostbyaddr(ip)[0].lower()

            cdn_domains = {
                "cloudflare": "Cloudflare",
                "cloudfront": "Amazon CloudFront",
                "akamai": "Akamai",
                "fastly": "Fastly",
                "edgecast": "EdgeCast/Verizon",
                "transparentedge": "TransparentEdge",
                "bunny": "BunnyCDN",
                "netlify": "Netlify",
            }

            for domain, cdn_name in cdn_domains.items():
                if domain in hostname:
                    return cdn_name
        except:
            pass

        return None

    def detect_cloud_provider(self, ip, isp_name=None, hostname=None):
        """
        Detect cloud/hosting provider based on IP, ISP, and hostname
        """
        provider = "Unknown"
        confidence = "low"

        # Cloud provider patterns
        cloud_patterns = {
            "AWS": {
                "asn": ["AS16509", "AS14618", "AS8987"],
                "isp": ["amazon", "aws", "amazon.com", "amazon data services"],
                "hostname": ["amazonaws.com", "compute.amazonaws", "ec2", "s3", "cloudfront"],
                "ip_ranges": [],  # Could add IP ranges
            },
            "Azure": {
                "asn": ["AS8075", "AS8068"],
                "isp": ["microsoft", "azure", "microsoft corporation"],
                "hostname": ["azurewebsites", "azure", "cloudapp.azure", "windows.net", "azureedge"],
                "ip_ranges": [],
            },
            "Google Cloud (GCP)": {
                "asn": ["AS15169", "AS19527", "AS139190", "AS396982"],
                "isp": ["google", "google cloud", "google llc"],
                "hostname": ["googleusercontent", "google", "gcp", "appspot", "1e100.net"],
                "ip_ranges": [],
            },
            "DigitalOcean": {
                "asn": ["AS14061"],
                "isp": ["digitalocean", "digital ocean"],
                "hostname": ["digitalocean.com", "digitaloceanspaces"],
                "ip_ranges": [],
            },
            "OVH": {
                "asn": ["AS16276"],
                "isp": ["ovh", "ovh sas", "ovh hosting"],
                "hostname": ["ovh.net", "ovh.com", "ovhcloud.com"],
                "ip_ranges": [],
            },
            "Hetzner": {
                "asn": ["AS24940"],
                "isp": ["hetzner", "hetzner online"],
                "hostname": ["hetzner.de", "hetzner.com", "your-server.de"],
                "ip_ranges": [],
            },
            "Linode": {
                "asn": ["AS63949"],
                "isp": ["linode", "akamai"],
                "hostname": ["linode.com", "linodeusercontent.com"],
                "ip_ranges": [],
            },
            "Vultr": {
                "asn": ["AS20473"],
                "isp": ["vultr", "choopa"],
                "hostname": ["vultr.com", "choopa.net"],
                "ip_ranges": [],
            },
            "Cloudflare": {
                "asn": ["AS13335"],
                "isp": ["cloudflare"],
                "hostname": ["cloudflare.com", "cloudflare.net"],
                "ip_ranges": [],
            },
            "Akamai": {
                "asn": ["AS20940", "AS16625", "AS21342"],
                "isp": ["akamai"],
                "hostname": ["akamai.com", "akamai.net", "akamaitechnologies"],
                "ip_ranges": [],
            },
            "Alibaba Cloud": {
                "asn": ["AS45102", "AS37963"],
                "isp": ["alibaba", "aliyun"],
                "hostname": ["aliyun.com", "alibaba.com"],
                "ip_ranges": [],
            },
            "Oracle Cloud": {
                "asn": ["AS31898", "AS792"],
                "isp": ["oracle", "oracle cloud"],
                "hostname": ["oraclecloud.com", "oracle.com"],
                "ip_ranges": [],
            },
            "IBM Cloud": {
                "asn": ["AS36351"],
                "isp": ["ibm", "softlayer"],
                "hostname": ["ibm.com", "softlayer.com"],
                "ip_ranges": [],
            },
            "Scaleway": {
                "asn": ["AS12876"],
                "isp": ["scaleway", "online s.a.s"],
                "hostname": ["scaleway.com", "scw.cloud"],
                "ip_ranges": [],
            },
        }

        # Get reverse DNS hostname if not provided
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0].lower()
            except:
                hostname = ""

        # Get ISP from geolocation if available
        if not isp_name and hasattr(self, "results") and "geolocation" in self.results:
            isp_name = self.results["geolocation"].get("isp", "")

        isp_lower = isp_name.lower() if isp_name else ""
        hostname_lower = hostname.lower() if hostname else ""

        # Get ASN from geolocation
        asn = None
        if hasattr(self, "results") and "geolocation" in self.results:
            asn = self.results["geolocation"].get("asn", "")

        # Check patterns for each cloud provider
        for provider_name, patterns in cloud_patterns.items():
            match_score = 0

            # Check ASN (highest confidence)
            if asn and any(asn_pattern in str(asn) for asn_pattern in patterns["asn"]):
                match_score += 3

            # Check ISP name
            if isp_name and any(isp_pattern in isp_lower for isp_pattern in patterns["isp"]):
                match_score += 2

            # Check hostname/reverse DNS
            if hostname and any(host_pattern in hostname_lower for host_pattern in patterns["hostname"]):
                match_score += 2

            # Determine provider based on match score
            if match_score >= 3:
                provider = provider_name
                confidence = "high"
                break
            elif match_score >= 2:
                provider = provider_name
                confidence = "medium"
                break
            elif match_score >= 1:
                provider = provider_name
                confidence = "low"

        return provider, confidence, hostname

    def analyze_geolocation(self, ip):
        """
        Analyze geolocation using free public API
        Uses ipapi.co which doesn't require API key for basic usage
        """
        if not ip:
            return None

        print("\n🌍 Analyzing Geolocation and Hosting...")

        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            geo_data = response.json()

            if "error" in geo_data:
                print(f"   └─ API Error: {geo_data.get('reason', 'Unknown')}")
                return None

            geo_info = {
                "ip": ip,
                "country": geo_data.get("country_name"),
                "country_code": geo_data.get("country_code"),
                "city": geo_data.get("city"),
                "region": geo_data.get("region"),
                "latitude": geo_data.get("latitude"),
                "longitude": geo_data.get("longitude"),
                "timezone": geo_data.get("timezone"),
                "isp": geo_data.get("org"),
                "asn": geo_data.get("asn"),
            }

            print(f"   └─ Country: {geo_info['country']} ({geo_info['country_code']})")
            print(f"   └─ City: {geo_info['city']}")
            print(f"   └─ ISP: {geo_info['isp']}")
            if geo_info["asn"]:
                print(f"   └─ ASN: {geo_info['asn']}")

            # Detect cloud provider
            provider, confidence, hostname = self.detect_cloud_provider(ip, isp_name=geo_info["isp"])

            if provider != "Unknown":
                print(f"   └─ Cloud Provider: {provider} (confidence: {confidence})")
                if hostname:
                    print(f"   └─ Hostname: {hostname}")

            geo_info["cloud_provider"] = provider
            geo_info["provider_confidence"] = confidence
            geo_info["hostname"] = hostname

            self.results["geolocation"] = geo_info
            return geo_info

        except Exception as e:
            print(f"   └─ Error: {str(e)}")
            return None

    def whois_lookup(self):
        """
        WHOIS lookup for domain information
        Requires python-whois library (optional)
        """
        print("\n📋 WHOIS Lookup...")

        try:
            import whois

            # Remove www if present for whois lookup
            domain_query = self.domain.replace("www.", "")

            w = whois.whois(domain_query)

            # Handle different response formats
            def safe_get(obj, attr):
                """Safely get attribute from whois object"""
                if hasattr(obj, attr):
                    val = getattr(obj, attr)
                    if val is None:
                        return "N/A"
                    # Handle lists
                    if isinstance(val, list):
                        if len(val) == 0:
                            return "N/A"
                        # Return first non-None value
                        for item in val:
                            if item is not None:
                                return str(item)
                        return "N/A"
                    return str(val)
                return "N/A"

            whois_data = {
                "registrar": safe_get(w, "registrar"),
                "creation_date": safe_get(w, "creation_date"),
                "expiration_date": safe_get(w, "expiration_date"),
                "updated_date": safe_get(w, "updated_date"),
                "name_servers": w.name_servers if hasattr(w, "name_servers") and w.name_servers else [],
                "status": w.status if hasattr(w, "status") and w.status else [],
                "emails": w.emails if hasattr(w, "emails") and w.emails else [],
                "org": safe_get(w, "org"),
                "country": safe_get(w, "country"),
                "registrant": safe_get(w, "name"),
                "city": safe_get(w, "city"),
                "state": safe_get(w, "state"),
            }

            # Clean up date formats
            for date_field in ["creation_date", "expiration_date", "updated_date"]:
                if whois_data[date_field] != "N/A":
                    # Extract just the date part if it's a datetime string
                    date_str = whois_data[date_field]
                    if " " in date_str:
                        whois_data[date_field] = date_str.split(" ")[0]

            print(f"   └─ Registrar: {whois_data['registrar']}")
            print(f"   └─ Created: {whois_data['creation_date']}")
            print(f"   └─ Expires: {whois_data['expiration_date']}")
            if whois_data["org"] != "N/A":
                print(f"   └─ Organization: {whois_data['org']}")
            if whois_data["country"] != "N/A":
                print(f"   └─ Country: {whois_data['country']}")
            if whois_data["name_servers"]:
                ns_display = ", ".join(whois_data["name_servers"][:3])
                if len(whois_data["name_servers"]) > 3:
                    ns_display += f" ... (+{len(whois_data['name_servers']) - 3})"
                print(f"   └─ Name Servers: {ns_display}")

            self.results["whois"] = whois_data
            return whois_data

        except ImportError:
            print("   └─ python-whois not installed (optional)")
            print("   └─ Install with: pip install python-whois")
            return None
        except Exception as e:
            print(f"   └─ Error: {str(e)}")
            # Try alternative method
            self._whois_alternative(self.domain.replace("www.", ""))
            return None

    def _whois_alternative(self, domain):
        """Alternative WHOIS lookup using raw socket connection"""
        print("   └─ Trying alternative WHOIS method...")
        try:
            import socket

            # Determine WHOIS server
            tld = domain.split(".")[-1]
            whois_server = f"whois.nic.{tld}"

            # Try generic WHOIS server if TLD-specific fails
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((whois_server, 43))
            except:
                whois_server = "whois.iana.org"
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((whois_server, 43))

            s.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            whois_text = response.decode("utf-8", errors="ignore")

            # Parse basic information
            registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
            created_match = re.search(r"Creation Date:\s*(.+)", whois_text, re.IGNORECASE)
            expires_match = re.search(r"Expir(?:y|ation) Date:\s*(.+)", whois_text, re.IGNORECASE)

            if registrar_match:
                print(f"   └─ Registrar: {registrar_match.group(1).strip()}")
            if created_match:
                print(f"   └─ Created: {created_match.group(1).strip()}")
            if expires_match:
                print(f"   └─ Expires: {expires_match.group(1).strip()}")

            self.results["whois"] = {
                "registrar": registrar_match.group(1).strip() if registrar_match else "N/A",
                "creation_date": created_match.group(1).strip() if created_match else "N/A",
                "expiration_date": expires_match.group(1).strip() if expires_match else "N/A",
                "raw_response": whois_text[:500],  # Store first 500 chars
            }

        except Exception as e:
            print(f"   └─ Alternative method failed: {str(e)}")

    def analyze(self):
        """Execute complete reconnaissance analysis"""
        print("=" * 80)
        print(f"🃏 RANKLE - Web Infrastructure Reconnaissance")
        print("=" * 80)
        print(f"🎯 Target: {self.domain}")
        print(f"⏰ Timestamp: {self.scan_timestamp}")
        print("=" * 80)

        # Execute all modules
        headers, response = self.analyze_http_headers()

        self.enumerate_subdomains_crtsh()

        dns_records = self.analyze_dns()

        self.analyze_tls_certificate()

        self.detect_technologies(response)

        # Advanced fingerprinting
        self.advanced_fingerprinting(response)

        cnames = dns_records.get("CNAME", [])
        self.detect_cdn_waf(headers, cnames)

        # Get first IP for geolocation
        ips = dns_records.get("A", [])
        if ips:
            self.analyze_geolocation(ips[0])

        # Optional WHOIS
        self.whois_lookup()

        # Try to find origin infrastructure behind WAF/CDN
        # Only run if CDN/WAF detected
        if self.results.get("cdn") != "Not detected" or self.results.get("waf") != "Not detected":
            self.find_origin_infrastructure()

        print("\n" + "=" * 80)
        print("✅ Reconnaissance completed")
        print("=" * 80)

        return self.results

    def print_summary_report(self):
        """Print comprehensive summary report"""
        print(f"\n{'='*80}")
        print("📊 RECONNAISSANCE SUMMARY REPORT")
        print(f"{'='*80}")
        print(f"🎯 Domain: {self.domain}")
        print(f"⏰ Scan Time: {self.scan_timestamp}")
        print(f"{'='*80}\n")

        # Section 1: Basic Information
        print("═" * 80)
        print("🌐 BASIC INFORMATION")
        print("═" * 80)

        if "status_code" in self.results:
            print(f"  Status Code:       {self.results['status_code']}")

        if "dns" in self.results:
            dns = self.results["dns"]
            if dns.get("A"):
                print(f"  IPv4 Address(es):  {', '.join(dns['A'][:3])}")
            if dns.get("AAAA"):
                print(f"  IPv6 Address(es):  {', '.join(dns['AAAA'][:2])}")

        # Section 2: Technologies
        print(f"\n{'═' * 80}")
        print("🔧 TECHNOLOGY STACK")
        print("═" * 80)

        if "technologies_web" in self.results:
            tech = self.results["technologies_web"]
            print(f"  CMS:               {tech.get('cms', 'Unknown')}")

            if tech.get("frameworks"):
                print(f"  JS Frameworks:     {', '.join(tech['frameworks'])}")

            if tech.get("analytics"):
                print(f"  Analytics:         {', '.join(tech['analytics'][:3])}")

            if tech.get("cdn"):
                print(f"  CDN/Libraries:     {', '.join(tech['cdn'][:3])}")

        if "technologies" in self.results:
            print(f"\n  Server Technologies:")
            for tech in self.results["technologies"]:
                print(f"    • {tech}")

        # Section 3: Security
        print(f"\n{'═' * 80}")
        print("🔒 SECURITY ANALYSIS")
        print("═" * 80)

        if "tls" in self.results:
            tls = self.results["tls"]
            issuer = tls.get("issuer", {}).get("organizationName", "N/A")
            print(f"  TLS/SSL:")
            print(f"    • Issuer:        {issuer}")
            print(f"    • Valid Until:   {tls.get('valid_until', 'N/A')}")
            print(f"    • TLS Version:   {tls.get('tls_version', 'N/A')}")

        if "security_headers" in self.results and self.results["security_headers"]:
            print(f"\n  Security Headers:")
            for header, value in self.results["security_headers"].items():
                value_short = value[:60] + "..." if len(value) > 60 else value
                print(f"    • {header}: {value_short}")
        else:
            print(f"\n  ⚠️  Security Headers: Not detected (Potential risk)")

        print(f"\n  CDN/WAF Protection:")
        print(f"    • CDN:           {self.results.get('cdn', 'Not detected')}")
        print(f"    • WAF:           {self.results.get('waf', 'Not detected')}")

        # Section 4: DNS
        print(f"\n{'═' * 80}")
        print("📡 DNS CONFIGURATION")
        print("═" * 80)

        if "dns" in self.results:
            dns = self.results["dns"]

            if dns.get("NS"):
                print(f"  Name Servers:")
                for ns in dns["NS"][:5]:
                    print(f"    • {ns}")

            if dns.get("MX"):
                print(f"\n  Mail Servers:")
                for mx in dns["MX"][:3]:
                    print(f"    • {mx}")

            if dns.get("TXT"):
                print(f"\n  TXT Records: {len(dns['TXT'])} found")

        # Section 5: Subdomains
        if "subdomains" in self.results and self.results["subdomains"]:
            print(f"\n{'═' * 80}")
            print("🔍 SUBDOMAIN ENUMERATION")
            print("═" * 80)
            print(f"  Total Found: {len(self.results['subdomains'])}")
            print(f"\n  Subdomains (first 15):")
            for subdomain in self.results["subdomains"][:15]:
                print(f"    • {subdomain}")
            if len(self.results["subdomains"]) > 15:
                print(f"    ... and {len(self.results['subdomains']) - 15} more")

        # Section 5.5: Advanced Fingerprinting
        if "advanced_fingerprint" in self.results:
            fp = self.results["advanced_fingerprint"]
            if any(
                [
                    fp.get("http_methods"),
                    fp.get("api_endpoints"),
                    fp.get("exposed_files"),
                    fp.get("server_fingerprint"),
                    fp.get("detected_from_cookies"),
                ]
            ):
                print(f"\n{'═' * 80}")
                print("🔬 ADVANCED FINGERPRINTING")
                print("═" * 80)

                if fp.get("server_fingerprint"):
                    print(f"  Server Versions:")
                    for tech, version in fp["server_fingerprint"].items():
                        print(f"    • {tech}: {version}")

                if fp.get("http_methods"):
                    print(f"\n  Allowed HTTP Methods: {', '.join(fp['http_methods'])}")

                if fp.get("api_endpoints"):
                    print(f"\n  Discovered API Endpoints ({len(fp['api_endpoints'])}):")
                    for ep in fp["api_endpoints"][:10]:
                        print(f"    • {ep['endpoint']} [{ep['status']}] - {ep['content_type']}")

                if fp.get("exposed_files"):
                    print(f"\n  ⚠️  Exposed Files ({len(fp['exposed_files'])}):")
                    for file in fp["exposed_files"]:
                        print(f"    • {file}")

                if fp.get("detected_from_cookies"):
                    print(f"\n  Technology from Cookies:")
                    for tech in set(fp["detected_from_cookies"]):
                        print(f"    • {tech}")

                if fp.get("error_page_tech"):
                    print(f"\n  Error Page Analysis:")
                    for tech in fp["error_page_tech"]:
                        print(f"    • {tech}")

                if fp.get("response_time_ms"):
                    print(f"\n  Response Time: {fp['response_time_ms']}ms")

        # Section 6: Geolocation
        if "geolocation" in self.results:
            print(f"\n{'═' * 80}")
            print("🌍 GEOLOCATION & HOSTING")
            print("═" * 80)
            geo = self.results["geolocation"]
            print(f"  Location:          {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
            print(f"  ISP:               {geo.get('isp', 'N/A')}")
            if geo.get("asn"):
                print(f"  ASN:               {geo['asn']}")
            if geo.get("cloud_provider") and geo.get("cloud_provider") != "Unknown":
                print(
                    f"  Cloud Provider:    {geo['cloud_provider']} ({geo.get('provider_confidence', 'unknown')} confidence)"
                )
            if geo.get("hostname"):
                print(f"  Hostname:          {geo['hostname']}")

        # Section 7: WHOIS
        if "whois" in self.results:
            print(f"\n{'═' * 80}")
            print("📋 WHOIS INFORMATION")
            print("═" * 80)
            whois = self.results["whois"]
            print(f"  Registrar:         {whois.get('registrar', 'N/A')}")
            print(f"  Created:           {whois.get('creation_date', 'N/A')}")
            print(f"  Expires:           {whois.get('expiration_date', 'N/A')}")

        # Section 8: Origin Infrastructure (if found)
        if "origin_infrastructure" in self.results and self.results["origin_infrastructure"].get("found"):
            print(f"\n{'═' * 80}")
            print("🎯 ORIGIN INFRASTRUCTURE (Behind WAF/CDN)")
            print("═" * 80)
            origin = self.results["origin_infrastructure"]
            print(f"  Detection Methods: {', '.join(origin.get('methods_used', []))}")
            print(f"  Origin IPs Found:  {len(origin.get('origin_ips', []))}")

            if origin.get("origin_providers"):
                print(f"\n  Origin Hosting:")
                for provider_info in origin["origin_providers"][:5]:
                    print(
                        f"    • {provider_info['ip']} → {provider_info['provider']} ({provider_info['confidence']} confidence)"
                    )

            if origin.get("origin_hostnames"):
                print(f"\n  Direct Access Domains ({len(origin['origin_hostnames'])} found):")
                for hostname in list(origin["origin_hostnames"])[:5]:
                    print(f"    • {hostname}")

        print(f"\n{'═' * 80}")
        print("✅ Report completed")
        print(f"{'═' * 80}\n")

    def save_json(self, filename=None):
        """Save results to JSON file"""
        import os

        if filename is None:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(reports_dir, exist_ok=True)

            filename = os.path.join(reports_dir, f"{self.domain.replace('.', '_')}_rankle.json")

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        print(f"💾 Results saved to: {filename}")
        return filename

    def save_text_report(self, filename=None):
        """Save technical text report without decorations"""
        import io
        import sys
        import os

        if filename is None:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(reports_dir, exist_ok=True)

            filename = os.path.join(reports_dir, f"{self.domain.replace('.', '_')}_rankle_report.txt")

        # Capture the output
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()

        self.print_technical_report()

        report_content = buffer.getvalue()
        sys.stdout = old_stdout

        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"💾 Report saved: {filename}")
        return filename

    def print_technical_report(self):
        """Print technical report - synthetic, no decorations"""
        print(f"DOMAIN: {self.domain}")
        print(f"SCAN_TIME: {self.scan_timestamp}")
        print(f"STATUS: {self.results.get('status_code', 'N/A')}\n")

        # Infrastructure
        print("[INFRASTRUCTURE]")
        if "dns" in self.results:
            dns = self.results["dns"]
            if dns.get("A"):
                print(f"IPv4: {', '.join(dns['A'][:5])}")
            if dns.get("AAAA"):
                print(f"IPv6: {', '.join(dns['AAAA'][:3])}")
            if dns.get("NS"):
                print(f"Nameservers: {', '.join(dns['NS'][:3])}")
            if dns.get("MX"):
                print(f"Mail: {', '.join(dns['MX'][:3])}")

        if "geolocation" in self.results:
            geo = self.results["geolocation"]
            print(f"Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}")
            print(f"ISP: {geo.get('isp', 'N/A')}")
            if geo.get("asn"):
                print(f"ASN: {geo['asn']}")
            if geo.get("cloud_provider") and geo.get("cloud_provider") != "Unknown":
                print(
                    f"Cloud Provider: {geo['cloud_provider']} ({geo.get('provider_confidence', 'unknown')} confidence)"
                )
            if geo.get("hostname"):
                print(f"Hostname: {geo['hostname']}")

        # Technology Stack
        print(f"\n[TECHNOLOGY]")
        if "technologies_web" in self.results:
            tech = self.results["technologies_web"]
            print(f"CMS: {tech.get('cms', 'Unknown')}")
            if tech.get("frameworks"):
                print(f"Frameworks: {', '.join(tech['frameworks'])}")
            if tech.get("analytics"):
                print(f"Analytics: {', '.join(tech['analytics'])}")

        if "headers" in self.results:
            server = self.results["headers"].get("server", "Unknown")
            print(f"Server: {server}")

        # Security
        print(f"\n[SECURITY]")
        if "tls" in self.results:
            tls = self.results["tls"]
            print(f"TLS Version: {tls.get('tls_version', 'N/A')}")
            print(f"Certificate Issuer: {tls.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"Certificate Expiry: {tls.get('valid_until', 'N/A')}")
            print(f"Cipher: {tls.get('cipher_suite', ('N/A',))[0] if tls.get('cipher_suite') else 'N/A'}")
            if tls.get("san_domains"):
                print(f"SANs: {len(tls['san_domains'])} domains")

        if "security_headers" in self.results:
            headers = self.results["security_headers"]
            if headers:
                print("Security Headers:")
                for k, v in headers.items():
                    v_short = v[:80] if len(v) > 80 else v
                    print(f"  {k}: {v_short}")
            else:
                print("Security Headers: NONE")

        print(f"CDN: {self.results.get('cdn', 'None')}")
        print(f"WAF: {self.results.get('waf', 'None')}")

        # Advanced Fingerprint
        if "advanced_fingerprint" in self.results:
            fp = self.results["advanced_fingerprint"]
            print(f"\n[FINGERPRINTING]")
            if fp.get("server_fingerprint"):
                print(f"Server Versions: {', '.join([f'{k}:{v}' for k,v in fp['server_fingerprint'].items()])}")
            if fp.get("http_methods"):
                print(f"HTTP Methods: {', '.join(fp['http_methods'])}")
            if fp.get("api_endpoints"):
                print(f"API Endpoints: {len(fp['api_endpoints'])} found")
                for ep in fp["api_endpoints"][:5]:
                    print(f"  {ep['endpoint']} [{ep['status']}]")
            if fp.get("exposed_files"):
                print(f"Exposed Files: {', '.join(fp['exposed_files'])}")
            if fp.get("response_time_ms"):
                print(f"Response Time: {fp['response_time_ms']}ms")

        # Subdomains
        if "subdomains" in self.results and self.results["subdomains"]:
            print(f"\n[SUBDOMAINS] ({len(self.results['subdomains'])})")
            for sub in self.results["subdomains"][:20]:
                print(f"  {sub}")
            if len(self.results["subdomains"]) > 20:
                print(f"  ... {len(self.results['subdomains']) - 20} more")

        # WHOIS
        if "whois" in self.results:
            print(f"\n[WHOIS]")
            whois = self.results["whois"]
            print(f"Registrar: {whois.get('registrar', 'N/A')}")
            print(f"Created: {whois.get('creation_date', 'N/A')}")
            print(f"Expires: {whois.get('expiration_date', 'N/A')}")
            if whois.get("name_servers"):
                print(f"NS: {', '.join(whois['name_servers'][:3])}")

        # DNS Records (TXT/SPF)
        if "dns" in self.results and self.results["dns"].get("TXT"):
            print(f"\n[DNS_RECORDS]")
            for txt in self.results["dns"]["TXT"][:5]:
                txt_short = txt[:100] if len(txt) > 100 else txt
                print(f"TXT: {txt_short}")

        # Origin Infrastructure
        if "origin_infrastructure" in self.results and self.results["origin_infrastructure"].get("found"):
            print(f"\n[ORIGIN_INFRASTRUCTURE]")
            origin = self.results["origin_infrastructure"]
            print(f"Methods: {', '.join(origin.get('methods_used', []))}")
            print(f"IPs: {', '.join(origin.get('origin_ips', [])[:5])}")
            if origin.get("origin_providers"):
                for provider_info in origin["origin_providers"][:3]:
                    print(
                        f"Provider: {provider_info['ip']} → {provider_info['provider']} ({provider_info['confidence']})"
                    )
            if origin.get("origin_hostnames"):
                print(f"Direct Domains: {', '.join(list(origin['origin_hostnames'])[:3])}")


def print_banner():
    """Print Rankle banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  █████╗ ███╗   ██╗██╗  ██╗██╗     ███████╗                     ║
║   ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██║     ██╔════╝                     ║
║   ██████╔╝███████║██╔██╗ ██║█████╔╝ ██║     █████╗                       ║
║   ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██║     ██╔══╝                       ║
║   ██║  ██║██║  ██║██║ ╚████║██║  ██╗███████╗███████╗                     ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝                     ║
║                                                                           ║
║              Web Infrastructure Reconnaissance Tool                       ║
║          Named after Rankle, Master of Pranks (MTG)                      ║
║                                                                           ║
║                      100% Open Source - No API Keys                      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print_banner()
        print("\n" + "=" * 80)
        print("📖 USAGE")
        print("=" * 80)
        print("\n  python rankle.py <domain> [options]")
        print("\nEXAMPLES:")
        print("  python rankle.py example.com")
        print("  python rankle.py https://example.com")
        print("  python rankle.py subdomain.example.com")
        print("  python rankle.py example.com --json")
        print("  python rankle.py example.com --output both")
        print("\nOPTIONS:")
        print("  --json, -j          Save results as JSON")
        print("  --text, -t          Save results as text report")
        print("  --output, -o TYPE   Save output (json/text/both)")
        print("  --help, -h          Show this help message")
        print("\nREQUIRED DEPENDENCIES:")
        print("  pip install requests dnspython beautifulsoup4")
        print("\nOPTIONAL DEPENDENCIES:")
        print("  pip install python-whois ipwhois builtwith")
        print("\nFEATURES:")
        print("  • DNS enumeration and configuration analysis")
        print("  • Subdomain discovery via Certificate Transparency")
        print("  • Web technology stack detection (CMS, frameworks)")
        print("  • TLS/SSL certificate analysis")
        print("  • HTTP security headers audit")
        print("  • CDN and WAF detection")
        print("  • Geolocation and hosting information")
        print("  • WHOIS lookup")
        print("  • JSON and text report export")
        print("\nNOTE:")
        print("  All reconnaissance is passive and uses public data sources.")
        print("  No active scanning or intrusive techniques are employed.")
        print("=" * 80 + "\n")
        sys.exit(1)

    # Parse arguments
    domain = sys.argv[1]
    auto_save = None

    # Check for flags
    if "--json" in sys.argv or "-j" in sys.argv:
        auto_save = "json"
    elif "--text" in sys.argv or "-t" in sys.argv:
        auto_save = "text"
    elif "--output" in sys.argv or "-o" in sys.argv:
        try:
            idx = sys.argv.index("--output") if "--output" in sys.argv else sys.argv.index("-o")
            if idx + 1 < len(sys.argv):
                auto_save = sys.argv[idx + 1]
        except (ValueError, IndexError):
            pass

    try:
        print_banner()

        # Create Rankle instance and analyze
        rankle = Rankle(domain)
        rankle.analyze()

        # Print summary report
        rankle.print_summary_report()

        # Handle output saving
        if auto_save:
            # Auto-save mode (for Docker/scripts)
            # Check if /output/ directory exists (Docker mode) or use reports/
            import os

            if os.path.exists("/output/"):
                output_dir = "/output/"
            else:
                output_dir = os.path.join(os.getcwd(), "reports")
                os.makedirs(output_dir, exist_ok=True)

            if auto_save in ["json", "both"]:
                json_path = os.path.join(output_dir, domain.replace(".", "_") + "_rankle.json")
                rankle.save_json(json_path)

            if auto_save in ["text", "both"]:
                text_path = os.path.join(output_dir, domain.replace(".", "_") + "_rankle_report.txt")
                rankle.save_text_report(text_path)
        else:
            # Interactive mode
            try:
                print("\n")
                save = input("💾 Save results? (json/text/both/n): ").lower().strip()

                if save in ["json", "both"]:
                    rankle.save_json()

                if save in ["text", "both"]:
                    rankle.save_text_report()
            except EOFError:
                # Non-interactive mode (e.g., Docker without -it or flags)
                print("💾 Running in non-interactive mode")
                print("   Use --json, --text, or --output flag to save results")
                print("   Or run with: docker run --rm -it rankle example.com")

        print("\n🃏 Thank you for using Rankle!")
        print('   "Master of Pranks knows all your secrets..."\n')

    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user\n")
        sys.exit(1)
    except ValueError as e:
        print(f"\n❌ Invalid input: {str(e)}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}\n")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
