"""
HTTP Fingerprinting Module for Rankle

Performs HTTP-based fingerprinting without HTML analysis:
- HTTP methods detection
- Server behavior analysis
- Error page signatures
- API endpoint discovery
- Exposed files/paths
- HTTP/2 and HTTP/3 support detection
"""

import contextlib
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin

import requests

from config.settings import DEFAULT_TIMEOUT, USER_AGENT


# Concurrency settings for path checking
MAX_PATH_WORKERS = 10


# Common sensitive/interesting paths to check
INTERESTING_PATHS = [
    # Configuration files
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.json",
    "/configuration.php",
    "/parameters.yml",
    # Git/Version control
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.hg/hgrc",
    # Backups
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    # Debug/Development
    "/debug",
    "/debug.log",
    "/error.log",
    "/errors.log",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/adminer.php",
    # API documentation
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/swagger",
    "/api/docs",
    "/graphql",
    "/graphiql",
    "/.well-known/openid-configuration",
    # Admin panels
    "/admin",
    "/administrator",
    "/admin/login",
    "/wp-admin",
    "/wp-login.php",
    "/manager",
    "/phpmyadmin",
    "/pma",
    "/adminer",
    "/console",
    "/dashboard",
    "/panel",
    # Status/Health endpoints
    "/status",
    "/health",
    "/healthz",
    "/ready",
    "/readiness",
    "/liveness",
    "/ping",
    "/metrics",
    "/prometheus",
    "/.well-known/security.txt",
    "/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    # Common framework paths
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    # Package managers
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/requirements.txt",
    "/Pipfile",
    "/yarn.lock",
    "/package-lock.json",
    # Cloud/Container
    "/.aws/credentials",
    "/.docker/config.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/kubernetes.yml",
    "/.kube/config",
]

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

# Common error signatures for server identification
ERROR_SIGNATURES: dict[str, list[str]] = {
    "Apache": [
        r"Apache/[\d.]+",
        r"apache_pb\.gif",
        r"Apache Server at",
    ],
    "nginx": [
        r"nginx/[\d.]+",
        r"nginx",
        r"Welcome to nginx",
    ],
    "IIS": [
        r"Microsoft-IIS/[\d.]+",
        r"ASP\.NET",
        r"X-AspNet-Version",
    ],
    "LiteSpeed": [
        r"LiteSpeed",
        r"litespeed",
    ],
    "Tomcat": [
        r"Apache Tomcat",
        r"Coyote",
        r"tomcat",
    ],
    "Jetty": [
        r"Jetty",
        r"jetty",
    ],
    "Express": [
        r"X-Powered-By: Express",
        r"Cannot GET",
        r"Cannot POST",
    ],
    "Django": [
        r"Django",
        r"CSRF verification failed",
        r"csrfmiddlewaretoken",
    ],
    "Laravel": [
        r"laravel_session",
        r"Laravel",
        r"XSRF-TOKEN",
    ],
    "Rails": [
        r"X-Runtime",
        r"X-Request-Id",
        r"Ruby on Rails",
    ],
    "Spring": [
        r"Whitelabel Error Page",
        r"Spring Boot",
        r"timestamp.*status.*error",
    ],
    "Flask": [
        r"Werkzeug",
        r"Flask",
    ],
    "FastAPI": [
        r'"detail":',
        r"FastAPI",
        r"/openapi\.json",
    ],
}


class HTTPFingerprinter:
    """
    Performs HTTP-based fingerprinting.

    Analyzes server behavior, exposed paths, and error signatures
    without relying on HTML content analysis.
    """

    def __init__(self, domain: str, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize HTTP fingerprinter.

        Args:
            domain: Target domain to fingerprint
            timeout: Request timeout in seconds
        """
        self.domain = domain
        self.timeout = timeout
        self.base_url = f"https://{domain}"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            }
        )

    def fingerprint(self) -> dict[str, Any]:
        """
        Perform comprehensive HTTP fingerprinting.

        Returns:
            Dictionary with fingerprinting results
        """
        results: dict[str, Any] = {
            "server": None,
            "http_version": None,
            "allowed_methods": [],
            "security_headers": {},
            "exposed_paths": [],
            "interesting_headers": {},
            "server_signatures": [],
            "api_endpoints": [],
            "redirects": None,
            "cookies": [],
            "http2_support": False,
            "hsts": False,
        }

        # Basic HTTP response analysis
        basic_info = self._analyze_basic_response()
        results.update(basic_info)

        # Allowed HTTP methods
        results["allowed_methods"] = self._detect_allowed_methods()

        # Check for exposed paths
        results["exposed_paths"] = self._check_exposed_paths()

        # Server signature detection
        results["server_signatures"] = self._detect_server_signatures()

        # API endpoint discovery
        results["api_endpoints"] = self._discover_api_endpoints()

        # HTTP/2 support check
        results["http2_support"] = self._check_http2_support()

        return results

    def _analyze_basic_response(self) -> dict[str, Any]:
        """Analyze basic HTTP response characteristics."""
        result: dict[str, Any] = {
            "server": None,
            "http_version": None,
            "security_headers": {},
            "interesting_headers": {},
            "redirects": None,
            "cookies": [],
            "hsts": False,
        }

        try:
            response = self.session.get(
                self.base_url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            # Server header
            result["server"] = response.headers.get("Server")

            # HTTP version
            if hasattr(response.raw, "version"):
                version = response.raw.version
                result["http_version"] = f"HTTP/{version // 10}.{version % 10}"

            # Security headers
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            for header in security_headers:
                if header in response.headers:
                    result["security_headers"][header] = response.headers[header][:100]

            # HSTS
            if "Strict-Transport-Security" in response.headers:
                result["hsts"] = True

            # Interesting headers
            interesting = [
                "X-Powered-By",
                "X-Generator",
                "X-AspNet-Version",
                "X-AspNetMvc-Version",
                "X-Runtime",
                "X-Request-Id",
                "X-Amzn-RequestId",
                "X-Cache",
                "X-Cache-Hits",
                "Via",
                "Age",
                "ETag",
                "Vary",
            ]
            for header in interesting:
                if header in response.headers:
                    result["interesting_headers"][header] = response.headers[header][
                        :100
                    ]

            # Redirects
            if response.history:
                result["redirects"] = {
                    "count": len(response.history),
                    "chain": [r.url for r in response.history[:5]],
                    "final_url": response.url,
                }

            # Cookies
            for cookie in response.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite"),
                }
                result["cookies"].append(cookie_info)

        except requests.RequestException:
            pass

        return result

    def _detect_allowed_methods(self) -> list[str]:
        """Detect allowed HTTP methods using OPTIONS request."""
        allowed = []

        try:
            # Try OPTIONS request
            response = self.session.options(self.base_url, timeout=self.timeout)
            allow_header = response.headers.get("Allow", "")
            if allow_header:
                allowed = [m.strip().upper() for m in allow_header.split(",")]
                return sorted(set(allowed))

            # Fall back to testing each method
            for method in HTTP_METHODS:
                with contextlib.suppress(requests.RequestException):
                    response = self.session.request(
                        method,
                        self.base_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                    if response.status_code not in [405, 501]:
                        allowed.append(method)

        except requests.RequestException:
            pass

        return sorted(set(allowed))

    def _check_exposed_paths(self, max_checks: int = 30) -> list[dict[str, Any]]:
        """Check for exposed sensitive paths using concurrent requests."""
        exposed: list[dict[str, Any]] = []
        paths_to_check = INTERESTING_PATHS[:max_checks]

        def check_single_path(path: str) -> dict[str, Any] | None:
            """Check a single path and return result if exposed."""
            try:
                url = urljoin(self.base_url, path)
                response = self.session.head(
                    url,
                    timeout=5,
                    allow_redirects=False,
                )

                if response.status_code == 200:
                    # Verify with GET for important paths
                    if any(
                        p in path for p in [".git", ".env", "config", "backup", ".sql"]
                    ):
                        get_response = self.session.get(
                            url,
                            timeout=5,
                            allow_redirects=False,
                        )
                        if get_response.status_code != 200:
                            return None

                    return {
                        "path": path,
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type", "unknown"),
                        "content_length": response.headers.get("Content-Length"),
                    }
                if response.status_code in [301, 302, 303, 307, 308]:
                    # Redirect might still be interesting
                    location = response.headers.get("Location", "")
                    if "login" not in location.lower():
                        return {
                            "path": path,
                            "status": response.status_code,
                            "redirect_to": location[:100],
                        }
            except requests.RequestException:
                pass
            return None

        # Use ThreadPoolExecutor for concurrent path checking
        with ThreadPoolExecutor(max_workers=MAX_PATH_WORKERS) as executor:
            futures = {
                executor.submit(check_single_path, path): path
                for path in paths_to_check
            }

            for future in as_completed(futures):
                with contextlib.suppress(Exception):
                    result = future.result()
                    if result:
                        exposed.append(result)

        return exposed

    def _detect_server_signatures(self) -> list[str]:
        """Detect server software from error pages and responses."""
        signatures = set()

        # Test non-existent path for error page
        test_paths = [
            "/this-path-should-not-exist-12345",
            "/",
            "/.htaccess",
        ]

        for path in test_paths:
            with contextlib.suppress(requests.RequestException):
                response = self.session.get(
                    urljoin(self.base_url, path),
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                # Check headers
                server = response.headers.get("Server", "")
                powered_by = response.headers.get("X-Powered-By", "")

                # Check against signatures
                check_text = f"{server} {powered_by} {response.text[:5000]}"

                for sig_name, patterns in ERROR_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, check_text, re.IGNORECASE):
                            signatures.add(sig_name)
                            break

        return sorted(signatures)

    def _discover_api_endpoints(self) -> list[dict[str, Any]]:
        """Discover common API endpoints."""
        endpoints = []

        api_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/v1",
            "/v2",
            "/rest",
            "/graphql",
            "/api/graphql",
            "/.well-known/openid-configuration",
            "/api/swagger.json",
            "/api/openapi.json",
            "/swagger.json",
            "/openapi.json",
        ]

        for path in api_paths:
            with contextlib.suppress(requests.RequestException):
                url = urljoin(self.base_url, path)
                response = self.session.get(
                    url,
                    timeout=5,
                    allow_redirects=False,
                )

                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    endpoints.append(
                        {
                            "path": path,
                            "status": response.status_code,
                            "content_type": content_type[:50],
                            "is_json": "json" in content_type.lower(),
                        }
                    )
                elif response.status_code in [401, 403]:
                    # Protected endpoint exists
                    endpoints.append(
                        {
                            "path": path,
                            "status": response.status_code,
                            "protected": True,
                        }
                    )

        return endpoints

    def _check_http2_support(self) -> bool:
        """Check if server supports HTTP/2."""
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2", "http/1.1"])

            with socket.create_connection(
                (self.domain, 443), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    protocol = ssock.selected_alpn_protocol()
                    return protocol == "h2"

        except Exception:  # noqa: S110
            pass

        return False

    def close(self):
        """Close the session."""
        self.session.close()


def fingerprint_http(domain: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Convenience function for HTTP fingerprinting.

    Args:
        domain: Target domain
        timeout: Request timeout

    Returns:
        HTTP fingerprinting results
    """
    fingerprinter = HTTPFingerprinter(domain, timeout=timeout)
    try:
        return fingerprinter.fingerprint()
    finally:
        fingerprinter.close()
