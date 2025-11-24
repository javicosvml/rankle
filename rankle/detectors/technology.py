"""
Technology Detection Module for Rankle

Detects web technologies through multiple passive techniques:
- HTML content pattern matching
- HTTP Headers analysis
- Cookie analysis
- Meta tags parsing
- JavaScript global detection
- Version extraction
"""

import json
import re
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup


# Load signatures from config file
def _load_signatures() -> dict[str, Any]:
    """Load technology signatures from JSON config."""
    config_path = (
        Path(__file__).parent.parent.parent / "config" / "tech_signatures.json"
    )
    try:
        with config_path.open(encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
            technologies: dict[str, Any] = data.get("technologies", {})
            return technologies
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


TECH_SIGNATURES = _load_signatures()

# Additional runtime signatures (extend JSON config)
ADDITIONAL_SIGNATURES: dict[str, dict[str, Any]] = {
    "Django": {
        "category": "Web Framework",
        "patterns": {
            "html": ["csrfmiddlewaretoken", "django"],
            "headers": {"X-Frame-Options": ["SAMEORIGIN"]},
            "cookies": ["csrftoken", "sessionid"],
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.3, "cookie": 0.5, "pattern": 0.3},
    },
    "Laravel": {
        "category": "Web Framework",
        "patterns": {
            "html": ["laravel", "csrf-token"],
            "headers": {},
            "cookies": ["laravel_session", "XSRF-TOKEN"],
        },
        "version_patterns": [],
        "confidence_weights": {"cookie": 0.6, "pattern": 0.3},
    },
    "Ruby on Rails": {
        "category": "Web Framework",
        "patterns": {
            "html": ["rails", "csrf-token", "authenticity_token"],
            "headers": {"X-Runtime": [""], "X-Request-Id": [""]},
            "cookies": ["_session_id"],
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.4, "cookie": 0.5, "pattern": 0.3},
    },
    "Express": {
        "category": "Web Framework",
        "patterns": {
            "headers": {"X-Powered-By": ["Express"]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.7},
    },
    "Flask": {
        "category": "Web Framework",
        "patterns": {
            "cookies": ["session"],
            "headers": {"Server": ["Werkzeug"]},
        },
        "version_patterns": ["Werkzeug/([\\d.]+)"],
        "confidence_weights": {"header": 0.5, "cookie": 0.3},
    },
    "FastAPI": {
        "category": "Web Framework",
        "patterns": {
            "html": ["/openapi.json", "/docs", "/redoc"],
            "headers": {},
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "ASP.NET": {
        "category": "Web Framework",
        "patterns": {
            "html": ["__VIEWSTATE", "__EVENTVALIDATION", "aspnetForm"],
            "headers": {"X-AspNet-Version": [""], "X-Powered-By": ["ASP.NET"]},
            "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        },
        "version_patterns": ["X-AspNet-Version: ([\\d.]+)"],
        "confidence_weights": {"header": 0.6, "cookie": 0.5, "pattern": 0.4},
    },
    "Spring": {
        "category": "Web Framework",
        "patterns": {
            "headers": {"X-Application-Context": [""]},
            "cookies": ["JSESSIONID"],
            "html": ["spring", "org.springframework"],
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.5, "cookie": 0.3, "pattern": 0.3},
    },
    "Svelte": {
        "category": "JavaScript Framework",
        "patterns": {
            "html": ["svelte", "__svelte"],
            "js_globals": ["__svelte"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.4, "js_global": 0.6},
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "patterns": {
            "html": [
                r"class=\"[^\"]*(?:flex|grid|w-|h-|p-|m-|text-|bg-|border-|rounded-)[^\"]*\"",
                "tailwindcss",
                "tailwind",
            ],
        },
        "version_patterns": ["tailwindcss@([\\d.]+)"],
        "confidence_weights": {"pattern": 0.5},
    },
    "WooCommerce": {
        "category": "E-commerce",
        "patterns": {
            "html": ["woocommerce", "wc-", "/wc-api/"],
            "cookies": ["woocommerce_"],
            "js_globals": ["wc_add_to_cart_params"],
        },
        "version_patterns": ["WooCommerce ([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "cookie": 0.4, "js_global": 0.5},
    },
    "PrestaShop": {
        "category": "E-commerce",
        "patterns": {
            "html": ["prestashop", "presta"],
            "cookies": ["PrestaShop-"],
            "meta": ["PrestaShop"],
        },
        "version_patterns": ["PrestaShop ([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "cookie": 0.5, "meta": 0.5},
    },
    "Squarespace": {
        "category": "CMS",
        "patterns": {
            "html": ["squarespace", "static.squarespace.com"],
            "headers": {"X-ServedBy": ["squarespace"]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.6, "pattern": 0.5},
    },
    "Wix": {
        "category": "CMS",
        "patterns": {
            "html": ["wix.com", "static.wixstatic.com", "_wix_browser_sess"],
            "cookies": ["wixSession"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "cookie": 0.5},
    },
    "Ghost": {
        "category": "CMS",
        "patterns": {
            "html": ["ghost", "ghost-"],
            "headers": {"X-Ghost-": [""]},
            "meta": ["Ghost"],
        },
        "version_patterns": ["Ghost ([\\d.]+)"],
        "confidence_weights": {"header": 0.5, "pattern": 0.4, "meta": 0.5},
    },
    "Contentful": {
        "category": "Headless CMS",
        "patterns": {
            "html": ["contentful", "ctfassets.net"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "Strapi": {
        "category": "Headless CMS",
        "patterns": {
            "html": ["/api/", "strapi"],
            "headers": {"X-Powered-By": ["Strapi"]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.6, "pattern": 0.3},
    },
    "Google Tag Manager": {
        "category": "Tag Manager",
        "patterns": {
            "html": [
                "googletagmanager.com/gtm.js",
                "GTM-",
                "gtm.start",
            ],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.7},
    },
    "Hotjar": {
        "category": "Analytics",
        "patterns": {
            "html": ["hotjar", "static.hotjar.com", "hj.q"],
            "cookies": ["_hj"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "cookie": 0.5},
    },
    "Segment": {
        "category": "Analytics",
        "patterns": {
            "html": ["segment.com/analytics.js", "analytics.load"],
            "js_globals": ["analytics"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.4},
    },
    "Mixpanel": {
        "category": "Analytics",
        "patterns": {
            "html": ["mixpanel", "cdn.mxpnl.com"],
            "cookies": ["mp_"],
            "js_globals": ["mixpanel"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "cookie": 0.4, "js_global": 0.5},
    },
    "Intercom": {
        "category": "Customer Support",
        "patterns": {
            "html": ["intercom", "widget.intercom.io", "intercomSettings"],
            "cookies": ["intercom-"],
            "js_globals": ["Intercom"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "cookie": 0.4, "js_global": 0.6},
    },
    "Zendesk": {
        "category": "Customer Support",
        "patterns": {
            "html": ["zendesk", "static.zdassets.com", "zdcdn.net"],
            "js_globals": ["zE", "zESettings"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.5},
    },
    "Drift": {
        "category": "Customer Support",
        "patterns": {
            "html": ["drift", "js.driftt.com"],
            "js_globals": ["drift", "driftt"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.5},
    },
    "Crisp": {
        "category": "Customer Support",
        "patterns": {
            "html": ["crisp.chat", "client.crisp.chat"],
            "js_globals": ["$crisp", "CRISP_WEBSITE_ID"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.6},
    },
    "Mailchimp": {
        "category": "Marketing",
        "patterns": {
            "html": ["mailchimp", "list-manage.com", "chimpstatic.com"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6},
    },
    "HubSpot": {
        "category": "Marketing",
        "patterns": {
            "html": ["hubspot", "hs-scripts.com", "hs-analytics.net"],
            "cookies": ["hubspotutk", "__hstc", "__hssc"],
            "js_globals": ["_hsq", "HubSpotConversations"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "cookie": 0.5, "js_global": 0.5},
    },
    "reCAPTCHA": {
        "category": "Security",
        "patterns": {
            "html": ["google.com/recaptcha", "grecaptcha", "g-recaptcha"],
            "js_globals": ["grecaptcha"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "js_global": 0.6},
    },
    "hCaptcha": {
        "category": "Security",
        "patterns": {
            "html": ["hcaptcha.com", "h-captcha"],
            "js_globals": ["hcaptcha"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "js_global": 0.6},
    },
    "Cloudflare Turnstile": {
        "category": "Security",
        "patterns": {
            "html": ["challenges.cloudflare.com/turnstile", "cf-turnstile"],
            "js_globals": ["turnstile"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "js_global": 0.6},
    },
    "Varnish": {
        "category": "Cache",
        "patterns": {
            "headers": {"Via": ["varnish"], "X-Varnish": [""]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.7},
    },
    "Redis": {
        "category": "Cache",
        "patterns": {
            "headers": {"X-Cache-Engine": ["Redis"]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.6},
    },
    "OpenResty": {
        "category": "Web Server",
        "patterns": {
            "headers": {"Server": ["openresty"]},
        },
        "version_patterns": ["openresty/([\\d.]+)"],
        "confidence_weights": {"header": 0.8},
    },
    "LiteSpeed": {
        "category": "Web Server",
        "patterns": {
            "headers": {"Server": ["LiteSpeed"]},
        },
        "version_patterns": ["LiteSpeed/([\\d.]+)"],
        "confidence_weights": {"header": 0.8},
    },
    "IIS": {
        "category": "Web Server",
        "patterns": {
            "headers": {"Server": ["Microsoft-IIS"], "X-Powered-By": ["ASP.NET"]},
        },
        "version_patterns": ["Microsoft-IIS/([\\d.]+)"],
        "confidence_weights": {"header": 0.8},
    },
    "Envoy": {
        "category": "Proxy",
        "patterns": {
            "headers": {"Server": ["envoy"], "X-Envoy-": [""]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.7},
    },
    "Traefik": {
        "category": "Proxy",
        "patterns": {
            "headers": {"Server": ["Traefik"]},
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.7},
    },
    "HAProxy": {
        "category": "Load Balancer",
        "patterns": {
            "headers": {"Server": ["HAProxy"]},
            "cookies": ["SERVERID"],
        },
        "version_patterns": [],
        "confidence_weights": {"header": 0.7, "cookie": 0.4},
    },
    "Sentry": {
        "category": "Error Tracking",
        "patterns": {
            "html": ["sentry", "browser.sentry-cdn.com", "Sentry.init"],
            "js_globals": ["Sentry"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.6},
    },
    "New Relic": {
        "category": "APM",
        "patterns": {
            "html": ["newrelic", "js-agent.newrelic.com", "NREUM"],
            "js_globals": ["NREUM", "newrelic"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.6},
    },
    "Datadog": {
        "category": "APM",
        "patterns": {
            "html": ["datadoghq", "datadog"],
            "js_globals": ["DD_RUM", "DD_LOGS"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.6},
    },
    "Stripe": {
        "category": "Payment",
        "patterns": {
            "html": ["stripe", "js.stripe.com"],
            "js_globals": ["Stripe"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "js_global": 0.7},
    },
    "PayPal": {
        "category": "Payment",
        "patterns": {
            "html": ["paypal", "paypalobjects.com"],
            "js_globals": ["paypal"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.6, "js_global": 0.6},
    },
    "Braintree": {
        "category": "Payment",
        "patterns": {
            "html": ["braintree", "js.braintreegateway.com"],
            "js_globals": ["braintree"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5, "js_global": 0.6},
    },
    "Lodash": {
        "category": "JavaScript Library",
        "patterns": {
            "html": ["lodash"],
            "js_globals": ["_"],
        },
        "version_patterns": ["lodash[.-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.3, "js_global": 0.3},
    },
    "Axios": {
        "category": "JavaScript Library",
        "patterns": {
            "html": ["axios"],
        },
        "version_patterns": ["axios@([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4},
    },
    "D3.js": {
        "category": "JavaScript Library",
        "patterns": {
            "html": ["d3.js", "d3.min.js"],
            "js_globals": ["d3"],
        },
        "version_patterns": ["d3[.-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "js_global": 0.5},
    },
    "Three.js": {
        "category": "JavaScript Library",
        "patterns": {
            "html": ["three.js", "three.min.js"],
            "js_globals": ["THREE"],
        },
        "version_patterns": ["three[.-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "js_global": 0.5},
    },
    "GSAP": {
        "category": "Animation",
        "patterns": {
            "html": ["gsap", "greensock"],
            "js_globals": ["gsap", "TweenMax", "TweenLite"],
        },
        "version_patterns": ["gsap@([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "js_global": 0.5},
    },
    "AOS": {
        "category": "Animation",
        "patterns": {
            "html": ["aos.js", "data-aos="],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "Font Awesome": {
        "category": "Icons",
        "patterns": {
            "html": ["font-awesome", "fontawesome", "fa-"],
        },
        "version_patterns": ["font-awesome[/-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.5},
    },
    "Material Icons": {
        "category": "Icons",
        "patterns": {
            "html": ["material-icons", "fonts.googleapis.com/icon"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "ZURB Foundation": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["foundation", "Foundation."],
            "js_globals": ["Foundation"],
        },
        "version_patterns": ["foundation[.-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4, "js_global": 0.5},
    },
    "Bulma": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["bulma", "is-", "has-text-"],
        },
        "version_patterns": ["bulma[/-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.4},
    },
    "Semantic UI": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["semantic-ui", "semantic.min"],
        },
        "version_patterns": ["semantic[.-]([\\d.]+)"],
        "confidence_weights": {"pattern": 0.5},
    },
    "Material UI": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["@mui", "@material-ui", "MuiButton"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "Chakra UI": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["@chakra-ui", "chakra-"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
    "Ant Design": {
        "category": "CSS Framework",
        "patterns": {
            "html": ["antd", "ant-"],
        },
        "version_patterns": [],
        "confidence_weights": {"pattern": 0.5},
    },
}


class TechnologyDetector:
    """
    Detects web technologies using multiple passive techniques.

    Combines HTML analysis, header inspection, cookie analysis,
    and pattern matching to identify technologies with confidence scores.
    """

    def __init__(self, domain: str):
        """
        Initialize technology detector.

        Args:
            domain: Target domain to analyze
        """
        self.domain = domain
        # Merge signatures from JSON and additional
        self.signatures = {**TECH_SIGNATURES, **ADDITIONAL_SIGNATURES}

    def detect(
        self,
        headers: dict[str, str] | None = None,
        cookies: list[str] | None = None,
        body: str | None = None,
    ) -> dict[str, Any]:
        """
        Perform comprehensive technology detection.

        Args:
            headers: HTTP response headers
            cookies: List of cookie names
            body: HTML response body

        Returns:
            Dictionary with detection results
        """
        results: dict[str, Any] = {
            "detected": False,
            "technologies": [],
            "categories": {},
        }

        if not any([headers, cookies, body]):
            return results

        all_detections: list[dict[str, Any]] = []

        for tech_name, signatures in self.signatures.items():
            evidence: list[dict[str, Any]] = []

            # Check headers
            if headers:
                header_matches = self._check_headers(headers, signatures)
                evidence.extend(header_matches)

            # Check cookies
            if cookies:
                cookie_matches = self._check_cookies(cookies, signatures)
                evidence.extend(cookie_matches)

            # Check HTML body
            if body:
                html_matches = self._check_html(body, signatures)
                evidence.extend(html_matches)

                # Check meta tags
                meta_matches = self._check_meta_tags(body, signatures)
                evidence.extend(meta_matches)

                # Extract version
                version = self._extract_version(body, headers or {}, signatures)
            else:
                version = None

            if evidence:
                confidence = self._calculate_confidence(evidence, signatures)
                if confidence >= 0.2:  # Minimum threshold
                    detection = {
                        "name": tech_name,
                        "category": signatures.get("category", "Unknown"),
                        "confidence": round(confidence, 2),
                        "version": version,
                        "evidence": evidence,
                    }
                    all_detections.append(detection)

        # Sort by confidence
        all_detections.sort(key=lambda x: x["confidence"], reverse=True)

        if all_detections:
            results["detected"] = True
            results["technologies"] = all_detections

            # Group by category
            for tech in all_detections:
                category = tech["category"]
                if category not in results["categories"]:
                    results["categories"][category] = []
                results["categories"][category].append(
                    {
                        "name": tech["name"],
                        "confidence": tech["confidence"],
                        "version": tech["version"],
                    }
                )

        return results

    def _check_headers(
        self, headers: dict[str, str], signatures: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check HTTP headers for technology signatures."""
        matches = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        patterns = signatures.get("patterns", {}).get("headers", {})

        for header_pattern, value_patterns in patterns.items():
            header_pattern_lower = header_pattern.lower()

            for header_name, header_value in headers_lower.items():
                # Check for prefix match (e.g., "X-Powered-By")
                if header_pattern_lower.endswith("-"):
                    if header_name.startswith(header_pattern_lower):
                        matches.append(
                            {
                                "type": "header",
                                "detail": f"{header_name} header present",
                                "weight": signatures.get("confidence_weights", {}).get(
                                    "header", 0.4
                                ),
                            }
                        )
                elif header_name == header_pattern_lower:
                    for pattern in value_patterns:
                        if not pattern:  # Empty = just check existence
                            matches.append(
                                {
                                    "type": "header",
                                    "detail": f"{header_name} header present",
                                    "weight": signatures.get(
                                        "confidence_weights", {}
                                    ).get("header", 0.4),
                                }
                            )
                            break
                        if re.search(pattern, header_value, re.IGNORECASE):
                            matches.append(
                                {
                                    "type": "header",
                                    "detail": f"{header_name}: {header_value[:50]}",
                                    "weight": signatures.get(
                                        "confidence_weights", {}
                                    ).get("header", 0.4),
                                }
                            )
                            break

        return matches

    def _check_cookies(
        self, cookies: list[str], signatures: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check cookies for technology signatures."""
        matches = []
        patterns = signatures.get("patterns", {}).get("cookies", [])

        for pattern in patterns:
            for cookie_name in cookies:
                if re.search(pattern, cookie_name, re.IGNORECASE):
                    matches.append(
                        {
                            "type": "cookie",
                            "detail": f"Cookie: {cookie_name}",
                            "weight": signatures.get("confidence_weights", {}).get(
                                "cookie", 0.3
                            ),
                        }
                    )
                    break  # One match per pattern is enough

        return matches

    def _check_html(
        self, body: str, signatures: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check HTML body for technology patterns."""
        matches = []
        patterns = signatures.get("patterns", {}).get("html", [])

        body_lower = body.lower()

        for pattern in patterns:
            try:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    # Truncate pattern for display
                    display_pattern = (
                        pattern[:30] + "..." if len(pattern) > 30 else pattern
                    )
                    matches.append(
                        {
                            "type": "html_pattern",
                            "detail": f"Pattern: {display_pattern}",
                            "weight": signatures.get("confidence_weights", {}).get(
                                "pattern", 0.3
                            ),
                        }
                    )
            except re.error:
                # Invalid regex, try as literal string
                if pattern.lower() in body_lower:
                    matches.append(
                        {
                            "type": "html_pattern",
                            "detail": f"Pattern: {pattern[:30]}",
                            "weight": signatures.get("confidence_weights", {}).get(
                                "pattern", 0.3
                            ),
                        }
                    )

        # Check JavaScript globals in scripts
        js_globals = signatures.get("patterns", {}).get("js_globals", [])
        for js_global in js_globals:
            # Look for assignments or references
            js_patterns = [
                rf"window\.{js_global}\s*=",
                rf"typeof\s+{js_global}",
                rf'"{js_global}"',
                rf"'{js_global}'",
                rf"\b{js_global}\b",
            ]
            for js_pattern in js_patterns:
                if re.search(js_pattern, body, re.IGNORECASE):
                    matches.append(
                        {
                            "type": "js_global",
                            "detail": f"JS Global: {js_global}",
                            "weight": signatures.get("confidence_weights", {}).get(
                                "js_global", 0.4
                            ),
                        }
                    )
                    break

        return matches

    def _check_meta_tags(
        self, body: str, signatures: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Check meta tags for technology signatures."""
        matches: list[dict[str, Any]] = []
        meta_patterns = signatures.get("patterns", {}).get("meta", [])

        if not meta_patterns:
            return matches

        try:
            soup = BeautifulSoup(body, "html.parser")

            # Check generator meta tag
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and hasattr(generator, "get"):
                content = generator.get("content", "")
                for pattern in meta_patterns:
                    if re.search(pattern, str(content), re.IGNORECASE):
                        matches.append(
                            {
                                "type": "meta_tag",
                                "detail": f"Generator: {content[:50]}",
                                "weight": signatures.get("confidence_weights", {}).get(
                                    "meta", 0.4
                                ),
                            }
                        )
                        break

            # Check all meta tags
            for meta in soup.find_all("meta"):
                content = meta.get("content", "")
                for pattern in meta_patterns:
                    if re.search(pattern, str(content), re.IGNORECASE):
                        matches.append(
                            {
                                "type": "meta_tag",
                                "detail": f"Meta content: {str(content)[:50]}",
                                "weight": signatures.get("confidence_weights", {}).get(
                                    "meta", 0.4
                                ),
                            }
                        )
                        break

        except Exception:  # noqa: S110
            pass

        return matches

    def _extract_version(
        self, body: str, headers: dict[str, str], signatures: dict[str, Any]
    ) -> str | None:
        """Extract version information from response."""
        version_patterns = signatures.get("version_patterns", [])

        # Check in body
        for pattern in version_patterns:
            try:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1)
            except (re.error, IndexError):
                continue

        # Check in headers
        for header_value in headers.values():
            for pattern in version_patterns:
                try:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        return match.group(1)
                except (re.error, IndexError):
                    continue

        return None

    def _calculate_confidence(
        self, evidence: list[dict[str, Any]], _signatures: dict[str, Any]
    ) -> float:
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
            weights.sort(reverse=True)
            type_score = weights[0]
            for i, w in enumerate(weights[1:], 1):
                type_score += w * (0.5**i)  # Diminishing returns
            total_score += type_score

        # Cap at 1.0
        return min(1.0, total_score)


def detect_technologies(
    domain: str,
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    """
    Convenience function for technology detection.

    Args:
        domain: Target domain
        headers: HTTP response headers
        cookies: List of cookie names
        body: HTML response body

    Returns:
        Technology detection results
    """
    detector = TechnologyDetector(domain)
    return detector.detect(headers=headers, cookies=cookies, body=body)
