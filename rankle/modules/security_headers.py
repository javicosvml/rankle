"""
Security Headers Auditor Module for Rankle

Analyzes HTTP security headers for potential vulnerabilities:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cross-Origin headers (CORS, COEP, COOP)
"""

import re
from typing import Any


# Security headers definitions with best practices
SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "min_max_age": 31536000,  # 1 year
        "checks": ["max_age", "include_subdomains", "preload"],
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "high",
        "recommended": "default-src 'self'; script-src 'self'",
        "dangerous_values": ["'unsafe-inline'", "'unsafe-eval'", "*", "data:"],
        "checks": ["has_default_src", "no_unsafe_inline", "no_unsafe_eval"],
    },
    "X-Frame-Options": {
        "description": "Clickjacking Protection",
        "severity": "medium",
        "recommended": "DENY",
        "valid_values": ["DENY", "SAMEORIGIN"],
        "deprecated_by": "Content-Security-Policy frame-ancestors",
    },
    "X-Content-Type-Options": {
        "description": "MIME-Type Sniffing Prevention",
        "severity": "medium",
        "recommended": "nosniff",
        "valid_values": ["nosniff"],
    },
    "X-XSS-Protection": {
        "description": "XSS Filter (Legacy)",
        "severity": "low",
        "recommended": "0",
        "note": "Deprecated. Modern browsers disable XSS auditor. Use CSP instead.",
        "valid_values": ["0", "1; mode=block"],
    },
    "Referrer-Policy": {
        "description": "Referrer Information Control",
        "severity": "medium",
        "recommended": "strict-origin-when-cross-origin",
        "secure_values": [
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ],
        "insecure_values": ["unsafe-url", "no-referrer-when-downgrade"],
    },
    "Permissions-Policy": {
        "description": "Browser Feature Permissions",
        "severity": "medium",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "sensitive_features": [
            "geolocation",
            "microphone",
            "camera",
            "payment",
            "usb",
            "bluetooth",
        ],
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Cross-Origin Opener Policy (COOP)",
        "severity": "medium",
        "recommended": "same-origin",
        "valid_values": ["same-origin", "same-origin-allow-popups", "unsafe-none"],
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Cross-Origin Embedder Policy (COEP)",
        "severity": "medium",
        "recommended": "require-corp",
        "valid_values": ["require-corp", "credentialless", "unsafe-none"],
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Cross-Origin Resource Policy (CORP)",
        "severity": "medium",
        "recommended": "same-origin",
        "valid_values": ["same-origin", "same-site", "cross-origin"],
    },
    "Cache-Control": {
        "description": "Cache Control Directives",
        "severity": "low",
        "recommended": "no-store, max-age=0",
        "sensitive_check": True,
    },
    "Clear-Site-Data": {
        "description": "Clear Site Data on Logout",
        "severity": "low",
        "recommended": '"cache", "cookies", "storage"',
    },
}

# Headers that leak information
INFO_LEAK_HEADERS: dict[str, dict[str, Any]] = {
    "Server": {
        "description": "Server software disclosure",
        "severity": "low",
        "recommendation": "Remove or set generic value",
    },
    "X-Powered-By": {
        "description": "Framework/technology disclosure",
        "severity": "low",
        "recommendation": "Remove header",
    },
    "X-AspNet-Version": {
        "description": "ASP.NET version disclosure",
        "severity": "medium",
        "recommendation": "Remove header",
    },
    "X-AspNetMvc-Version": {
        "description": "ASP.NET MVC version disclosure",
        "severity": "medium",
        "recommendation": "Remove header",
    },
    "X-Runtime": {
        "description": "Processing time disclosure",
        "severity": "low",
        "recommendation": "Remove header",
    },
    "X-Version": {
        "description": "Application version disclosure",
        "severity": "medium",
        "recommendation": "Remove header",
    },
}


class SecurityHeadersAuditor:
    """
    Audits HTTP security headers for vulnerabilities and misconfigurations.

    Provides detailed analysis and recommendations for improving
    security posture based on industry best practices.
    """

    def __init__(self, domain: str):
        """
        Initialize security headers auditor.

        Args:
            domain: Target domain for context
        """
        self.domain = domain

    def audit(self, headers: dict[str, str] | None = None) -> dict[str, Any]:
        """
        Perform comprehensive security headers audit.

        Args:
            headers: HTTP response headers to audit

        Returns:
            Dictionary with audit results and recommendations
        """
        results: dict[str, Any] = {
            "score": 0,
            "grade": "F",
            "present": [],
            "missing": [],
            "issues": [],
            "info_leaks": [],
            "recommendations": [],
            "details": {},
        }

        if not headers:
            results["issues"].append("No headers provided for analysis")
            return results

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Audit security headers
        total_score = 0
        max_score = 0

        for header_name, config in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            max_score += self._get_header_weight(config["severity"])

            if header_lower in headers_lower:
                value = headers_lower[header_lower]
                analysis = self._analyze_header(header_name, value, config)

                results["present"].append(
                    {
                        "header": header_name,
                        "value": value[:100],
                        "status": analysis["status"],
                        "score": analysis["score"],
                    }
                )

                results["details"][header_name] = analysis
                total_score += analysis["score"]

                if analysis["issues"]:
                    results["issues"].extend(analysis["issues"])
            else:
                results["missing"].append(
                    {
                        "header": header_name,
                        "description": config["description"],
                        "severity": config["severity"],
                        "recommended": config.get("recommended", "N/A"),
                    }
                )

                results["recommendations"].append(
                    {
                        "header": header_name,
                        "action": "Add header",
                        "value": config.get("recommended", "See documentation"),
                        "priority": config["severity"],
                    }
                )

        # Check for information disclosure headers
        for header_name, config in INFO_LEAK_HEADERS.items():
            header_lower = header_name.lower()
            if header_lower in headers_lower:
                value = headers_lower[header_lower]
                results["info_leaks"].append(
                    {
                        "header": header_name,
                        "value": value[:50],
                        "description": config["description"],
                        "severity": config["severity"],
                        "recommendation": config["recommendation"],
                    }
                )

        # Calculate final score
        results["score"] = int((total_score / max_score) * 100) if max_score > 0 else 0
        results["grade"] = self._calculate_grade(results["score"])

        # Add summary
        results["summary"] = {
            "present_count": len(results["present"]),
            "missing_count": len(results["missing"]),
            "issue_count": len(results["issues"]),
            "info_leak_count": len(results["info_leaks"]),
        }

        return results

    def _get_header_weight(self, severity: str) -> int:
        """Get scoring weight based on severity."""
        weights = {"high": 20, "medium": 10, "low": 5}
        return weights.get(severity, 5)

    def _analyze_header(
        self, header_name: str, value: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze a specific security header."""
        analysis: dict[str, Any] = {
            "status": "ok",
            "score": self._get_header_weight(config["severity"]),
            "issues": [],
            "recommendations": [],
        }

        value_lower = value.lower()

        # Header-specific analysis
        if header_name == "Strict-Transport-Security":
            analysis = self._analyze_hsts(value, analysis, config)
        elif header_name == "Content-Security-Policy":
            analysis = self._analyze_csp(value, analysis, config)
        elif header_name == "X-Frame-Options":
            analysis = self._analyze_x_frame_options(value, analysis, config)
        elif header_name == "X-Content-Type-Options":
            analysis = self._analyze_x_content_type_options(value, analysis, config)
        elif header_name == "Referrer-Policy":
            analysis = self._analyze_referrer_policy(value, analysis, config)
        elif header_name == "Permissions-Policy":
            analysis = self._analyze_permissions_policy(value, analysis, config)
        elif "valid_values" in config:
            # Generic validation
            valid = any(v.lower() in value_lower for v in config["valid_values"])
            if not valid:
                analysis["status"] = "warning"
                analysis["score"] = int(analysis["score"] * 0.5)
                analysis["issues"].append(
                    f"{header_name}: Value '{value[:30]}' is not recommended"
                )

        return analysis

    def _analyze_hsts(
        self, value: str, analysis: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze HSTS header."""
        # Check max-age
        max_age_match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            min_age = config.get("min_max_age", 31536000)

            if max_age < 86400:  # Less than 1 day
                analysis["status"] = "error"
                analysis["score"] = 0
                analysis["issues"].append(
                    f"HSTS: max-age too short ({max_age}s). Minimum recommended: 1 year"
                )
            elif max_age < min_age:
                analysis["status"] = "warning"
                analysis["score"] = int(analysis["score"] * 0.7)
                analysis["issues"].append(
                    f"HSTS: max-age ({max_age}s) below recommended ({min_age}s)"
                )
        else:
            analysis["status"] = "error"
            analysis["score"] = 0
            analysis["issues"].append("HSTS: Missing max-age directive")

        # Check includeSubDomains
        if "includesubdomains" not in value.lower():
            analysis["recommendations"].append("Consider adding includeSubDomains")

        # Check preload
        if "preload" not in value.lower():
            analysis["recommendations"].append(
                "Consider adding preload for HSTS preload list"
            )

        return analysis

    def _analyze_csp(
        self, value: str, analysis: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze Content-Security-Policy header."""
        value_lower = value.lower()

        # Check for dangerous values
        dangerous = config.get("dangerous_values", [])
        found_dangerous = [dv for dv in dangerous if dv.lower() in value_lower]

        if "'unsafe-inline'" in value_lower and "'unsafe-eval'" in value_lower:
            analysis["status"] = "error"
            analysis["score"] = int(analysis["score"] * 0.3)
            analysis["issues"].append(
                "CSP: Both 'unsafe-inline' and 'unsafe-eval' present - significantly weakens protection"
            )
        elif found_dangerous:
            analysis["status"] = "warning"
            analysis["score"] = int(analysis["score"] * 0.6)
            analysis["issues"].append(
                f"CSP: Potentially dangerous values: {', '.join(found_dangerous)}"
            )

        # Check for default-src
        if "default-src" not in value_lower:
            analysis["recommendations"].append("Add default-src directive as fallback")

        # Check for report-uri or report-to
        if "report-uri" not in value_lower and "report-to" not in value_lower:
            analysis["recommendations"].append(
                "Consider adding report-uri or report-to for CSP violation reporting"
            )

        return analysis

    def _analyze_x_frame_options(
        self, value: str, analysis: dict[str, Any], _config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze X-Frame-Options header."""
        value_upper = value.upper().strip()

        if value_upper not in ["DENY", "SAMEORIGIN"]:
            if value_upper.startswith("ALLOW-FROM"):
                analysis["status"] = "warning"
                analysis["issues"].append(
                    "X-Frame-Options: ALLOW-FROM is deprecated and not widely supported"
                )
                analysis["score"] = int(analysis["score"] * 0.5)
            else:
                analysis["status"] = "error"
                analysis["score"] = 0
                analysis["issues"].append(
                    f"X-Frame-Options: Invalid value '{value[:30]}'"
                )

        analysis["recommendations"].append(
            "Consider using CSP frame-ancestors instead (more flexible)"
        )

        return analysis

    def _analyze_x_content_type_options(
        self, value: str, analysis: dict[str, Any], _config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze X-Content-Type-Options header."""
        if value.lower().strip() != "nosniff":
            analysis["status"] = "error"
            analysis["score"] = 0
            analysis["issues"].append(
                f"X-Content-Type-Options: Invalid value '{value}'. Should be 'nosniff'"
            )

        return analysis

    def _analyze_referrer_policy(
        self, value: str, analysis: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze Referrer-Policy header."""
        value_lower = value.lower().strip()

        insecure = config.get("insecure_values", [])
        if value_lower in [v.lower() for v in insecure]:
            analysis["status"] = "warning"
            analysis["score"] = int(analysis["score"] * 0.5)
            analysis["issues"].append(
                f"Referrer-Policy: '{value}' may leak sensitive URL information"
            )

        secure = config.get("secure_values", [])
        if value_lower not in [v.lower() for v in secure]:
            analysis["recommendations"].append(
                "Consider using 'strict-origin-when-cross-origin' for better privacy"
            )

        return analysis

    def _analyze_permissions_policy(
        self, value: str, analysis: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze Permissions-Policy header."""
        sensitive = config.get("sensitive_features", [])
        value_lower = value.lower()

        unrestricted = []
        for feature in sensitive:
            # Check if feature allows all origins (=*)
            pattern = rf"{feature}=\*"
            if re.search(pattern, value_lower):
                unrestricted.append(feature)

        if unrestricted:
            analysis["status"] = "warning"
            analysis["score"] = int(analysis["score"] * 0.7)
            analysis["issues"].append(
                f"Permissions-Policy: Sensitive features unrestricted: {', '.join(unrestricted)}"
            )

        # Check for missing sensitive features
        for feature in sensitive:
            if feature not in value_lower:
                analysis["recommendations"].append(
                    f"Consider restricting '{feature}' feature"
                )

        return analysis

    def _calculate_grade(self, score: int) -> str:
        """Calculate security grade from score."""
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def get_missing_headers(self, headers: dict[str, str]) -> list[str]:
        """Get list of missing critical security headers."""
        headers_lower = {k.lower() for k in headers}
        missing = []

        for header_name, config in SECURITY_HEADERS.items():
            if (
                config["severity"] in ["high", "medium"]
                and header_name.lower() not in headers_lower
            ):
                missing.append(header_name)

        return missing


def audit_security_headers(
    domain: str, headers: dict[str, str] | None = None
) -> dict[str, Any]:
    """
    Convenience function for security headers audit.

    Args:
        domain: Target domain
        headers: HTTP response headers

    Returns:
        Security headers audit results
    """
    auditor = SecurityHeadersAuditor(domain)
    return auditor.audit(headers=headers)
