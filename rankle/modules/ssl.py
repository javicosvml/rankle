"""
SSL/TLS Certificate Analyzer Module for Rankle

Analyzes TLS certificates through passive techniques:
- Certificate chain extraction
- Subject and issuer analysis
- SAN (Subject Alternative Names) discovery
- Certificate validity and expiration
- TLS protocol version detection
- Cipher suite analysis
"""

import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from config.settings import DEFAULT_TIMEOUT


class SSLAnalyzer:
    """
    Analyzes SSL/TLS certificates and configuration.

    Provides detailed information about certificates including
    validity, issuer, subject alternative names, and security assessment.
    """

    def __init__(self, domain: str, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize SSL analyzer.

        Args:
            domain: Target domain to analyze
            timeout: Connection timeout in seconds
        """
        self.domain = domain
        self.timeout = timeout
        self.port = 443

    def analyze(self) -> dict[str, Any]:
        """
        Perform comprehensive SSL/TLS analysis.

        Returns:
            Dictionary with certificate and TLS configuration details
        """
        results: dict[str, Any] = {
            "valid": False,
            "certificate": None,
            "chain": [],
            "protocols": [],
            "cipher_suite": None,
            "security_grade": None,
            "issues": [],
            "san_domains": [],
        }

        try:
            cert_data = self._get_certificate()
            if cert_data:
                results["valid"] = True
                results["certificate"] = cert_data["certificate"]
                results["chain"] = cert_data.get("chain", [])
                results["san_domains"] = cert_data.get("san_domains", [])

                # Analyze TLS configuration
                tls_config = self._analyze_tls_config()
                results["protocols"] = tls_config.get("protocols", [])
                results["cipher_suite"] = tls_config.get("cipher_suite")

                # Security assessment
                security = self._assess_security(cert_data, tls_config)
                results["security_grade"] = security.get("grade")
                results["issues"] = security.get("issues", [])

        except Exception as e:
            results["issues"].append(f"SSL analysis error: {e!s}")

        return results

    def _get_certificate(self) -> dict[str, Any] | None:
        """Retrieve and parse SSL certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Allow self-signed for analysis

            with (
                socket.create_connection(
                    (self.domain, self.port), timeout=self.timeout
                ) as sock,
                context.wrap_socket(sock, server_hostname=self.domain) as ssock,
            ):
                cert = ssock.getpeercert(binary_form=False)
                cert_binary = ssock.getpeercert(binary_form=True)

                if not cert and cert_binary is not None:
                    # Try to get cert even without verification
                    cert = self._parse_binary_cert(cert_binary)

                if cert:
                    return self._parse_certificate(cert)

        except ssl.SSLError as e:
            # Try alternative method
            return self._get_certificate_alternative(str(e))
        except (TimeoutError, ConnectionRefusedError, OSError):
            return None

        return None

    def _get_certificate_alternative(self, _ssl_error: str) -> dict[str, Any] | None:
        """Alternative certificate retrieval for problematic hosts."""
        try:
            # Create context that accepts all certificates
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with (
                socket.create_connection(
                    (self.domain, self.port), timeout=self.timeout
                ) as sock,
                context.wrap_socket(sock, server_hostname=self.domain) as ssock,
            ):
                cert_binary = ssock.getpeercert(binary_form=True)

                if cert_binary:
                    return self._parse_binary_cert(cert_binary)

        except Exception:  # noqa: S110
            pass

        return None

    def _parse_certificate(self, cert: dict[str, Any]) -> dict[str, Any]:
        """Parse certificate into structured format."""
        result: dict[str, Any] = {
            "certificate": {},
            "chain": [],
            "san_domains": [],
        }

        # Subject
        subject = {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                subject[key] = value
        result["certificate"]["subject"] = subject

        # Issuer
        issuer = {}
        for rdn in cert.get("issuer", ()):
            for key, value in rdn:
                issuer[key] = value
        result["certificate"]["issuer"] = issuer

        # Validity
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        result["certificate"]["valid_from"] = not_before
        result["certificate"]["valid_until"] = not_after

        # Calculate days until expiration
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            days_until_expiry = (expiry - now).days
            result["certificate"]["days_until_expiry"] = days_until_expiry
            result["certificate"]["is_expired"] = days_until_expiry < 0
        except (ValueError, TypeError):
            result["certificate"]["days_until_expiry"] = None
            result["certificate"]["is_expired"] = None

        # Serial number
        result["certificate"]["serial_number"] = cert.get("serialNumber", "")

        # Version
        result["certificate"]["version"] = cert.get("version", 0) + 1

        # Subject Alternative Names (SAN)
        san_domains = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_domains.append(san_value)
            elif san_type == "IP Address":
                san_domains.append(f"IP:{san_value}")
        result["san_domains"] = san_domains
        result["certificate"]["san_count"] = len(san_domains)

        # OCSP and CRL
        result["certificate"]["ocsp"] = cert.get("OCSP", [])
        result["certificate"]["crl"] = cert.get("crlDistributionPoints", [])

        # CA Issuers
        result["certificate"]["ca_issuers"] = cert.get("caIssuers", [])

        return result

    def _parse_binary_cert(self, cert_binary: bytes) -> dict[str, Any] | None:
        """Parse binary certificate data."""
        try:
            # Use ssl to decode
            import ssl as ssl_module

            # Create a temporary context to decode the cert
            # Note: _ssl._test_decode_cert is an internal CPython API
            _ssl_internal = getattr(ssl_module, "_ssl", None)
            if _ssl_internal is not None:
                decode_func = getattr(_ssl_internal, "_test_decode_cert", None)
                if decode_func is not None:
                    cert = decode_func(cert_binary)
                    if cert:
                        return self._parse_certificate(cert)
        except Exception:  # noqa: S110
            pass

        # Fallback: extract basic info from binary
        try:
            result: dict[str, Any] = {
                "certificate": {
                    "subject": {"commonName": self.domain},
                    "issuer": {},
                    "raw_available": True,
                },
                "chain": [],
                "san_domains": [],
            }
            return result
        except Exception:
            return None

    def _analyze_tls_config(self) -> dict[str, Any]:
        """Analyze TLS protocol and cipher configuration."""
        results: dict[str, Any] = {
            "protocols": [],
            "cipher_suite": None,
        }

        # Check supported protocols
        protocols_to_check = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ]

        for proto_name, proto_version in protocols_to_check:
            if self._check_protocol_support(proto_version):
                results["protocols"].append(proto_name)

        # Get current cipher suite
        try:
            context = ssl.create_default_context()
            with (
                socket.create_connection(
                    (self.domain, self.port), timeout=self.timeout
                ) as sock,
                context.wrap_socket(sock, server_hostname=self.domain) as ssock,
            ):
                cipher = ssock.cipher()
                if cipher:
                    results["cipher_suite"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }
        except Exception:  # noqa: S110
            pass

        return results

    def _check_protocol_support(self, protocol: ssl.TLSVersion) -> bool:
        """Check if a specific TLS protocol version is supported."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = protocol
            context.maximum_version = protocol
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with (
                socket.create_connection(
                    (self.domain, self.port), timeout=self.timeout
                ) as sock,
                context.wrap_socket(sock, server_hostname=self.domain),
            ):
                return True
        except Exception:
            return False

    def _assess_security(
        self, cert_data: dict[str, Any], tls_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Assess overall SSL/TLS security."""
        issues: list[str] = []
        score = 100

        cert = cert_data.get("certificate", {})

        # Check expiration
        days_until_expiry = cert.get("days_until_expiry")
        if days_until_expiry is not None:
            if days_until_expiry < 0:
                issues.append("Certificate is expired")
                score -= 50
            elif days_until_expiry < 30:
                issues.append(f"Certificate expires in {days_until_expiry} days")
                score -= 20
            elif days_until_expiry < 90:
                issues.append(f"Certificate expires in {days_until_expiry} days")
                score -= 5

        # Check protocols
        protocols = tls_config.get("protocols", [])
        if "TLSv1.3" not in protocols:
            issues.append("TLS 1.3 not supported")
            score -= 10

        if not protocols:
            issues.append("Could not determine supported protocols")
            score -= 15

        # Check cipher strength
        cipher = tls_config.get("cipher_suite", {})
        if cipher:
            bits = cipher.get("bits", 0)
            if bits < 128:
                issues.append(f"Weak cipher ({bits} bits)")
                score -= 30
            elif bits < 256:
                score -= 5

            # Check for weak ciphers
            cipher_name = cipher.get("name", "").upper()
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
            for weak in weak_ciphers:
                if weak in cipher_name:
                    issues.append(f"Weak cipher algorithm: {weak}")
                    score -= 25
                    break

        # Check SAN
        san_domains = cert_data.get("san_domains", [])
        if not san_domains:
            issues.append("No Subject Alternative Names")
            score -= 5

        # Check issuer (self-signed)
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        if subject.get("commonName") == issuer.get("commonName") and subject.get(
            "organizationName"
        ) == issuer.get("organizationName"):
            issues.append("Self-signed certificate")
            score -= 20

        # Calculate grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "grade": grade,
            "score": max(0, score),
            "issues": issues,
        }

    def get_san_domains(self) -> list[str]:
        """Get all Subject Alternative Names from certificate."""
        try:
            cert_data = self._get_certificate()
            if cert_data:
                san_domains: list[str] = cert_data.get("san_domains", [])
                return san_domains
        except Exception:  # noqa: S110
            pass
        return []


def analyze_ssl(domain: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Convenience function for SSL analysis.

    Args:
        domain: Target domain
        timeout: Connection timeout

    Returns:
        SSL analysis results
    """
    analyzer = SSLAnalyzer(domain, timeout=timeout)
    return analyzer.analyze()
