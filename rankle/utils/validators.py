"""
Validation utilities for Rankle
"""

import re
from urllib.parse import urlparse


def validate_domain(domain: str) -> bool:
    """
    Validate domain format

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def extract_domain(url: str) -> str:
    """
    Extract clean domain from URL

    Args:
        url: URL to extract domain from

    Returns:
        Clean domain name
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    # Remove port if present
    return domain.split(":")[0]


def validate_ip(ip: str) -> bool:
    """
    Validate IP address format

    Args:
        ip: IP address to validate

    Returns:
        True if valid IPv4 or IPv6, False otherwise
    """
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6_pattern = r"^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$"

    if re.match(ipv4_pattern, ip):
        parts = ip.split(".")
        return all(0 <= int(part) <= 255 for part in parts)

    return bool(re.match(ipv6_pattern, ip))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe file system usage

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Limit length
    return filename[:200]


def validate_url(url: str) -> bool:
    """
    Validate URL format

    Args:
        url: URL to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False
