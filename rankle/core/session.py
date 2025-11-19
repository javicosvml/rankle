"""
HTTP Session management for Rankle
"""

import sys

try:
    import requests
except ImportError:
    print("\n" + "=" * 80)
    print("❌ Missing required dependency: requests")
    print("=" * 80)
    print("\nPlease install required libraries:")
    print("  pip install requests")
    print("=" * 80 + "\n")
    sys.exit(1)

from config.settings import DEFAULT_HEADERS, DEFAULT_TIMEOUT, MAX_REDIRECTS


class SessionManager:
    """Manages HTTP sessions with realistic headers"""

    def __init__(self, user_agent: str | None = None, timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize session manager

        Args:
            user_agent: Custom user agent string
            timeout: Default timeout for requests
        """
        self.timeout = timeout
        self.session = self._create_session(user_agent)

    def _create_session(self, user_agent: str | None = None) -> requests.Session:
        """
        Create requests session with realistic headers

        Args:
            user_agent: Custom user agent string

        Returns:
            Configured requests session
        """
        session = requests.Session()
        headers = DEFAULT_HEADERS.copy()

        if user_agent:
            headers["User-Agent"] = user_agent

        session.headers.update(headers)
        session.max_redirects = MAX_REDIRECTS

        return session

    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform GET request

        Args:
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """
        Perform POST request

        Args:
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.post(url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        """
        Perform HEAD request

        Args:
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.head(url, **kwargs)

    def close(self):
        """Close the session"""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
