"""
HTTP Session management for Rankle

Features:
- Realistic browser headers
- Automatic retry with exponential backoff
- Connection pooling
- Configurable timeouts
"""

import sys


try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("\n" + "=" * 80)
    print("❌ Missing required dependency: requests")
    print("=" * 80)
    print("\nPlease install required libraries:")
    print("  pip install requests")
    print("=" * 80 + "\n")
    sys.exit(1)

from config.settings import DEFAULT_HEADERS, DEFAULT_TIMEOUT, MAX_REDIRECTS


# Retry configuration
RETRY_TOTAL = 3
RETRY_BACKOFF_FACTOR = 0.5
RETRY_STATUS_FORCELIST = [429, 500, 502, 503, 504]


class SessionManager:
    """
    Manages HTTP sessions with realistic headers and automatic retry.

    Features:
    - Retry logic with exponential backoff for transient errors
    - Configurable timeouts
    - Connection pooling for performance
    - Realistic browser headers
    """

    def __init__(
        self,
        user_agent: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = RETRY_TOTAL,
    ):
        """
        Initialize session manager.

        Args:
            user_agent: Custom user agent string
            timeout: Default timeout for requests in seconds
            retries: Number of retries for failed requests
        """
        self.timeout = timeout
        self.retries = retries
        self.session = self._create_session(user_agent)

    def _create_session(self, user_agent: str | None = None) -> requests.Session:
        """
        Create requests session with retry logic and realistic headers.

        Args:
            user_agent: Custom user agent string

        Returns:
            Configured requests session with retry adapter
        """
        session = requests.Session()
        headers = DEFAULT_HEADERS.copy()

        if user_agent:
            headers["User-Agent"] = user_agent

        session.headers.update(headers)
        session.max_redirects = MAX_REDIRECTS

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.retries,
            backoff_factor=RETRY_BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_FORCELIST,
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            raise_on_status=False,
        )

        # Mount adapter with retry strategy for both HTTP and HTTPS
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        return session

    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Perform GET request with automatic retry.

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
        Perform POST request.

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
        Perform HEAD request with automatic retry.

        Args:
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.head(url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        """
        Perform OPTIONS request with automatic retry.

        Args:
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.options(url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Perform HTTP request with specified method.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: URL to request
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        return self.session.request(method, url, **kwargs)

    def close(self):
        """Close the session and release resources."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        self.close()
