"""
Rate Limiter Module for Rankle

Provides intelligent rate limiting to avoid detection and respect server limits:
- Adaptive delays based on response times
- Exponential backoff on errors
- Per-host rate limiting
- Jitter for natural-looking traffic
"""

import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    # Base delay between requests (seconds)
    base_delay: float = 0.5

    # Minimum delay (seconds)
    min_delay: float = 0.2

    # Maximum delay (seconds)
    max_delay: float = 5.0

    # Jitter percentage (0.0 to 1.0)
    jitter: float = 0.3

    # Backoff multiplier on errors
    backoff_multiplier: float = 2.0

    # Max consecutive errors before longer pause
    max_consecutive_errors: int = 3

    # Pause duration after max errors (seconds)
    error_pause: float = 10.0

    # Adaptive delay based on response time
    adaptive: bool = True

    # Response time threshold for increasing delay (seconds)
    slow_response_threshold: float = 2.0


@dataclass
class HostState:
    """State tracking for a specific host."""

    last_request_time: float = 0.0
    current_delay: float = 0.5
    consecutive_errors: int = 0
    total_requests: int = 0
    total_errors: int = 0
    avg_response_time: float = 0.0
    response_times: list[float] = field(default_factory=list)


class RateLimiter:
    """
    Intelligent rate limiter for web reconnaissance.

    Features:
    - Per-host tracking
    - Adaptive delays based on server response times
    - Exponential backoff on errors
    - Random jitter for natural traffic patterns
    """

    def __init__(self, config: RateLimitConfig | None = None):
        """
        Initialize rate limiter.

        Args:
            config: Rate limiting configuration
        """
        self.config = config or RateLimitConfig()
        self._host_states: dict[str, HostState] = defaultdict(HostState)
        self._lock = Lock()

    def wait(self, host: str) -> float:
        """
        Wait appropriate time before next request to host.

        Args:
            host: Target hostname

        Returns:
            Actual wait time in seconds
        """
        with self._lock:
            state = self._host_states[host]

            # Calculate time since last request
            now = time.time()
            elapsed = now - state.last_request_time

            # Calculate required delay with jitter
            delay = self._calculate_delay(state)

            # Only wait if needed
            if elapsed < delay:
                wait_time = delay - elapsed
                time.sleep(wait_time)
                actual_wait = wait_time
            else:
                actual_wait = 0.0

            # Update last request time
            state.last_request_time = time.time()
            state.total_requests += 1

            return actual_wait

    def _calculate_delay(self, state: HostState) -> float:
        """Calculate delay with jitter and adaptive adjustments."""
        base = state.current_delay

        # Add jitter
        jitter_range = base * self.config.jitter
        jitter = random.uniform(-jitter_range, jitter_range)
        delay = base + jitter

        # Clamp to bounds
        return max(self.config.min_delay, min(self.config.max_delay, delay))

    def record_success(self, host: str, response_time: float):
        """
        Record a successful request.

        Args:
            host: Target hostname
            response_time: Response time in seconds
        """
        with self._lock:
            state = self._host_states[host]
            state.consecutive_errors = 0

            # Track response time
            state.response_times.append(response_time)
            if len(state.response_times) > 10:
                state.response_times.pop(0)

            # Calculate average response time
            state.avg_response_time = sum(state.response_times) / len(
                state.response_times
            )

            # Adaptive delay adjustment
            if self.config.adaptive:
                if response_time > self.config.slow_response_threshold:
                    # Slow response, increase delay
                    state.current_delay = min(
                        state.current_delay * 1.5,
                        self.config.max_delay,
                    )
                elif response_time < self.config.slow_response_threshold / 2:
                    # Fast response, decrease delay gradually
                    state.current_delay = max(
                        state.current_delay * 0.9,
                        self.config.base_delay,
                    )

    def record_error(self, host: str):
        """
        Record a failed request.

        Args:
            host: Target hostname
        """
        with self._lock:
            state = self._host_states[host]
            state.consecutive_errors += 1
            state.total_errors += 1

            # Exponential backoff
            state.current_delay = min(
                state.current_delay * self.config.backoff_multiplier,
                self.config.max_delay,
            )

            # Long pause after too many errors
            if state.consecutive_errors >= self.config.max_consecutive_errors:
                time.sleep(self.config.error_pause)
                state.consecutive_errors = 0
                state.current_delay = self.config.base_delay

    def record_rate_limited(self, host: str, retry_after: float | None = None):
        """
        Record a rate limit response (429).

        Args:
            host: Target hostname
            retry_after: Retry-After header value if present
        """
        with self._lock:
            state = self._host_states[host]

            if retry_after:
                # Server specified wait time
                wait_time = min(retry_after, 60.0)  # Cap at 60 seconds
                time.sleep(wait_time)
                state.current_delay = max(state.current_delay, retry_after / 2)
            else:
                # Default: significant backoff
                state.current_delay = min(
                    state.current_delay * 3,
                    self.config.max_delay,
                )
                time.sleep(state.current_delay)

    def get_stats(self, host: str) -> dict[str, Any]:
        """
        Get rate limiting statistics for a host.

        Args:
            host: Target hostname

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            state = self._host_states[host]
            return {
                "total_requests": state.total_requests,
                "total_errors": state.total_errors,
                "consecutive_errors": state.consecutive_errors,
                "current_delay": state.current_delay,
                "avg_response_time": state.avg_response_time,
            }

    def reset(self, host: str | None = None):
        """
        Reset rate limiter state.

        Args:
            host: Specific host to reset, or None for all
        """
        with self._lock:
            if host:
                self._host_states[host] = HostState()
            else:
                self._host_states.clear()


# Preset configurations for different scanning modes
RATE_LIMIT_PRESETS: dict[str, RateLimitConfig] = {
    # Stealth mode - very slow, minimal detection risk
    "stealth": RateLimitConfig(
        base_delay=2.0,
        min_delay=1.0,
        max_delay=10.0,
        jitter=0.5,
        backoff_multiplier=3.0,
        slow_response_threshold=3.0,
    ),
    # Normal mode - balanced speed and stealth
    "normal": RateLimitConfig(
        base_delay=0.5,
        min_delay=0.2,
        max_delay=5.0,
        jitter=0.3,
        backoff_multiplier=2.0,
        slow_response_threshold=2.0,
    ),
    # Fast mode - faster scanning, higher detection risk
    "fast": RateLimitConfig(
        base_delay=0.1,
        min_delay=0.05,
        max_delay=2.0,
        jitter=0.2,
        backoff_multiplier=1.5,
        slow_response_threshold=1.0,
    ),
    # Aggressive mode - maximum speed, high detection risk
    "aggressive": RateLimitConfig(
        base_delay=0.05,
        min_delay=0.01,
        max_delay=1.0,
        jitter=0.1,
        backoff_multiplier=1.2,
        slow_response_threshold=0.5,
    ),
}


def get_rate_limiter(preset: str = "normal") -> RateLimiter:
    """
    Get a rate limiter with a preset configuration.

    Args:
        preset: One of "stealth", "normal", "fast", "aggressive"

    Returns:
        Configured RateLimiter instance
    """
    config = RATE_LIMIT_PRESETS.get(preset, RATE_LIMIT_PRESETS["normal"])
    return RateLimiter(config)


# Global rate limiter instance
_global_rate_limiter: RateLimiter | None = None


def get_global_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    global _global_rate_limiter  # noqa: PLW0603
    if _global_rate_limiter is None:
        _global_rate_limiter = get_rate_limiter("normal")
    return _global_rate_limiter


def set_global_rate_limiter(preset: str):
    """Set the global rate limiter preset."""
    global _global_rate_limiter  # noqa: PLW0603
    _global_rate_limiter = get_rate_limiter(preset)
