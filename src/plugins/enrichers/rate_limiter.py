"""Rate limiting for API calls."""

import asyncio
import time
from collections import deque
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    calls: int
    period: int  # seconds


class RateLimiter:
    """Token bucket rate limiter with per-service limits."""

    def __init__(self):
        """Initialize rate limiter."""
        self._limits: Dict[str, RateLimitConfig] = {}
        self._tokens: Dict[str, deque] = {}
        self._locks: Dict[str, asyncio.Lock] = {}

    def configure(self, service: str, calls: int, period: int):
        """Configure rate limit for a service.

        Args:
            service: Service name
            calls: Number of calls allowed
            period: Time period in seconds
        """
        self._limits[service] = RateLimitConfig(calls=calls, period=period)
        self._tokens[service] = deque(maxlen=calls)
        self._locks[service] = asyncio.Lock()

    async def acquire(self, service: str, timeout: Optional[float] = None) -> bool:
        """Acquire a token for making an API call.

        Args:
            service: Service name
            timeout: Maximum time to wait in seconds

        Returns:
            True if token acquired, False if timeout

        Raises:
            ValueError: If service not configured
        """
        if service not in self._limits:
            # If not configured, allow immediately
            return True

        async with self._locks[service]:
            config = self._limits[service]
            tokens = self._tokens[service]

            start_time = time.time()

            while True:
                now = time.time()

                # Remove expired tokens
                while tokens and tokens[0] < now - config.period:
                    tokens.popleft()

                # Check if we can make a call
                if len(tokens) < config.calls:
                    tokens.append(now)
                    return True

                # Check timeout
                if timeout and (time.time() - start_time) >= timeout:
                    return False

                # Wait before retry
                if tokens:
                    oldest_token = tokens[0]
                    wait_time = (oldest_token + config.period) - now
                    if wait_time > 0:
                        await asyncio.sleep(min(wait_time, 0.1))
                else:
                    await asyncio.sleep(0.1)

    def get_status(self, service: str) -> Dict[str, any]:
        """Get current status for a service.

        Args:
            service: Service name

        Returns:
            Dictionary with status information
        """
        if service not in self._limits:
            return {"configured": False}

        config = self._limits[service]
        tokens = self._tokens[service]
        now = time.time()

        # Count valid tokens
        valid_tokens = sum(1 for t in tokens if t >= now - config.period)

        return {
            "configured": True,
            "limit": config.calls,
            "period": config.period,
            "used": valid_tokens,
            "available": config.calls - valid_tokens,
        }


# Global rate limiter instance
_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance."""
    return _rate_limiter


def configure_default_limits():
    """Configure default rate limits for known services."""
    limiter = get_rate_limiter()

    # Configure default limits based on research
    limiter.configure("virustotal", calls=4, period=60)
    limiter.configure("ipinfo", calls=1000, period=3600)
    limiter.configure("greynoise", calls=10, period=60)
    limiter.configure("abuseipdb", calls=1, period=86400)
    limiter.configure("shodan", calls=1, period=1)
    limiter.configure("censys", calls=5, period=60)
    limiter.configure("securitytrails", calls=1, period=1800)
    limiter.configure("threatcrowd", calls=1, period=10)
    limiter.configure("bgpview", calls=10, period=60)
    limiter.configure("alienvault_otx", calls=10, period=60)
    limiter.configure("urlhaus", calls=10, period=60)
    limiter.configure("crtsh", calls=5, period=60)
    limiter.configure("ipqualityscore", calls=10, period=60)
