"""Token Bucket rate limiter for Aegis Shield.

Provides a thread-safe, in-memory Token Bucket rate limiter to restrict
requests per API key (rate_limit_rpm). Supports checking limits and
consuming tokens in <1ms without database roundtrips.
"""

from __future__ import annotations

import time
from threading import Lock
from aegis_shield.config import settings


class TokenBucket:
    """A single bucket tracking tokens for a client/API key."""

    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate  # Tokens added per second
        self.tokens = float(capacity)
        self.last_update = time.monotonic()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Consume tokens from the bucket. Returns True if successful."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Replenish tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class RateLimiter:
    """Manages buckets for all clients/API keys."""

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = Lock()

    def check_limit(self, key: str, rpm: int | None = None) -> bool:
        """Check and consume a rate limit token for a given key.

        Parameters
        ----------
        key : str
            Unique identifier (e.g. API key hash or client IP).
        rpm : int, optional
            Limit in requests per minute. Defaults to settings.rate_limit_rpm.
        """
        if not settings.rate_limit_enabled:
            return True

        limit = rpm if rpm is not None else settings.rate_limit_rpm
        fill_rate = limit / 60.0

        with self._lock:
            if key not in self._buckets:
                # Capacity equals the limit to allow short bursts
                self._buckets[key] = TokenBucket(capacity=limit, fill_rate=fill_rate)
            bucket = self._buckets[key]

        return bucket.consume()
