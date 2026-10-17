"""CyberSentinel AI — Rate Limiting Storage Backends (CSAI-SEC-API-RATE-LIMIT)

Provides atomic Redis sliding-window storage with bounded thread-safe in-memory
fallback. Guarantees deterministic state under concurrency and bounded memory use.
"""

import collections
import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Deque, Dict, Tuple
from uuid import uuid4

from pydantic import BaseModel

logger = logging.getLogger("cybersentinel.rate_limit")

# Atomic Lua script for Redis sliding window rate limiting
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

-- Remove timestamps older than (now - window)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

-- Count current entries in window
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 2)
    return {1, limit - current_count - 1, 0, now + window}
else
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    local reset_epoch = now + window
    if #oldest >= 2 then
        local oldest_time = tonumber(oldest[2])
        retry_after = math.max(1, math.ceil(oldest_time + window - now))
        reset_epoch = oldest_time + window
    end
    return {0, 0, retry_after, reset_epoch}
end
"""


class RateLimitResult(BaseModel):
    """Result of an evaluated rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset_epoch: float
    retry_after: int = 0


class BaseRateLimitStore(ABC):
    """Abstract interface for rate limit storage backends."""

    @abstractmethod
    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult | None:
        """Attempt to acquire a request quota within sliding window.

        Returns RateLimitResult if evaluated, or None if store is unavailable.
        """
        pass

    @abstractmethod
    def check_health(self) -> Dict[str, str | bool]:
        """Check backend health and operational status."""
        pass


class RedisRateLimitStore(BaseRateLimitStore):
    """Atomic Redis-backed sliding window rate limiter using server-side Lua scripts."""

    def __init__(self, redis_url: str, client: object | None = None) -> None:
        self.redis_url = redis_url
        self._custom_client = client is not None
        self._client = client
        self._script: Any = None
        self._is_connected = False
        self._last_reconnect_attempt: float = 0.0
        self._init_client()

    def _init_client(self) -> None:
        if self._client is not None:
            try:
                if hasattr(self._client, "ping"):
                    self._client.ping()  # type: ignore[attr-defined]
                if self._script is None and hasattr(self._client, "register_script"):
                    self._script = self._client.register_script(SLIDING_WINDOW_LUA)  # type: ignore[attr-defined]
                self._is_connected = True
            except Exception as exc:
                logger.warning("Redis client ping/register failed: %s", exc)
                self._is_connected = False
            return

        try:
            import redis

            self._client = redis.from_url(self.redis_url, socket_timeout=1.0)
            self._client.ping()  # type: ignore[attr-defined]
            self._script = self._client.register_script(SLIDING_WINDOW_LUA)  # type: ignore[attr-defined]
            self._is_connected = True
        except Exception as exc:
            logger.warning("Failed to connect to Redis rate limit store: %s", exc)
            self._is_connected = False
            self._client = None
            self._script = None

    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult | None:
        now = time.time()
        if not self._is_connected or self._client is None or self._script is None:
            # Debounced auto-reconnection attempt (1s interval)
            if now - self._last_reconnect_attempt >= 1.0:
                self._last_reconnect_attempt = now
                self._init_client()
            if not self._is_connected or self._client is None or self._script is None:
                return None

        member = f"{now}-{uuid4().hex[:8]}"
        try:
            # Execute atomic Lua script
            res = self._script(  # type: ignore[misc]
                keys=[key],
                args=[now, window_seconds, limit, member],
            )
            # res: {allowed (0/1), remaining, retry_after, reset_epoch}
            allowed = bool(res[0])
            remaining = int(res[1])
            retry_after = int(res[2])
            reset_epoch = float(res[3])

            return RateLimitResult(
                allowed=allowed,
                limit=limit,
                remaining=remaining,
                reset_epoch=reset_epoch,
                retry_after=retry_after,
            )
        except Exception as exc:
            logger.warning("Redis rate limit evaluation error for key %s: %s", key, exc)
            self._is_connected = False
            self._last_reconnect_attempt = now
            if not self._custom_client:
                self._client = None
                self._script = None
            return None

    def check_health(self) -> Dict[str, str | bool]:
        if not self._is_connected or self._client is None:
            self._init_client()
        if not self._is_connected or self._client is None:
            return {"type": "redis", "healthy": False, "connected": False}
        try:
            self._client.ping()  # type: ignore[attr-defined]
            return {"type": "redis", "healthy": True, "connected": True}
        except Exception:
            self._is_connected = False
            if not self._custom_client:
                self._client = None
                self._script = None
            return {"type": "redis", "healthy": False, "connected": False}


class InMemoryRateLimitStore(BaseRateLimitStore):
    """Thread-safe bounded in-memory sliding window rate limiter.

    Uses an OrderedDict LRU cache to bound memory consumption and avoid
    unbounded per-IP or per-user state growth.
    NOTE: Process-local only. Not globally consistent across multiple worker processes.
    """

    def __init__(self, max_keys: int = 10000, reject_on_capacity: bool = False) -> None:
        self.max_keys = max_keys
        self.reject_on_capacity = reject_on_capacity
        self._lock = threading.Lock()
        self._is_exhausted = False
        # Key -> deque of timestamps
        self._store: collections.OrderedDict[str, Deque[Tuple[float, float]]] = (
            collections.OrderedDict()
        )

    def set_exhausted(self, exhausted: bool) -> None:
        """Explicitly set or clear storage exhaustion state (for fail-closed testing)."""
        with self._lock:
            self._is_exhausted = exhausted

    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult | None:
        if self._is_exhausted:
            return None

        now_mono = time.monotonic()
        now_wall = time.time()
        cutoff_mono = now_mono - window_seconds

        with self._lock:
            if self._is_exhausted:
                return None

            if key in self._store:
                # Mark as recently used
                self._store.move_to_end(key)
                window_deque = self._store[key]
            else:
                # If reject_on_capacity is enabled and capacity reached, fail admission
                if self.reject_on_capacity and len(self._store) >= self.max_keys:
                    return None

                # Evict oldest entry if capacity reached
                if len(self._store) >= self.max_keys:
                    self._store.popitem(last=False)
                window_deque = collections.deque()
                self._store[key] = window_deque

            # Prune timestamps older than window
            while window_deque and window_deque[0][0] <= cutoff_mono:
                window_deque.popleft()

            current_count = len(window_deque)
            if current_count < limit:
                window_deque.append((now_mono, now_wall))
                remaining = limit - current_count - 1
                reset_epoch = now_wall + window_seconds
                return RateLimitResult(
                    allowed=True,
                    limit=limit,
                    remaining=remaining,
                    reset_epoch=reset_epoch,
                    retry_after=0,
                )
            else:
                oldest_mono, oldest_wall = window_deque[0]
                elapsed_since_oldest = now_mono - oldest_mono
                retry_after = max(1, int(window_seconds - elapsed_since_oldest + 0.999))
                reset_epoch = oldest_wall + window_seconds
                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_epoch=reset_epoch,
                    retry_after=retry_after,
                )

    def clear(self) -> None:
        """Clear all in-memory rate limiting state (for testing)."""
        with self._lock:
            self._store.clear()

    def check_health(self) -> Dict[str, str | bool]:
        with self._lock:
            key_count = len(self._store)
        return {
            "type": "in_memory",
            "healthy": True,
            "connected": True,
            "active_keys": str(key_count),
            "max_keys": str(self.max_keys),
            "scope": "process_local",
        }
