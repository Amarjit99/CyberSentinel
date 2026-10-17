"""CyberSentinel AI — Telemetry Deduplication & Idempotency Engine"""

import threading
import time
from collections import OrderedDict

from packages.observability import metrics


class DeduplicationCache:
    """Thread-safe bounded LRU / TTL deduplication cache."""

    def __init__(self, max_capacity: int = 50000, ttl_seconds: int = 86400) -> None:
        self.max_capacity = max_capacity
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _evict_expired(self, current_time: float) -> None:
        """Evict items older than TTL."""
        expired_keys = [k for k, exp in self._cache.items() if current_time > exp]
        for k in expired_keys:
            del self._cache[k]

    def is_duplicate(self, key: str) -> bool:
        """Check whether an event key was already processed within the active window."""
        now = time.time()
        with self._lock:
            # Check expiration
            if key in self._cache:
                if now <= self._cache[key]:
                    metrics.inc_duplicate()
                    return True
                else:
                    del self._cache[key]

            # Register new entry with expiration
            if len(self._cache) >= self.max_capacity:
                self._evict_expired(now)
                if len(self._cache) >= self.max_capacity:
                    # Pop oldest (FIFO)
                    self._cache.popitem(last=False)

            self._cache[key] = now + self.ttl_seconds
            return False

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


# Global singleton deduplicator
deduplicator = DeduplicationCache()
