"""CyberSentinel AI — Deduplication Engine Unit Tests"""

import time

from services.normalization.deduplication import DeduplicationCache


def test_deduplication_basic():
    """Verify first event passes and identical key is flagged as duplicate."""
    cache = DeduplicationCache(max_capacity=100, ttl_seconds=10)
    key = "conn-01:hash-abcdef123456"

    # First attempt: not duplicate
    assert cache.is_duplicate(key) is False

    # Second attempt with same key: duplicate
    assert cache.is_duplicate(key) is True

    # Different key: not duplicate
    assert cache.is_duplicate("conn-01:hash-999999999999") is False


def test_deduplication_ttl_expiration():
    """Verify keys expire after configured TTL."""
    cache = DeduplicationCache(max_capacity=100, ttl_seconds=1)
    key = "expiring-key"

    assert cache.is_duplicate(key) is False
    assert cache.is_duplicate(key) is True

    # Sleep past TTL
    time.sleep(1.1)

    # Key should no longer be considered duplicate
    assert cache.is_duplicate(key) is False


def test_deduplication_capacity_eviction():
    """Verify LRU/FIFO eviction when max capacity is reached."""
    cache = DeduplicationCache(max_capacity=3, ttl_seconds=60)
    cache.is_duplicate("k1")
    cache.is_duplicate("k2")
    cache.is_duplicate("k3")
    assert cache.size() == 3

    # Add 4th key; oldest key 'k1' should be evicted
    cache.is_duplicate("k4")
    assert cache.size() == 3

    # 'k1' was evicted, so re-submitting 'k1' is accepted
    assert cache.is_duplicate("k1") is False
