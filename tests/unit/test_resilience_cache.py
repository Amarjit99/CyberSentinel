import time

import pytest

from packages.resilience.cache import SafeTTLCache


def test_safe_ttl_cache_is_bounded_and_lru_ordered():
    cache = SafeTTLCache[str](max_entries=2, ttl_seconds=10)
    cache.put("a", "A")
    cache.put("b", "B")
    assert cache.get("a") == "A"
    cache.put("c", "C")
    assert cache.get("b") is None
    assert cache.get("a") == "A"
    assert cache.get("c") == "C"


def test_safe_ttl_cache_expires_entries():
    cache = SafeTTLCache[str](max_entries=1, ttl_seconds=0.01)
    cache.put("a", "A")
    time.sleep(0.02)
    assert cache.get("a") is None


@pytest.mark.parametrize("max_entries,ttl_seconds", [(0, 1), (1, 0)])
def test_safe_ttl_cache_rejects_unbounded_configuration(max_entries, ttl_seconds):
    with pytest.raises(ValueError):
        SafeTTLCache(max_entries=max_entries, ttl_seconds=ttl_seconds)
