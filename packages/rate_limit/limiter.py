"""CyberSentinel AI — Rate Limiter Engine (CSAI-SEC-API-RATE-LIMIT)

Coordinates primary Redis and secondary in-memory stores, applies category
budgets, enforces fail-closed policies for expensive operations under outage,
and records telemetry metrics.
"""

import logging
from typing import Dict, Optional

from packages.observability.metrics import metrics
from packages.rate_limit.config import RateLimitBudget, RateLimitCategory, RateLimitConfig
from packages.rate_limit.storage import (
    BaseRateLimitStore,
    InMemoryRateLimitStore,
    RateLimitResult,
    RedisRateLimitStore,
)

logger = logging.getLogger("cybersentinel.rate_limit")


class RateLimiter:
    """Core rate limiter coordinating distributed and local sliding window stores."""

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        primary_store: Optional[BaseRateLimitStore] = None,
        fallback_store: Optional[BaseRateLimitStore] = None,
    ) -> None:
        self.config = config or RateLimitConfig.from_env()

        # Primary store: Redis (if configured and available)
        self.primary_store: Optional[BaseRateLimitStore]
        if primary_store is not None:
            self.primary_store = primary_store
        elif self.config.redis_url:
            self.primary_store = RedisRateLimitStore(self.config.redis_url)
        else:
            self.primary_store = None

        # Fallback store: Bounded thread-safe in-memory store
        self.fallback_store = fallback_store or InMemoryRateLimitStore(
            max_keys=self.config.max_in_memory_keys
        )

    def evaluate(
        self,
        key: str,
        category: RateLimitCategory,
        budget_override: Optional[RateLimitBudget] = None,
    ) -> RateLimitResult:
        """Evaluate rate limit quota for a given identifier and category.

        If primary store is unavailable, automatically falls back to bounded in-memory store.
        For expensive operations (AI, Benchmarks), ensures requests do not silently become unlimited.
        """
        if not self.config.enabled:
            # Rate limiting globally disabled
            return RateLimitResult(
                allowed=True,
                limit=999999,
                remaining=999999,
                reset_epoch=0.0,
                retry_after=0,
            )

        budget = budget_override or self.config.budgets.get(
            category,
            RateLimitBudget(requests=60, window_seconds=60),
        )

        metrics.inc_counter(f"rate_limit_requests_{category.value}_total", 1)

        result: Optional[RateLimitResult] = None

        # 1. Attempt primary store (Redis)
        primary_failed = False
        if self.primary_store is not None:
            result = self.primary_store.acquire(
                key=key,
                limit=budget.requests,
                window_seconds=budget.window_seconds,
            )
            if result is None:
                primary_failed = True
                metrics.inc_counter("rate_limit_redis_errors_total", 1)
                logger.warning(
                    "Primary Redis store failed; evaluating fallback policy for category '%s'",
                    category.value,
                )

        # Fail-closed for expensive operations when shared Redis quota cannot be guaranteed
        if primary_failed and self.config.fail_closed_expensive and category in (
            RateLimitCategory.AI,
            RateLimitCategory.BENCHMARK,
            RateLimitCategory.RESPONSE,
        ):
            metrics.inc_counter(f"rate_limit_fail_closed_{category.value}_total", 1)
            metrics.inc_counter("rate_limit_exceeded_total", 1)
            logger.warning(
                "Failing closed for expensive operation '%s' because shared Redis store is unavailable",
                category.value,
            )
            import time

            return RateLimitResult(
                allowed=False,
                limit=budget.requests,
                remaining=0,
                reset_epoch=time.time() + budget.window_seconds,
                retry_after=budget.window_seconds,
            )

        # 2. Fallback store (In-memory) - for standard/read traffic or when primary not configured
        if result is None and self.fallback_store is not None:
            metrics.inc_counter(f"rate_limit_fallback_used_{category.value}_total", 1)
            try:
                result = self.fallback_store.acquire(
                    key=key,
                    limit=budget.requests,
                    window_seconds=budget.window_seconds,
                )
            except Exception as exc:
                logger.error("Fallback in-memory rate limit store error: %s", exc)
                result = None

        if result is None:
            import time

            # If fallback store is also completely exhausted or unavailable:
            # expensive operations (AI, Benchmarks, Response proposals) fail-closed, general operations fail-open
            fail_closed = self.config.fail_closed_expensive and category in (
                RateLimitCategory.AI,
                RateLimitCategory.BENCHMARK,
                RateLimitCategory.RESPONSE,
            )
            result = RateLimitResult(
                allowed=not fail_closed,
                limit=budget.requests,
                remaining=0,
                reset_epoch=time.time() + budget.window_seconds,
                retry_after=budget.window_seconds if fail_closed else 0,
            )

        if not result.allowed:
            metrics.inc_counter(f"rate_limit_exceeded_{category.value}_total", 1)
            metrics.inc_counter("rate_limit_exceeded_total", 1)
            logger.info(
                "Rate limit exceeded: category='%s' key='%s' retry_after=%ds",
                category.value,
                key,
                result.retry_after,
            )

        return result

    def check_health(self) -> Dict[str, object]:
        """Inspect operational health of rate limiting backend stores."""
        primary_info = (
            self.primary_store.check_health()
            if self.primary_store
            else {"type": "none", "connected": False}
        )
        fallback_info = self.fallback_store.check_health()
        return {
            "enabled": self.config.enabled,
            "primary": primary_info,
            "fallback": fallback_info,
        }
