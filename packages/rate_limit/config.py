"""CyberSentinel AI — API Rate Limit & Abuse Protection Configuration (CSAI-SEC-API-RATE-LIMIT)"""

import os
from enum import Enum
from typing import Dict, Set

from pydantic import BaseModel, Field


class RateLimitCategory(str, Enum):
    """Authoritative API endpoint rate limit categories."""

    AUTH = "auth"
    READ = "read"
    AI = "ai"
    BENCHMARK = "benchmark"
    RESPONSE = "response"
    INGESTION = "ingestion"
    GENERAL = "general"


class RateLimitBudget(BaseModel):
    """Budget constraints for a specific endpoint category."""

    requests: int = Field(..., description="Maximum allowed requests within window")
    window_seconds: int = Field(default=60, description="Sliding window duration in seconds")


class RateLimitConfig(BaseModel):
    """Global configuration for API abuse protection and rate limiting."""

    enabled: bool = Field(default=True, description="Master enable/disable switch")
    redis_url: str | None = Field(default=None, description="Redis connection URL for shared limits")
    trusted_proxies: Set[str] = Field(
        default_factory=lambda: {"127.0.0.1", "::1", "localhost"},
        description="Set of IP addresses trusted for X-Forwarded-For resolution",
    )
    fail_closed_expensive: bool = Field(
        default=True,
        description="Whether expensive operations (AI, Benchmarks) fail-closed if rate store is completely exhausted",
    )
    max_in_memory_keys: int = Field(
        default=10000,
        description="Maximum entries in process-local LRU store to prevent memory exhaustion",
    )
    max_request_body_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Maximum allowable HTTP request body size in bytes",
    )
    budgets: Dict[RateLimitCategory, RateLimitBudget] = Field(
        default_factory=dict,
        description="Category-specific request budgets",
    )

    @classmethod
    def from_env(cls) -> "RateLimitConfig":
        """Instantiate configuration from environment variables with safe defaults."""
        is_test = "PYTEST_CURRENT_TEST" in os.environ or os.getenv("TESTING") == "1"

        enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("true", "1")
        redis_url = os.getenv("RATE_LIMIT_REDIS_URL") or os.getenv("REDIS_URL")

        trusted_proxies_str = os.getenv("RATE_LIMIT_TRUSTED_PROXIES", "127.0.0.1,::1,localhost")
        trusted_proxies = {p.strip() for p in trusted_proxies_str.split(",") if p.strip()}

        max_in_memory_keys = int(os.getenv("RATE_LIMIT_MAX_IN_MEMORY_KEYS", "10000"))
        max_request_body_bytes = int(
            os.getenv("MAX_REQUEST_BODY_BYTES", str(10 * 1024 * 1024))
        )
        fail_closed_expensive = os.getenv(
            "RATE_LIMIT_FAIL_CLOSED_EXPENSIVE", "true"
        ).lower() in ("true", "1")

        # In standard automated test runs, provide generous headroom so existing non-rate-limit tests
        # run at full speed without throttle, unless an individual test explicitly overrides budgets.
        multiplier = 100 if is_test else 1

        budgets = {
            RateLimitCategory.AUTH: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_AUTH_PER_MINUTE", str(60 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.READ: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_READ_PER_MINUTE", str(120 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.AI: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_AI_PER_MINUTE", str(20 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.BENCHMARK: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_BENCHMARK_PER_MINUTE", str(10 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.RESPONSE: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_RESPONSE_PER_MINUTE", str(30 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.INGESTION: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_INGEST_PER_MINUTE", str(300 * multiplier))),
                window_seconds=60,
            ),
            RateLimitCategory.GENERAL: RateLimitBudget(
                requests=int(os.getenv("RATE_LIMIT_GENERAL_PER_MINUTE", str(60 * multiplier))),
                window_seconds=60,
            ),
        }

        return cls(
            enabled=enabled,
            redis_url=redis_url,
            trusted_proxies=trusted_proxies,
            fail_closed_expensive=fail_closed_expensive,
            max_in_memory_keys=max_in_memory_keys,
            max_request_body_bytes=max_request_body_bytes,
            budgets=budgets,
        )
