"""CyberSentinel AI — API Abuse Protection & Rate Limiting Verification (CSAI-SEC-API-RATE-LIMIT)

Comprehensive adversarial, concurrency, failover, and boundary tests validating:
1. Requests within limit succeed with X-RateLimit headers.
2. Requests exceeding limit return HTTP 429 and RATE_LIMIT_EXCEEDED error code.
3. Retry-After and X-RateLimit-* telemetry headers are returned accurately.
4. Concurrency safety: atomic Lua sorted sets / synchronized windows prevent race bypasses.
5. Role header spoofing resistance (X-Operator-Role never bypasses limits).
6. Request identifier / query parameter spoofing resistance for authenticated principals.
7. Expensive AI and benchmark category budgets strictly enforced.
8. Payload body size bounds (413) and pagination bounds (422) preserved.
9. Multi-principal and multi-IP quota isolation.
10. Redis-backed atomic sliding window operations with live Redis when available.
11. Redis outage resilience: in-memory fallback engages safely, fail-closed for expensive operations.
12. In-memory LRU store bounding (no memory leak or unbounded state growth).
13. Authorization independence: rate limiting never bypasses RBAC or leaks incident data.
14. Legitimate SOC analyst incident workflows succeed unhindered.
15. Response execution remains blocked by LIVE_RESPONSE_DISABLED=true invariant.
16. Unauthenticated IP spoofing resistance via untrusted X-Forwarded-For headers.
"""

import concurrent.futures
import os
import time
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from packages.auth import create_access_token
from packages.rate_limit import (
    InMemoryRateLimitStore,
    RateLimitBudget,
    RateLimitCategory,
    RateLimitConfig,
    RateLimiter,
    RedisRateLimitStore,
    get_safe_client_ip,
)
from schemas.enums import ErrorCodeEnum, RBACRoleEnum
from services.response import ExecuteActionRequest, ResponseManager


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    """Test client with clean rate-limiter state for testing."""
    test_config = RateLimitConfig(
        enabled=True,
        redis_url=None,  # Use in-memory for deterministic unit isolation
        max_in_memory_keys=100,
        max_request_body_bytes=1024 * 1024,  # 1 MB
        fail_closed_expensive=True,
        trusted_proxies={"127.0.0.1", "::1", "localhost"},
        budgets={
            RateLimitCategory.AUTH: RateLimitBudget(requests=5, window_seconds=60),
            RateLimitCategory.READ: RateLimitBudget(requests=5, window_seconds=60),
            RateLimitCategory.AI: RateLimitBudget(requests=2, window_seconds=60),
            RateLimitCategory.BENCHMARK: RateLimitBudget(requests=2, window_seconds=60),
            RateLimitCategory.RESPONSE: RateLimitBudget(requests=3, window_seconds=60),
            RateLimitCategory.INGESTION: RateLimitBudget(requests=10, window_seconds=60),
            RateLimitCategory.GENERAL: RateLimitBudget(requests=5, window_seconds=60),
        },
    )
    test_limiter = RateLimiter(config=test_config)
    app.state.rate_limit_config = test_config
    app.state.rate_limiter = test_limiter

    with TestClient(app) as test_client:
        yield test_client

    # Teardown
    app.state.rate_limit_config = None
    app.state.rate_limiter = None


def _make_auth_header(user_id: str, role: RBACRoleEnum = RBACRoleEnum.SOC_ANALYST) -> dict:
    """Helper to generate authentic Authorization headers."""
    token = create_access_token(
        subject=user_id,
        role=role,
        expires_in_seconds=3600,
    )
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# 1. Standard Quota Conformance & 429 Enforcement
# ==============================================================================


def test_requests_within_limit_succeed_with_headers(client: TestClient):
    """[MOCKED / ISOLATED] Requests within configured quota return 200 and accurate X-RateLimit-* headers."""
    headers = _make_auth_header("analyst-1")

    # Send 4 requests (budget is 5)
    for i in range(4):
        resp = client.get("/api/v1/incidents", headers=headers)
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert resp.headers["X-RateLimit-Limit"] == "5"
        assert resp.headers["X-RateLimit-Remaining"] == str(5 - (i + 1))
        assert "X-RateLimit-Reset" in resp.headers


def test_requests_exceeding_limit_return_429_and_retry_after(client: TestClient):
    """[MOCKED / ISOLATED] Exceeding quota triggers HTTP 429, RATE_LIMIT_EXCEEDED error code, and Retry-After header."""
    headers = _make_auth_header("analyst-burst")

    # Budget is 5 requests per 60s for READ
    for _ in range(5):
        resp = client.get("/api/v1/incidents", headers=headers)
        assert resp.status_code == 200

    # 6th request must be rejected
    blocked = client.get("/api/v1/incidents", headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After") is not None
    retry_after = int(blocked.headers["Retry-After"])
    assert 1 <= retry_after <= 60


def test_authentication_endpoints_use_auth_budget(client: TestClient):
    """Authentication routes use the dedicated AUTH budget rather than GENERAL."""
    for _ in range(5):
        response = client.post("/api/v1/auth/revoke")
        assert response.status_code == 401
        assert response.headers["X-RateLimit-Limit"] == "5"

    blocked = client.post("/api/v1/auth/revoke")
    assert blocked.status_code == 429
    assert blocked.json()["error_code"] == ErrorCodeEnum.RATE_LIMIT_EXCEEDED.value
    assert blocked.headers["X-RateLimit-Limit"] == "5"

    data = blocked.json()
    assert data["error_code"] == ErrorCodeEnum.RATE_LIMIT_EXCEEDED.value
    assert "Rate limit exceeded" in data["message"]
    assert "X-Request-ID" in blocked.headers


# ==============================================================================
# 2. Concurrency Safety & Race-Condition Resistance
# ==============================================================================


def test_concurrent_requests_strictly_bounded():
    """[MOCKED / ISOLATED] Concurrent requests across worker threads cannot race or exceed the atomic quota."""
    config = RateLimitConfig(
        enabled=True,
        redis_url=None,
        budgets={
            RateLimitCategory.GENERAL: RateLimitBudget(requests=3, window_seconds=60),
        },
    )
    limiter = RateLimiter(config=config)

    # 15 concurrent threads competing for a budget of 3
    results = []

    def attempt_request(thread_idx: int):
        return limiter.evaluate("rl:concurrency:test_user", RateLimitCategory.GENERAL)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(attempt_request, i) for i in range(15)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    allowed_count = sum(1 for r in results if r.allowed)
    blocked_count = sum(1 for r in results if not r.allowed)

    assert allowed_count == 3
    assert blocked_count == 12


# ==============================================================================
# 3. Security Invariants: Role Header & Identifier Spoofing Resistance
# ==============================================================================


def test_unauthenticated_role_header_spoofing_does_not_bypass_limit(client: TestClient):
    """[MOCKED / ISOLATED] Unauthenticated attacker sending X-Operator-Role: Admin cannot bypass IP-based limit."""
    # Read budget is 5
    for _ in range(5):
        resp = client.get("/api/v1/incidents", headers={"X-Operator-Role": "Admin"})
        # Without valid auth token, will be throttled based on safe IP
        assert resp.status_code in (200, 401, 403)

    # Attempt to bypass using different spoofed roles
    bypass_1 = client.get("/api/v1/incidents", headers={"X-Operator-Role": "SecurityAdmin"})
    assert bypass_1.status_code == 429

    bypass_2 = client.get("/api/v1/incidents", headers={"X-Operator-Role": "SystemEngineer"})
    assert bypass_2.status_code == 429


def test_authenticated_principal_cannot_bypass_via_request_identifiers(client: TestClient):
    """[MOCKED / ISOLATED] Authenticated principal cannot bypass limit by altering query params or X-Request-ID."""
    headers = _make_auth_header("analyst-id-test")

    # Exhaust quota (5 requests)
    for i in range(5):
        resp = client.get(
            f"/api/v1/incidents?attempt={i}",
            headers={**headers, "X-Request-ID": f"req-uuid-{i}"},
        )
        assert resp.status_code == 200

    # Attacker attempts bypass with new UUID and query params
    blocked = client.get(
        "/api/v1/incidents?cache_buster=12345",
        headers={**headers, "X-Request-ID": "bypass-uuid-attempt"},
    )
    assert blocked.status_code == 429
    assert blocked.json()["error_code"] == ErrorCodeEnum.RATE_LIMIT_EXCEEDED.value


# ==============================================================================
# 4. Endpoint Category Budgets: AI and Benchmark Operations
# ==============================================================================


def test_expensive_ai_endpoints_enforce_strict_budget(client: TestClient):
    """[MOCKED / ISOLATED] Expensive AI operations (triage, continue) have strict category budget (2 requests)."""
    headers = _make_auth_header("analyst-ai-budget", role=RBACRoleEnum.SOC_MANAGER)

    # Category AI limit is 2
    # Mock triage agent to avoid full LLM invocation
    with patch("apps.api.main.triage_agent.triage_incident") as mock_triage:
        mock_triage.return_value = MagicMock(
            severity="medium",
            summary="Automated triage test",
            confidence=0.85,
            suggested_actions=[],
            reasoning="Test",
        )
        # First 2 requests within budget
        r1 = client.post("/api/v1/incidents/test-inc-01/triage", headers=headers)
        assert r1.status_code in (200, 404)  # Allowed through rate limiter

        r2 = client.post("/api/v1/incidents/test-inc-01/triage", headers=headers)
        assert r2.status_code in (200, 404)

        # 3rd request must be blocked by rate limit (budget=2)
        r3 = client.post("/api/v1/incidents/test-inc-01/triage", headers=headers)
        assert r3.status_code == 429
        assert r3.json()["error_code"] == ErrorCodeEnum.RATE_LIMIT_EXCEEDED.value
        assert "Rate limit exceeded for endpoint category 'ai'" in r3.json()["message"]


def test_expensive_incident_risk_assessment_route_coverage(client: TestClient):
    """[MOCKED / ISOLATED] Expensive POST risk-assessment is classified into AI category and throttled after 2 requests."""
    headers = _make_auth_header("analyst-risk-cov", role=RBACRoleEnum.SOC_MANAGER)

    with patch("apps.api.main.risk_engine.assess_incident") as mock_assess:
        mock_assess.return_value = MagicMock(
            overall_score=75,
            tier=MagicMock(value="Tier 2"),
            summary="Test assessment",
            confidence=0.9,
            breakdown=MagicMock(business_criticality=80, asset_exposure=70, threat_severity=75),
            mitre_coverage=[],
            recommended_actions=[],
            assessed_at="2026-10-17T00:00:00Z",
            model_version="test-model",
            prompt_tokens=100,
            completion_tokens=50,
        )
        r1 = client.post("/api/v1/incidents/test-inc-01/risk-assessment", headers=headers)
        assert r1.status_code in (200, 404)

        r2 = client.post("/api/v1/incidents/test-inc-01/risk-assessment", headers=headers)
        assert r2.status_code in (200, 404)

        # 3rd request must be throttled by AI category limit (budget=2)
        r3 = client.post("/api/v1/incidents/test-inc-01/risk-assessment", headers=headers)
        assert r3.status_code == 429
        assert "Rate limit exceeded for endpoint category 'ai'" in r3.json()["message"]


def test_benchmark_endpoints_enforce_strict_budget(client: TestClient):
    """[MOCKED / ISOLATED] Benchmark execution endpoints enforce Category D budget (2 requests)."""
    headers = _make_auth_header("admin-bench", role=RBACRoleEnum.ADMIN)

    # Category BENCHMARK limit is 2
    with patch("apps.api.main.default_benchmark_runner.run_benchmark") as mock_bench:
        mock_bench.return_value = MagicMock(
            run_id="run-123",
            dataset=MagicMock(name="synthetic-small"),
            mode=MagicMock(value="full"),
            total_cases=1,
            successful_cases=1,
            failed_cases=0,
            execution_time_seconds=0.1,
            metrics=MagicMock(),
            results=[],
            timestamp=time.time(),
        )

        r1 = client.post(
            "/api/v1/benchmarks/run",
            headers=headers,
            json={"dataset_name": "synthetic-small", "execution_mode": "mock"},
        )
        assert r1.status_code in (200, 422)

        r2 = client.post(
            "/api/v1/benchmarks/run",
            headers=headers,
            json={"dataset_name": "synthetic-small", "execution_mode": "mock"},
        )
        assert r2.status_code in (200, 422)

        # 3rd benchmark run is blocked
        r3 = client.post(
            "/api/v1/benchmarks/run",
            headers=headers,
            json={"dataset_name": "synthetic-small", "execution_mode": "mock"},
        )
        assert r3.status_code == 429
        assert "benchmark" in r3.json()["message"]


# ==============================================================================
# 5. Payload and Pagination Abuse Controls
# ==============================================================================


def test_request_payload_exceeding_max_bytes_rejected_with_413(client: TestClient):
    """[MOCKED / ISOLATED] Requests with Content-Length exceeding max_request_body_bytes return 413."""
    headers = _make_auth_header("analyst-payload")
    # max_request_body_bytes is 1MB in fixture; send header indicating 5MB
    large_headers = {
        **headers,
        "Content-Length": str(5 * 1024 * 1024),
        "Content-Type": "application/json",
    }

    resp = client.post(
        "/api/v1/events",
        headers=large_headers,
        content=b"{}",
    )
    assert resp.status_code == 413
    assert "exceeds maximum allowed limit" in resp.json()["message"]


def test_chunked_streaming_request_without_content_length_exceeding_max_bytes_rejected_with_413(client: TestClient):
    """[MOCKED / ISOLATED] Streamed chunked payload without Content-Length exceeding max_request_body_bytes returns 413."""
    headers = _make_auth_header("analyst-stream-413")
    # Generate chunks exceeding 1 MB
    def large_stream():
        chunk = b'{"events": [' + (b" " * (256 * 1024))
        yield chunk
        for _ in range(4):
            yield b" " * (256 * 1024)
        yield b"]}"

    resp = client.post(
        "/api/v1/events",
        headers={**headers, "Content-Type": "application/json"},
        content=large_stream(),
    )
    assert resp.status_code == 413
    assert resp.json()["error_code"] == ErrorCodeEnum.INVALID_SCHEMA.value


def test_route_classification_matrix_parameter_bypass_attempt(client: TestClient):
    """[MOCKED / ISOLATED] Path matrix parameters cannot bypass route categorization or bounds."""
    headers = _make_auth_header("analyst-matrix-cov", role=RBACRoleEnum.SOC_MANAGER)

    with patch("apps.api.main.triage_agent.triage_incident") as mock_triage:
        mock_triage.return_value = MagicMock(
            severity="medium",
            summary="Matrix test",
            confidence=0.85,
            suggested_actions=[],
            reasoning="Test",
        )
        # Request with matrix parameter ;bypass=true must still be classified as AI
        r1 = client.post("/api/v1/incidents/test-inc-01;bypass=true/triage", headers=headers)
        assert r1.status_code in (200, 404)

        r2 = client.post("/api/v1/incidents/test-inc-01;bypass=true/triage", headers=headers)
        assert r2.status_code in (200, 404)

        # 3rd request must be blocked under AI category
        r3 = client.post("/api/v1/incidents/test-inc-01;bypass=true/triage", headers=headers)
        assert r3.status_code == 429
        assert "Rate limit exceeded for endpoint category 'ai'" in r3.json()["message"]


def test_pagination_bounds_remain_strictly_enforced(client: TestClient):
    """[MOCKED / ISOLATED] Unbounded pagination requests (limit=1000000) are rejected by schema validation (422)."""
    headers = _make_auth_header("analyst-paging")
    resp = client.get("/api/v1/incidents?limit=10000", headers=headers)
    assert resp.status_code == 422
    assert resp.json()["error_code"] == ErrorCodeEnum.VALIDATION_ERROR.value


# ==============================================================================
# 6. Principal and IP Isolation
# ==============================================================================


def test_principal_quotas_are_strictly_isolated(client: TestClient):
    """[MOCKED / ISOLATED] Exhausting quota for Analyst A does not impact Analyst B."""
    headers_a = _make_auth_header("analyst-alpha")
    headers_b = _make_auth_header("analyst-beta")

    # Exhaust Analyst A
    for _ in range(5):
        resp_a = client.get("/api/v1/incidents", headers=headers_a)
        assert resp_a.status_code == 200

    blocked_a = client.get("/api/v1/incidents", headers=headers_a)
    assert blocked_a.status_code == 429

    # Analyst B still has full quota
    resp_b = client.get("/api/v1/incidents", headers=headers_b)
    assert resp_b.status_code == 200
    assert resp_b.headers["X-RateLimit-Remaining"] == "4"


def test_safe_ip_extraction_and_untrusted_header_resistance():
    """[MOCKED / ISOLATED] Client cannot spoof IP via X-Forwarded-For unless proxy is in trusted_proxies."""
    # Case 1: Untrusted client directly connecting from 203.0.113.5 tries spoofing 10.0.0.1
    req_untrusted = MagicMock()
    req_untrusted.client.host = "203.0.113.5"
    req_untrusted.headers = {"x-forwarded-for": "10.0.0.1, 198.51.100.2"}

    trusted_proxies = {"127.0.0.1", "10.100.0.1"}
    safe_ip = get_safe_client_ip(req_untrusted, trusted_proxies)
    assert safe_ip == "203.0.113.5"  # Direct peer used; spoofed header ignored

    # Case 2: Trusted reverse proxy at 127.0.0.1 forwards genuine client IP
    req_trusted = MagicMock()
    req_trusted.client.host = "127.0.0.1"
    req_trusted.headers = {"x-forwarded-for": "198.51.100.25, 127.0.0.1"}

    safe_ip_trusted = get_safe_client_ip(req_trusted, trusted_proxies)
    assert safe_ip_trusted == "198.51.100.25"


# ==============================================================================
# 7. Redis Storage & Sliding Window Correctness
# ==============================================================================


def test_redis_sliding_window_store_live_if_available():
    """[REAL INFRASTRUCTURE] Verify RedisRateLimitStore executes atomic Lua script against real Redis if reachable."""
    redis_url = os.getenv("RATE_LIMIT_REDIS_URL") or os.getenv("REDIS_URL") or "redis://127.0.0.1:6379/0"
    try:
        import redis
        client = redis.Redis.from_url(redis_url, socket_timeout=1.0)
        client.ping()
    except Exception:
        pytest.skip("Local Redis instance not reachable for live Redis test")

    store = RedisRateLimitStore(redis_url=redis_url)
    test_key = f"user_test_{time.time()}"

    # Budget: 3 requests per 10s
    r1 = store.acquire(test_key, 3, 10)
    assert r1 is not None
    assert r1.allowed is True
    assert r1.remaining == 2

    r2 = store.acquire(test_key, 3, 10)
    assert r2 is not None
    assert r2.allowed is True
    assert r2.remaining == 1

    r3 = store.acquire(test_key, 3, 10)
    assert r3 is not None
    assert r3.allowed is True
    assert r3.remaining == 0

    # 4th request must be blocked
    r4 = store.acquire(test_key, 3, 10)
    assert r4 is not None
    assert r4.allowed is False
    assert r4.remaining == 0
    assert r4.retry_after > 0


def test_distributed_quota_enforcement_with_real_redis():
    """[REAL INFRASTRUCTURE] Multiple distributed workers sharing real Redis enforce single global window atomically."""
    redis_url = os.getenv("RATE_LIMIT_REDIS_URL") or os.getenv("REDIS_URL") or "redis://127.0.0.1:6379/0"
    try:
        import redis
        client = redis.Redis.from_url(redis_url, socket_timeout=1.0)
        client.ping()
    except Exception:
        pytest.skip("Local Redis instance not reachable for distributed Redis test")

    # Worker 1 and Worker 2 instances
    worker1_store = RedisRateLimitStore(redis_url=redis_url)
    worker2_store = RedisRateLimitStore(redis_url=redis_url)

    shared_key = f"shared_quota_{time.time()}"
    limit = 3
    window = 10

    # Worker 1 consumes 1 request
    w1_r1 = worker1_store.acquire(shared_key, limit, window)
    assert w1_r1 is not None and w1_r1.allowed is True and w1_r1.remaining == 2

    # Worker 2 consumes 1 request on same principal key
    w2_r1 = worker2_store.acquire(shared_key, limit, window)
    assert w2_r1 is not None and w2_r1.allowed is True and w2_r1.remaining == 1

    # Worker 1 consumes 3rd request (exhausts budget)
    w1_r2 = worker1_store.acquire(shared_key, limit, window)
    assert w1_r2 is not None and w1_r2.allowed is True and w1_r2.remaining == 0

    # Worker 2 attempts 4th request -> blocked by shared atomic Lua state
    w2_r2 = worker2_store.acquire(shared_key, limit, window)
    assert w2_r2 is not None
    assert w2_r2.allowed is False
    assert w2_r2.remaining == 0
    assert w2_r2.retry_after > 0


# ==============================================================================
# 8. Store Outages & Fail-Closed Behavior
# ==============================================================================


def test_redis_outage_activates_in_memory_fallback():
    """[MOCKED / ISOLATED] When Redis is unreachable, RateLimiter falls back to process-local store."""
    bad_config = RateLimitConfig(
        enabled=True,
        redis_url="redis://127.0.0.1:59999/0",  # Unused port -> connection failure
        fail_closed_expensive=True,
        budgets={
            RateLimitCategory.READ: RateLimitBudget(requests=3, window_seconds=60),
            RateLimitCategory.AI: RateLimitBudget(requests=2, window_seconds=60),
        },
    )
    limiter = RateLimiter(config=bad_config)

    # Read requests should still be bounded by in-memory fallback
    res1 = limiter.evaluate("failover:read:key", RateLimitCategory.READ)
    assert res1.allowed is True
    assert res1.remaining == 2

    res2 = limiter.evaluate("failover:read:key", RateLimitCategory.READ)
    assert res2.allowed is True
    assert res2.remaining == 1

    res3 = limiter.evaluate("failover:read:key", RateLimitCategory.READ)
    assert res3.allowed is True
    assert res3.remaining == 0

    # 4th request rejected
    res4 = limiter.evaluate("failover:read:key", RateLimitCategory.READ)
    assert res4.allowed is False


def test_fail_closed_for_expensive_ai_when_storage_unreachable():
    """[MOCKED / ISOLATED] Expensive AI operations fail-closed if both stores are exhausted or fail-closed configured."""
    config = RateLimitConfig(
        enabled=True,
        redis_url="redis://127.0.0.1:59999/0",
        fail_closed_expensive=True,
        budgets={
            RateLimitCategory.AI: RateLimitBudget(requests=1, window_seconds=60),
        },
    )
    limiter = RateLimiter(config=config)
    # Simulate fallback store returning None (exhaustion or failure)
    with patch.object(limiter.fallback_store, "acquire", return_value=None):
        res = limiter.evaluate("fail_closed:ai:key", RateLimitCategory.AI)
        assert res.allowed is False  # Never silently unlimited for AI
        assert res.retry_after > 0


def test_expensive_endpoints_fail_closed_when_redis_unavailable_and_fallback_exhausted():
    """[MOCKED / ISOLATED] Verify expensive AI & Response operations fail-closed when Redis is down AND fallback is exhausted."""
    config = RateLimitConfig(
        enabled=True,
        redis_url="redis://127.0.0.1:59999/0",  # Offline Redis
        fail_closed_expensive=True,
        budgets={
            RateLimitCategory.AI: RateLimitBudget(requests=2, window_seconds=60),
            RateLimitCategory.RESPONSE: RateLimitBudget(requests=2, window_seconds=60),
            RateLimitCategory.READ: RateLimitBudget(requests=5, window_seconds=60),
        },
    )
    limiter = RateLimiter(config=config)
    # Simulate memory store exhausted
    limiter.fallback_store.set_exhausted(True)

    # 1. Expensive AI operation must fail closed (allowed=False)
    ai_res = limiter.evaluate("exhausted:ai:principal", RateLimitCategory.AI)
    assert ai_res.allowed is False
    assert ai_res.remaining == 0
    assert ai_res.retry_after == 60

    # 2. Expensive Response operation must fail closed (allowed=False)
    resp_res = limiter.evaluate("exhausted:resp:principal", RateLimitCategory.RESPONSE)
    assert resp_res.allowed is False
    assert resp_res.remaining == 0
    assert resp_res.retry_after == 60

    # 3. Standard read operation fails open safely to avoid taking down entire site for reads
    read_res = limiter.evaluate("exhausted:read:principal", RateLimitCategory.READ)
    assert read_res.allowed is True


# ==============================================================================
# 9. In-Memory LRU Capacity & State Bounding
# ==============================================================================


def test_in_memory_store_lru_bounding():
    """[MOCKED / ISOLATED] In-memory rate limit store bounds memory by evicting oldest keys past max_keys."""
    bounded_store = InMemoryRateLimitStore(max_keys=5)

    for i in range(10):
        bounded_store.acquire(f"user_key_{i}", limit=10, window_seconds=60)

    # Size must never exceed 5
    assert len(bounded_store._store) == 5
    # Oldest keys (0, 1, 2, 3, 4) should have been evicted
    assert "user_key_0" not in bounded_store._store
    assert "user_key_9" in bounded_store._store


# ==============================================================================
# 10. Incident Isolation & Live Response Safety Invariant
# ==============================================================================


def test_rate_limiting_does_not_bypass_authorization(client: TestClient):
    """[MOCKED / ISOLATED] Rate limiter does not grant access to unauthenticated endpoints requiring auth."""
    # Attempt to access protected endpoint without credentials
    resp = client.get("/api/v1/incidents/protected-incident-id")
    # Must be 401 or 403, never 200
    assert resp.status_code in (401, 403, 404)
    # No sensitive data leak in error envelope
    assert "secret" not in resp.text.lower()


def test_live_response_disabled_invariant_strictly_preserved():
    """[MOCKED / ISOLATED] Verify LIVE_RESPONSE_DISABLED=true remains enforced at the execution boundary."""
    manager = ResponseManager(live_response_disabled=True)
    assert manager.live_response_disabled is True

    # When live_response_disabled=True, live actions (dry_run=False) transition to BLOCKED_SAFETY
    class MockProposal:
        id = "prop-test-01"
        incident_id = "inc-test-01"
        state = "APPROVED"
        expires_at = None
        action_type = "isolate_host"
        risk = "Tier 2"
        action_payload_hash = "mock_hash"

    class MockSession:
        def __init__(self):
            self.calls = 0

        def execute(self, query):
            self.calls += 1
            call_num = self.calls

            class Result:
                def scalar_one_or_none(self):
                    if call_num == 1:
                        return MockProposal()
                    return None

                def scalars(self):
                    class Scalars:
                        def first(self):
                            return None
                    return Scalars()

            return Result()

        def commit(self):
            pass

        def add(self, item):
            pass

        def refresh(self, item):
            pass

    req = ExecuteActionRequest(dry_run=False, expected_payload_hash="mock_hash")
    res = manager.execute_action(
        proposal_id="prop-test-01",
        request=req,
        actor_id="analyst-lead",
        db_session=MockSession(),  # type: ignore[arg-type]
    )
    assert res["state"] == "BLOCKED_SAFETY"
    assert "LIVE_RESPONSE_DISABLED=true enforced" in res["result"]["safety_barrier"]


# ==============================================================================
# 11. Storage Failure, Auto-Recovery, and Multi-Worker Safe Policy (Task D)
# ==============================================================================


def test_redis_dynamic_disconnect_and_auto_recovery():
    """[MOCKED / ISOLATED] Verify RedisRateLimitStore detects disconnection and auto-recovers when Redis returns."""
    mock_redis = MagicMock()
    mock_script = MagicMock()

    # Call 1: Success (returns allowed=1, remaining=2, retry=0, reset=now+60)
    # Call 2: Disconnection exception
    # Call 3: Success after recovery
    mock_script.side_effect = [
        [1, 2, 0, time.time() + 60],
        RuntimeError("Connection lost to Redis master"),
        [1, 1, 0, time.time() + 60],
    ]
    mock_redis.register_script.return_value = mock_script
    mock_redis.ping.return_value = True

    store = RedisRateLimitStore(redis_url="redis://mock:6379/0", client=mock_redis)
    assert store._is_connected is True

    # 1. Normal evaluation
    r1 = store.acquire("recovery:test:key", 3, 60)
    assert r1 is not None and r1.allowed is True

    # 2. Redis failure occurs during acquire
    r2 = store.acquire("recovery:test:key", 3, 60)
    assert r2 is None  # Handled safely, marked disconnected
    assert store._is_connected is False

    # Advance time past 1-second debounce for auto-reconnect
    store._last_reconnect_attempt = time.time() - 2.0

    # 3. Redis returns
    r3 = store.acquire("recovery:test:key", 3, 60)
    assert r3 is not None and r3.allowed is True
    assert store._is_connected is True


def test_expensive_operations_fail_closed_immediately_when_shared_redis_fails():
    """[MOCKED / ISOLATED] When primary Redis fails, expensive operations fail-closed immediately to prevent multi-worker quota drift."""
    failing_redis = MagicMock()
    failing_redis.register_script.side_effect = RuntimeError("Redis cluster unreachable")
    failing_redis.ping.side_effect = RuntimeError("Redis cluster unreachable")

    config = RateLimitConfig(
        enabled=True,
        redis_url="redis://failing:6379/0",
        fail_closed_expensive=True,
        budgets={
            RateLimitCategory.AI: RateLimitBudget(requests=5, window_seconds=60),
            RateLimitCategory.BENCHMARK: RateLimitBudget(requests=5, window_seconds=60),
            RateLimitCategory.RESPONSE: RateLimitBudget(requests=5, window_seconds=60),
            RateLimitCategory.READ: RateLimitBudget(requests=10, window_seconds=60),
        },
    )
    primary_store = RedisRateLimitStore(redis_url="redis://failing:6379/0", client=failing_redis)
    fallback_store = InMemoryRateLimitStore()

    limiter = RateLimiter(
        config=config,
        primary_store=primary_store,
        fallback_store=fallback_store,
    )

    # 1. Expensive AI operation fails closed immediately (never delegated to local worker store)
    ai_result = limiter.evaluate("principal:ai:test", RateLimitCategory.AI)
    assert ai_result.allowed is False
    assert ai_result.remaining == 0
    assert ai_result.retry_after == 60

    # 2. Expensive Benchmark operation fails closed immediately
    bench_result = limiter.evaluate("principal:bench:test", RateLimitCategory.BENCHMARK)
    assert bench_result.allowed is False
    assert bench_result.remaining == 0

    # 3. Expensive Response operation fails closed immediately
    resp_result = limiter.evaluate("principal:resp:test", RateLimitCategory.RESPONSE)
    assert resp_result.allowed is False
    assert resp_result.remaining == 0

    # 4. Standard read traffic safely falls back to local store and remains available
    read_result = limiter.evaluate("principal:read:test", RateLimitCategory.READ)
    assert read_result.allowed is True
    assert read_result.remaining == 9


def test_fallback_store_exception_safety():
    """[MOCKED / ISOLATED] Exceptions in fallback storage backend are caught safely and do not crash the request."""
    config = RateLimitConfig(
        enabled=True,
        redis_url=None,  # No primary store
        fail_closed_expensive=True,
        budgets={
            RateLimitCategory.AI: RateLimitBudget(requests=2, window_seconds=60),
            RateLimitCategory.READ: RateLimitBudget(requests=5, window_seconds=60),
        },
    )
    mock_fallback = MagicMock()
    mock_fallback.acquire.side_effect = RuntimeError("Fatal memory corrupted in store")

    limiter = RateLimiter(config=config, fallback_store=mock_fallback)

    # Expensive AI operation fails closed safely
    ai_res = limiter.evaluate("key:ai:err", RateLimitCategory.AI)
    assert ai_res.allowed is False
    assert ai_res.retry_after == 60

    # Standard read fails open safely
    read_res = limiter.evaluate("key:read:err", RateLimitCategory.READ)
    assert read_res.allowed is True


def test_in_memory_store_reject_on_capacity():
    """[MOCKED / ISOLATED] When reject_on_capacity=True, new keys exceeding max_keys are rejected (return None)."""
    store = InMemoryRateLimitStore(max_keys=2, reject_on_capacity=True)

    r1 = store.acquire("key_1", 5, 60)
    assert r1 is not None and r1.allowed is True

    r2 = store.acquire("key_2", 5, 60)
    assert r2 is not None and r2.allowed is True

    # 3rd distinct key exceeds max_keys and reject_on_capacity is True
    r3 = store.acquire("key_3", 5, 60)
    assert r3 is None
