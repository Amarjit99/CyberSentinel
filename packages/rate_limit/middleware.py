"""CyberSentinel AI — Rate Limiting & Abuse Protection Middleware (CSAI-SEC-API-RATE-LIMIT)

Applies server-controlled rate limits by verified principal and endpoint category,
enforces request payload size limits, and sanitizes proxy IPs safely.
"""

import posixpath
from datetime import datetime, timezone
from typing import Optional, cast
from uuid import uuid4

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from packages.auth import get_current_principal
from packages.rate_limit.config import RateLimitCategory, RateLimitConfig
from packages.rate_limit.ip import get_safe_client_ip
from packages.rate_limit.limiter import RateLimiter
from schemas.api_contracts import ErrorEnvelope
from schemas.enums import ErrorCodeEnum


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware enforcing category-based bounded rate limiting."""

    def __init__(
        self,
        app,
        limiter: Optional[RateLimiter] = None,
        config: Optional[RateLimitConfig] = None,
    ) -> None:
        super().__init__(app)
        self.config = config or RateLimitConfig.from_env()
        self.limiter = limiter or RateLimiter(config=self.config)

    def _classify_endpoint(self, method: str, normalized_path: str) -> RateLimitCategory:
        """Categorize incoming requests based on path and HTTP method."""
        # Public health and documentation
        if normalized_path in ("/health", "/ready", "/docs", "/redoc", "/openapi.json"):
            return RateLimitCategory.AUTH
        if normalized_path.startswith("/api/v1/auth"):
            return RateLimitCategory.AUTH

        # Category D: Benchmarking & Detection Engineering (Heavy AST / evaluation runs)
        if normalized_path.startswith("/api/v1/benchmarks") and method == "POST":
            return RateLimitCategory.BENCHMARK
        if normalized_path.startswith("/api/v1/detection") and method == "POST":
            return RateLimitCategory.BENCHMARK

        # Category C: Expensive AI Operations (Triage, Investigation, Tool Execution, RAG, Orchestration, Risk Assessment)
        if method == "POST":
            if (
                normalized_path.endswith("/triage")
                or normalized_path.endswith("/investigations")
                or normalized_path.endswith("/tools/execute")
                or (
                    normalized_path.startswith("/api/v1/investigations/")
                    and normalized_path.endswith("/continue")
                )
                or normalized_path.startswith("/api/v1/orchestrator/")
                or normalized_path == "/api/v1/rag/query"
                or normalized_path == "/api/v1/hunting/jobs"
                or normalized_path.endswith("/risk-assessment")
            ):
                return RateLimitCategory.AI

        # Category E: Response Governance (Proposals, Dual Approvals, Execution Gating)
        if method == "POST":
            if (
                "/proposals" in normalized_path
                or normalized_path.startswith("/api/v1/response-actions")
            ):
                return RateLimitCategory.RESPONSE

        # Category Ingestion: Telemetry ingestion pipeline and quarantine replay
        if method == "POST" and (
            normalized_path == "/api/v1/events"
            or "/quarantine" in normalized_path
        ):
            return RateLimitCategory.INGESTION

        # Category B: High-volume Read APIs
        if method in ("GET", "HEAD") and normalized_path.startswith("/api/v1/"):
            return RateLimitCategory.READ

        return RateLimitCategory.GENERAL

    async def dispatch(self, request: Request, call_next) -> Response:
        config = getattr(request.app.state, "rate_limit_config", None) or self.config
        limiter = getattr(request.app.state, "rate_limiter", None) or self.limiter

        if not config.enabled:
            return cast(Response, await call_next(request))

        request_id = getattr(request.state, "request_id", None) or request.headers.get(
            "X-Request-ID", str(uuid4())
        )

        # 1. Request Body Size Abuse Protection
        content_length_header = request.headers.get("content-length")
        if content_length_header:
            try:
                content_length = int(content_length_header)
                if content_length > config.max_request_body_bytes:
                    envelope = ErrorEnvelope(
                        error_code=ErrorCodeEnum.INVALID_SCHEMA,
                        message=(
                            f"Request payload size ({content_length} bytes) exceeds maximum "
                            f"allowed limit of {config.max_request_body_bytes} bytes."
                        ),
                        request_id=request_id,
                        timestamp=datetime.now(timezone.utc),
                    )
                    return JSONResponse(
                        status_code=413,
                        content=envelope.model_dump(mode="json"),
                        headers={"X-Request-ID": request_id},
                    )
            except ValueError:
                pass
        elif request.method in ("POST", "PUT", "PATCH"):
            # Chunked or streamed transfer without Content-Length: wrap receive to bound streaming payload
            original_receive = request._receive
            received_bytes = 0

            async def bounded_receive():
                nonlocal received_bytes
                message = await original_receive()
                if message["type"] == "http.request":
                    body = message.get("body", b"")
                    received_bytes += len(body)
                    if received_bytes > config.max_request_body_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail=(
                                f"Streaming request payload size ({received_bytes} bytes) exceeds maximum "
                                f"allowed limit of {config.max_request_body_bytes} bytes."
                            ),
                        )
                return message

            request._receive = bounded_receive

        # 2. Path Normalization (prevents // or /../ or ;matrix route alias bypasses)
        raw_path = "/".join(segment.split(";")[0] for segment in request.url.path.split("/"))
        normalized_path = posixpath.normpath(raw_path).rstrip("/").lower()
        if not normalized_path:
            normalized_path = "/"
        method = request.method.upper()

        category = self._classify_endpoint(method, normalized_path)

        # 3. Server-controlled Identity Resolution (prevents role header or query parameter spoofing)
        principal_id: Optional[str] = None
        auth_hdr = request.headers.get("Authorization")
        api_key_hdr = request.headers.get("X-API-Key")

        if auth_hdr or api_key_hdr:
            try:
                # Validate genuine cryptographic credentials or API keys
                principal = get_current_principal(
                    authorization=auth_hdr,
                    x_api_key=api_key_hdr,
                )
                principal_id = principal.id
            except Exception:
                # If credentials fail verification, principal is unauthenticated
                principal_id = None

        if principal_id:
            rate_key = f"rl:{category.value}:u:{principal_id}"
        else:
            safe_ip = get_safe_client_ip(request, config.trusted_proxies)
            rate_key = f"rl:{category.value}:ip:{safe_ip}"

        # 4. Quota Evaluation
        result = limiter.evaluate(key=rate_key, category=category)

        if not result.allowed:
            envelope = ErrorEnvelope(
                error_code=ErrorCodeEnum.RATE_LIMIT_EXCEEDED,
                message=(
                    f"Rate limit exceeded for endpoint category '{category.value}'. "
                    f"Retry after {result.retry_after} seconds."
                ),
                request_id=request_id,
                timestamp=datetime.now(timezone.utc),
            )
            return JSONResponse(
                status_code=429,
                content=envelope.model_dump(mode="json"),
                headers={
                    "X-Request-ID": request_id,
                    "Retry-After": str(result.retry_after),
                    "X-RateLimit-Limit": str(result.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(result.reset_epoch)),
                },
            )

        # 5. Execute Request & Attach Telemetry Headers
        response = cast(Response, await call_next(request))
        response.headers["X-RateLimit-Limit"] = str(result.limit)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(int(result.reset_epoch))
        return response
