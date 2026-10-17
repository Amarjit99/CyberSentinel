"""CyberSentinel AI — LLM Provider Interfaces & Gateway Redaction (ADR-0005, Doc 22, Sprint 15)

Manages integrations with language models, enforces Stage 2 pre-LLM redaction,
implements timeouts, budget tracking, error categorization, transient retries,
and offline deterministic fallbacks.
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type

import httpx
from pydantic import BaseModel, Field

from packages.observability.metrics import metrics
from packages.resilience.cache import SafeTTLCache

logger = logging.getLogger("cybersentinel.agents.providers")


# Stage 2 Pre-LLM Gateway Redaction Patterns (ADR-0005)
SECRET_PATTERNS = [
    (re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1: [REDACTED_PASSWORD]"),
    (re.compile(r"(api[_-]?key|secret|token|access[_-]?key)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1: [REDACTED_SECRET]"),
    (re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"), "[REDACTED_API_KEY]"),
    (re.compile(r"-----BEGIN\s+([A-Z\s]+)?KEY-----.*?-----END\s+([A-Z\s]+)?KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
]


def sanitize_for_model(text: str) -> str:
    """Pre-LLM Gateway redaction: strips credentials and sensitive tokens before model submission."""
    if not text:
        return ""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


# ==============================================================================
# Explicit Provider Error Hierarchy (Sprint 15)
# ==============================================================================

class LLMProviderError(Exception):
    """Base exception for all AI provider communication and execution failures."""


class LLMProviderUnavailableError(LLMProviderError):
    """Raised when an external LLM provider endpoint is unreachable or offline."""


class LLMProviderTimeoutError(LLMProviderError):
    """Raised when an AI provider call exceeds the configured execution deadline."""


class LLMProviderRateLimitError(LLMProviderError):
    """Raised when an AI provider returns HTTP 429 Too Many Requests or quota exhaustion."""


class LLMProviderAuthenticationError(LLMProviderError):
    """Raised when an AI provider returns HTTP 401/403 invalid API key or permission denied."""


class LLMOutputValidationError(LLMProviderError):
    """Raised when model completion fails JSON parsing or strict schema validation."""


# ==============================================================================
# Circuit Breaker for Provider Outages & Fault Isolation (Sprint 25)
# ==============================================================================

class CircuitState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Bounded circuit breaker to isolate provider outages and suppress repetitive failures."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 30.0,
        half_open_success_threshold: int = 2,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.1, recovery_timeout_seconds)
        self.half_open_success_threshold = max(1, half_open_success_threshold)
        self.state: str = CircuitState.CLOSED
        self.failure_count: int = 0
        self.consecutive_successes: int = 0
        self.last_failure_time: float = 0.0

    def can_execute(self) -> bool:
        """Determines if requests are permitted through the circuit breaker."""
        if self.state == CircuitState.CLOSED:
            return True
        now = time.time()
        if self.state == CircuitState.OPEN:
            if now - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                self.consecutive_successes = 0
                return True
            return False
        # In HALF_OPEN, allow probe calls
        return True

    def record_success(self) -> None:
        """Record successful invocation to reset or recover circuit state."""
        if self.state == CircuitState.HALF_OPEN:
            self.consecutive_successes += 1
            if self.consecutive_successes >= self.half_open_success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.consecutive_successes = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self) -> None:
        """Record failed invocation; transitions circuit to OPEN when threshold reached."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.state == CircuitState.HALF_OPEN or self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            metrics.inc_counter("circuit_breaker_tripped_total", 1)

    def reset(self) -> None:
        """Force reset circuit breaker to normal operational state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.consecutive_successes = 0
        self.last_failure_time = 0.0


# ==============================================================================
# Provider Metadata & DTOs
# ==============================================================================

class ProviderInfo(BaseModel):
    """Metadata describing the AI provider and model utilized for inference."""

    provider_name: str = Field(..., description="Provider class or adapter name")
    model_name: str = Field(..., description="Target model reference string")
    is_available: bool = Field(default=True, description="Whether provider is verified active")
    is_fallback: bool = Field(default=False, description="True if output was generated by deterministic fallback")
    latency_ms: Optional[float] = Field(default=None, description="Request execution latency in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe diagnostics (no credentials)")


class ProviderCompletionRequest(BaseModel):
    """Typed parameters for invoking an AI completion."""

    system_prompt: str
    user_prompt: str
    target_schema: Optional[Type[BaseModel]] = None
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    max_output_tokens: int = Field(default=4096, ge=128, le=16384)
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)


class ProviderCompletionResponse(BaseModel):
    """Structured response returned by provider completion."""

    content_json: Dict[str, Any]
    provider_info: ProviderInfo
    raw_tokens_estimate: int = 0
    latency_ms: float = 0.0


# ==============================================================================
# Provider Abstract Base Class
# ==============================================================================

class BaseLLMProvider(ABC):
    """Abstract interface for LLM / SLM completion providers with safety guarantees."""

    @abstractmethod
    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        target_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: float = 30.0,
    ) -> Dict[str, Any]:
        """Generate structured JSON output conforming to the target schema."""
        raise NotImplementedError

    @abstractmethod
    def check_availability(self) -> ProviderInfo:
        """Inspect provider configuration and return health diagnostics without leaking secrets."""
        raise NotImplementedError


# ==============================================================================
# Concrete Provider Implementations
# ==============================================================================

class MockLLMProvider(BaseLLMProvider):
    """Configurable mock provider for isolated testing, failure injection, and unit tests."""

    def __init__(
        self,
        canned_response: Optional[Dict[str, Any]] = None,
        should_fail: bool = False,
        failure_exception: Optional[Exception] = None,
        model_name: str = "mock-model-v1",
    ):
        self.canned_response = canned_response or {}
        self.should_fail = should_fail
        self.failure_exception = failure_exception
        self.model_name = model_name
        self.call_count: int = 0
        self.last_prompt: Optional[str] = None
        self.last_system_prompt: Optional[str] = None

    def check_availability(self) -> ProviderInfo:
        return ProviderInfo(
            provider_name="MockLLMProvider",
            model_name=self.model_name,
            is_available=not self.should_fail,
            is_fallback=False,
            metadata={"call_count": self.call_count},
        )

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        target_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: float = 30.0,
    ) -> Dict[str, Any]:
        self.call_count += 1
        self.last_system_prompt = sanitize_for_model(system_prompt)
        self.last_prompt = sanitize_for_model(user_prompt)

        if self.should_fail:
            if self.failure_exception:
                raise self.failure_exception
            raise LLMProviderUnavailableError("Simulated LLM provider timeout / connection failure")

        if target_schema is not None and self.canned_response:
            try:
                target_schema(**self.canned_response)
            except Exception as e:
                raise LLMOutputValidationError(f"Mock response failed target schema validation: {e}") from e

        return self.canned_response


class HTTPLLMProvider(BaseLLMProvider):
    """Real HTTP client targeting OpenAI / Ollama / vLLM / Gemini compatible endpoints.

    Features:
    - Pre-LLM credential redaction.
    - Explicit error categorization (Timeout, Auth, RateLimit, Schema).
    - Bounded transient failure retries with exponential backoff.
    - Safe diagnostics without secret leakage.
    """

    MAX_RESPONSE_BYTES = 500_000

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 2,
        initial_backoff: float = 0.5,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.base_url: str = str(base_url or os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key: Optional[str] = api_key or os.getenv("LLM_API_KEY")
        self.model: str = str(model or os.getenv("LLM_MODEL") or "gpt-4o-mini")
        self.max_retries = max(0, min(max_retries, 3))
        # When running under pytest, scale down initial backoff so tests execute fast
        if "PYTEST_CURRENT_TEST" in os.environ or os.getenv("TESTING") == "1":
            self.initial_backoff = 0.01
        else:
            self.initial_backoff = max(0.05, initial_backoff)
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.cache_enabled = os.getenv("LLM_CACHE_ENABLED", "false").lower() == "true"
        self._response_cache: SafeTTLCache[Dict[str, Any]] = SafeTTLCache(
            max_entries=int(os.getenv("LLM_CACHE_MAX_ENTRIES", "128")),
            ttl_seconds=float(os.getenv("LLM_CACHE_TTL_SECONDS", "30")),
        )

    def check_availability(self) -> ProviderInfo:
        is_local = "localhost" in self.base_url or "127.0.0.1" in self.base_url
        has_auth = bool(self.api_key) or is_local
        safe_url = self.base_url.split("?")[0]
        is_available = has_auth and (self.circuit_breaker.state != CircuitState.OPEN)
        return ProviderInfo(
            provider_name="HTTPLLMProvider",
            model_name=self.model,
            is_available=is_available,
            is_fallback=False,
            metadata={
                "base_url": safe_url,
                "has_api_key": bool(self.api_key),
                "is_local_endpoint": is_local,
                "circuit_state": self.circuit_breaker.state,
            },
        )

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        target_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: float = 30.0,
    ) -> Dict[str, Any]:
        # Fail fast if circuit breaker is OPEN due to sustained outage
        if not self.circuit_breaker.can_execute():
            metrics.inc_counter("circuit_breaker_rejections_total", 1)
            raise LLMProviderUnavailableError(
                f"Circuit breaker is OPEN for {self.model}; suppressing repeated calls during provider outage."
            )

        info = self.check_availability()
        if not info.is_available:
            metrics.inc_counter("provider_auth_errors_total", 1)
            raise LLMProviderAuthenticationError(
                "External LLM API key not configured. Set LLM_API_KEY environment variable."
            )

        clean_sys = sanitize_for_model(system_prompt)
        clean_user = sanitize_for_model(user_prompt)
        cache_key = ""
        if self.cache_enabled:
            cache_key = hashlib.sha256(
                json.dumps(
                    {
                        "model": self.model,
                        "system": clean_sys,
                        "user": clean_user,
                        "schema": target_schema.__name__ if target_schema else None,
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            cached = self._response_cache.get(cache_key)
            if cached is not None:
                metrics.inc_counter("llm_cache_hits_total", 1)
                return dict(cached)
            metrics.inc_counter("llm_cache_misses_total", 1)

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": clean_sys},
                {"role": "user", "content": clean_user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        attempts = 0
        backoff = self.initial_backoff
        start_time = time.perf_counter()

        while attempts <= self.max_retries:
            attempts += 1
            try:
                async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                    res = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                    )

                # 1. Non-retryable Authentication Failure (HTTP 401/403)
                if res.status_code in (401, 403):
                    metrics.inc_counter("provider_auth_errors_total", 1)
                    raise LLMProviderAuthenticationError(f"AI Provider authentication failed (HTTP {res.status_code})")

                # 2. Rate Limiting (HTTP 429) - Retry with jitter backoff
                if res.status_code == 429:
                    metrics.inc_counter("provider_rate_limit_errors_total", 1)
                    if attempts <= self.max_retries:
                        jitter = random.uniform(0.8, 1.2)
                        sleep_time = min(backoff * jitter, 10.0)
                        logger.warning("HTTPLLMProvider rate-limited (429); retry %d/%d backing off %.2fs", attempts, self.max_retries, sleep_time)
                        metrics.inc_counter("provider_retries_total", 1)
                        await asyncio.sleep(sleep_time)
                        backoff *= 2.0
                        continue
                    self.circuit_breaker.record_failure()
                    raise LLMProviderRateLimitError("AI Provider rate limit or quota exceeded (HTTP 429)")

                # 3. Transient Gateway / Upstream Outage (HTTP 502/503/504) - Retry with jitter backoff
                if res.status_code in (502, 503, 504):
                    if attempts <= self.max_retries:
                        jitter = random.uniform(0.8, 1.2)
                        sleep_time = min(backoff * jitter, 10.0)
                        logger.warning("HTTPLLMProvider transient HTTP %d; retry %d/%d in %.2fs", res.status_code, attempts, self.max_retries, sleep_time)
                        metrics.inc_counter("provider_retries_total", 1)
                        await asyncio.sleep(sleep_time)
                        backoff *= 2.0
                        continue
                    self.circuit_breaker.record_failure()
                    raise LLMProviderUnavailableError(f"AI Provider returned transient HTTP {res.status_code} after {self.max_retries} retries")

                res.raise_for_status()

                # Guard against oversized output denial of service
                if len(res.content) > self.MAX_RESPONSE_BYTES:
                    metrics.inc_counter("provider_oversized_responses_total", 1)
                    raise LLMOutputValidationError(
                        f"AI Provider response exceeded maximum size limit ({len(res.content)} > {self.MAX_RESPONSE_BYTES} bytes)"
                    )

                data = res.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                if not isinstance(parsed, dict):
                    parsed = {"result": parsed}

                if target_schema is not None:
                    try:
                        target_schema(**parsed)
                    except Exception as ve:
                        metrics.inc_counter("provider_schema_validation_errors_total", 1)
                        raise LLMOutputValidationError(f"Model completion violated required schema: {ve}") from ve

                # Success: reset circuit breaker failure count and record latency
                self.circuit_breaker.record_success()
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                metrics.set_gauge("last_llm_provider_latency_ms", elapsed_ms)
                if self.cache_enabled:
                    self._response_cache.put(cache_key, dict(parsed))
                return parsed

            except httpx.TimeoutException as te:
                metrics.inc_counter("provider_timeout_errors_total", 1)
                if attempts <= self.max_retries:
                    jitter = random.uniform(0.8, 1.2)
                    sleep_time = min(backoff * jitter, 10.0)
                    logger.warning("HTTPLLMProvider timeout; retry %d/%d in %.2fs", attempts, self.max_retries, sleep_time)
                    metrics.inc_counter("provider_retries_total", 1)
                    await asyncio.sleep(sleep_time)
                    backoff *= 2.0
                    continue
                self.circuit_breaker.record_failure()
                raise LLMProviderTimeoutError(f"AI Provider call exceeded timeout of {timeout_seconds}s after {self.max_retries} retries: {te}") from te

            except (LLMProviderError, LLMOutputValidationError):
                raise

            except httpx.HTTPStatusError as hse:
                metrics.inc_counter("provider_errors_total", 1)
                if attempts <= self.max_retries and hse.response.status_code in (502, 503, 504):
                    jitter = random.uniform(0.8, 1.2)
                    sleep_time = min(backoff * jitter, 10.0)
                    metrics.inc_counter("provider_retries_total", 1)
                    await asyncio.sleep(sleep_time)
                    backoff *= 2.0
                    continue
                self.circuit_breaker.record_failure()
                raise LLMProviderUnavailableError(f"AI Provider returned HTTP error: {hse}") from hse

            except Exception as ex:
                metrics.inc_counter("provider_errors_total", 1)
                if attempts <= self.max_retries:
                    jitter = random.uniform(0.8, 1.2)
                    sleep_time = min(backoff * jitter, 10.0)
                    metrics.inc_counter("provider_retries_total", 1)
                    await asyncio.sleep(sleep_time)
                    backoff *= 2.0
                    continue
                self.circuit_breaker.record_failure()
                raise LLMProviderUnavailableError(f"AI Provider connection error: {ex}") from ex

        self.circuit_breaker.record_failure()
        raise LLMProviderUnavailableError(f"AI Provider failed after {self.max_retries} retries.")


class DeterministicRuleProvider(BaseLLMProvider):
    """Deterministic, offline analysis engine that reasons over incident context without external models.

    Acts as the baseline fallback engine conforming to the evidence-grounded investigation contract.
    """

    def check_availability(self) -> ProviderInfo:
        return ProviderInfo(
            provider_name="DeterministicRuleProvider",
            model_name="deterministic-rule-engine-v1",
            is_available=True,
            is_fallback=True,
            metadata={"offline_guarantee": True},
        )

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        target_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: float = 30.0,
    ) -> Dict[str, Any]:
        """Synthesizes structured investigation findings deterministically from prompt data."""
        # Detect attack themes from untrusted context safely
        text_lower = user_prompt.lower()
        is_c2 = "c2" in text_lower or "beacon" in text_lower or "t1071" in text_lower
        is_auth = "auth" in text_lower or "brute" in text_lower or "t1110" in text_lower or "credential" in text_lower
        is_exec = "exec" in text_lower or "powershell" in text_lower or "t1059" in text_lower or "process" in text_lower
        is_discovery = "discovery" in text_lower or "t1033" in text_lower

        if is_c2:
            category = "command_and_control"
            severity = "critical"
            impact = "Potential active Command and Control channel communication detected."
            steps = [
                "Isolate affected endpoint from network boundary immediately",
                "Block destination C2 IP / domain at egress firewall",
                "Capture active network socket connections and process memory dump",
            ]
        elif is_auth and is_exec:
            category = "credential_access_and_execution"
            severity = "high"
            impact = "Multi-stage attack pattern: Credential compromise followed by host process execution."
            steps = [
                "Revoke compromised user session credentials and force password reset",
                "Inspect child process tree spawned by authenticated user session",
                "Verify host integrity and check for lateral movement indicators",
            ]
        elif is_auth:
            category = "credential_access"
            severity = "high"
            impact = "Suspicious authentication anomalies indicating password spraying or brute force attack."
            steps = [
                "Review targeted account login history across identity providers",
                "Verify source IP against corporate VPN allowlists",
                "Enforce multi-factor authentication challenge on user account",
            ]
        elif is_exec:
            category = "execution"
            severity = "high"
            impact = "Suspicious command-line or script execution detected on monitored endpoint."
            steps = [
                "Inspect parent-child relationship of executing process",
                "Extract script block logs or encoded PowerShell command payloads",
                "Check for scheduled task or registry persistence mechanisms",
            ]
        elif is_discovery:
            category = "discovery"
            severity = "medium"
            impact = "Internal reconnaissance or system discovery commands executed."
            steps = [
                "Verify whether discovery commands correlate with administrative activity",
                "Monitor for subsequent credential dumping or lateral movement attempts",
            ]
        else:
            category = "general_security_alert"
            severity = "medium"
            impact = "Correlated telemetry patterns warranting tier-1 triage investigation."
            steps = [
                "Review correlated alerts and associated entities",
                "Inspect raw event timeline for anomalous sequence patterns",
            ]

        # Extract cited IDs from user_prompt
        det_matches = re.findall(r"det-[a-zA-Z0-9_\-]+", user_prompt)
        ev_matches = re.findall(r"ev-[a-zA-Z0-9_\-]+", user_prompt)
        supporting_refs = list(dict.fromkeys(det_matches + ev_matches))[:4]

        result = {
            "suspected_category": category,
            "recommended_severity": severity,
            "confidence": 0.85,
            "potential_impact": impact,
            "recommended_steps": steps,
            "supporting_evidence": supporting_refs,
            "contradictory_evidence": [],
            "missing_evidence": [
                "Full host memory dump not yet acquired",
                "Endpoint network packet captures pending review",
            ],
            "requires_analyst_review": True,
        }

        if target_schema is not None:
            try:
                target_schema(**result)
            except Exception:
                # Return dictionary as is; caller will validate or wrap
                pass

        return result


__all__ = [
    "BaseLLMProvider",
    "MockLLMProvider",
    "HTTPLLMProvider",
    "DeterministicRuleProvider",
    "CircuitBreaker",
    "CircuitState",
    "LLMProviderError",
    "LLMProviderUnavailableError",
    "LLMProviderTimeoutError",
    "LLMProviderRateLimitError",
    "LLMProviderAuthenticationError",
    "LLMOutputValidationError",
    "ProviderInfo",
    "ProviderCompletionRequest",
    "ProviderCompletionResponse",
    "sanitize_for_model",
]
