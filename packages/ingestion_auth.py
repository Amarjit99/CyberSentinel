"""HMAC authentication for telemetry connector requests."""

import hashlib
import hmac
import os
import time


def source_auth_required() -> bool:
    """Return whether production connector authentication is required."""
    is_test = "PYTEST_CURRENT_TEST" in os.environ or os.getenv("TESTING") == "1"
    default = "false" if is_test else "true"
    return os.getenv("INGESTION_SOURCE_AUTH_REQUIRED", default).lower() in ("true", "1")


def verify_source_signature(
    body: bytes,
    source_id: str | None,
    timestamp: str | None,
    signature: str | None,
    secret: str | None = None,
    now: float | None = None,
) -> bool:
    """Verify timestamped HMAC-SHA256 signature for an exact request body."""
    if not source_id or not timestamp or not signature:
        return False
    try:
        request_time = int(timestamp)
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - request_time) > 300:
        return False
    signing_secret = secret or os.getenv("INGESTION_SOURCE_AUTH_SECRET")
    if not signing_secret:
        return False
    message = f"{source_id}.{timestamp}.".encode("utf-8") + body
    expected = hmac.new(
        signing_secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature.removeprefix("sha256="))


__all__ = ["source_auth_required", "verify_source_signature"]
