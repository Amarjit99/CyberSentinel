"""CyberSentinel AI — Common Lightweight Utilities"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def compute_sha256(data: str | bytes) -> str:
    """Compute hex-encoded SHA-256 digest of input."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of a JSON-serializable dictionary."""
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return compute_sha256(canonical_json)


def sanitize_raw_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize dictionary to mask passwords, tokens, API keys, and secrets."""
    sanitized: Dict[str, Any] = {}
    sensitive_keys = {
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
        "access_token",
        "refresh_token",
    }

    for k, v in payload.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in sensitive_keys):
            sanitized[k] = "********"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_raw_payload(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_raw_payload(item) if isinstance(item, dict) else item for item in v
            ]
        else:
            sanitized[k] = v

    return sanitized


__all__ = ["utc_now", "compute_sha256", "compute_payload_hash", "sanitize_raw_payload"]
