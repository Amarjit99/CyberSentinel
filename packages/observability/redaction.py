"""CyberSentinel AI — Observability Redaction & Secret Scrubbing (ADR-0005, Sprint 25)

Enforces secret scrubbing for structured logs, diagnostic messages, audit records,
and health checks to prevent credential and token leakage.
"""

import re
from typing import Any, Dict, Union

# Regex patterns for sensitive tokens and credentials
REDACTION_PATTERNS = [
    # Authorization / Bearer tokens
    (re.compile(r"Bearer\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # JWT tokens
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"), "[REDACTED_JWT_TOKEN]"),
    # API keys (OpenAI sk-, GitHub ghp-, AWS AKIA)
    (re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"), "[REDACTED_API_KEY]"),
    # Database connection strings with passwords (e.g. postgresql://user:pass@host:port/db)
    (re.compile(r"(postgres(?:ql)?|mysql|redis)://([^:]+):([^@]+)@", re.IGNORECASE), r"\1://\2:[REDACTED_CREDENTIAL]@"),
    # Key-value assignments in log messages (password=..., api_key=...)
    (re.compile(r"(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1=[REDACTED]"),
    # PEM Private Keys
    (re.compile(r"-----BEGIN\s+([A-Z\s]+)?KEY-----.*?-----END\s+([A-Z\s]+)?KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
]

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "auth",
    "private_key",
    "credential",
)


def scrub_string(text: str) -> str:
    """Scrub sensitive credentials, tokens, and passwords from a string."""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def scrub_secrets(obj: Any) -> Any:
    """Recursively scrub secrets from dictionaries, lists, strings, and scalar values."""
    if isinstance(obj, dict):
        scrubbed_dict: Dict[str, Any] = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                scrubbed_dict[k] = "[REDACTED]"
            else:
                scrubbed_dict[k] = scrub_secrets(v)
        return scrubbed_dict

    if isinstance(obj, list):
        return [scrub_secrets(item) for item in obj]

    if isinstance(obj, tuple):
        return tuple(scrub_secrets(item) for item in obj)

    if isinstance(obj, set):
        return {scrub_secrets(item) for item in obj}

    if isinstance(obj, str):
        return scrub_string(obj)

    return obj


def safe_diagnostic_message(msg_or_exc: Union[str, Exception]) -> str:
    """Sanitize an exception or diagnostic message to guarantee zero secret leakage."""
    raw = str(msg_or_exc)
    return scrub_string(raw)


__all__ = [
    "scrub_string",
    "scrub_secrets",
    "safe_diagnostic_message",
]
