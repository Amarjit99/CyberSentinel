"""CyberSentinel AI — Observability & Telemetry Contracts"""

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from packages.observability.metrics import IngestionMetrics, metrics
from packages.observability.redaction import (
    safe_diagnostic_message,
    scrub_secrets,
    scrub_string,
)


class CorrelationContext(BaseModel):
    """Distributed tracing and request correlation context."""

    request_id: str = Field(..., description="Unique HTTP or pipeline request ID")
    trace_id: Optional[str] = Field(default=None, description="OpenTelemetry trace identifier")
    span_id: Optional[str] = Field(default=None, description="OpenTelemetry span identifier")
    actor_id: Optional[str] = Field(default=None, description="Calling user or agent ID")


class StructuredLogRecord(BaseModel):
    """Standardized JSON log record structure."""

    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    level: str = Field(..., description="Log severity level (INFO, WARN, ERROR)")
    message: str = Field(..., description="Log message text")
    logger: str = Field(..., description="Originating logger name")
    correlation: Optional[CorrelationContext] = Field(default=None, description="Request context")
    extra: Dict[str, Any] = Field(
        default_factory=dict, description="Structured key-value attributes"
    )


__all__ = [
    "CorrelationContext",
    "StructuredLogRecord",
    "IngestionMetrics",
    "metrics",
    "scrub_secrets",
    "scrub_string",
    "safe_diagnostic_message",
]

