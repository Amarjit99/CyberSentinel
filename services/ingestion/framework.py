"""CyberSentinel AI — Production Connector Framework

Provides the base abstraction, lifecycle management, error classification,
backpressure control, and metric tracking for all telemetry adapters.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from packages.common import utc_now


class ConnectorStatus(str, Enum):
    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    DEGRADED = "DEGRADED"


class ErrorClassification(str, Enum):
    TRANSIENT = "TRANSIENT"  # Retryable (e.g., socket timeout, rate-limited, temporary I/O)
    PERMANENT = "PERMANENT"  # Non-retryable (e.g., malformed record, auth failure, bad schema)


class IngestionException(Exception):
    """Structured exception carrying failure classification and source context."""

    def __init__(
        self,
        message: str,
        error_code: str = "INGEST_ERROR",
        classification: ErrorClassification = ErrorClassification.PERMANENT,
        source_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.classification = classification
        self.source_id = source_id
        self.details = details or {}

    @property
    def is_retryable(self) -> bool:
        return self.classification == ErrorClassification.TRANSIENT


class ConnectorConfig(BaseModel):
    """Configuration contract for telemetry connectors."""

    connector_id: str = Field(..., description="Unique connector identifier")
    name: str = Field(..., description="Descriptive connector name")
    source_type: str = Field(
        ..., description="Telemetry source type (syslog, cloudtrail, zeek, endpoint)"
    )
    enabled: bool = Field(default=True, description="Whether connector is actively collecting")
    batch_size: int = Field(default=100, ge=1, le=10000, description="Maximum batch size per fetch")
    timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0, description="I/O timeout limit")
    max_retries: int = Field(
        default=3, ge=0, le=10, description="Maximum retry attempts on transient failures"
    )
    retry_backoff_seconds: float = Field(
        default=0.5, ge=0.05, le=30.0, description="Exponential backoff base"
    )
    buffer_capacity: int = Field(
        default=1000, ge=1, le=100000, description="Internal bounded buffer size"
    )


class ConnectorMetrics(BaseModel):
    """Runtime telemetry metrics per connector."""

    events_received: int = 0
    events_emitted: int = 0
    errors_transient: int = 0
    errors_permanent: int = 0
    buffer_usage: int = 0
    last_active: Optional[str] = None


class BaseConnector(ABC):
    """Abstract connector contract supporting lifecycle, backpressure, and metrics."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        self.status = ConnectorStatus.INITIALIZED
        self.metrics = ConnectorMetrics()
        self._buffer: List[Dict[str, Any]] = []

    def start(self) -> None:
        """Initialize resources and transition connector to RUNNING state."""
        if not self.config.enabled:
            self.status = ConnectorStatus.STOPPED
            return
        self.status = ConnectorStatus.RUNNING
        self.metrics.last_active = utc_now().isoformat()

    def stop(self) -> None:
        """Gracefully release resources and flush internal buffers."""
        self.status = ConnectorStatus.STOPPED
        self._buffer.clear()
        self.metrics.buffer_usage = 0

    def health_check(self) -> Dict[str, Any]:
        """Report component health, current status, and capacity metrics."""
        return {
            "connector_id": self.config.connector_id,
            "status": self.status.value,
            "enabled": self.config.enabled,
            "buffer_usage": len(self._buffer),
            "buffer_capacity": self.config.buffer_capacity,
            "healthy": self.status in (ConnectorStatus.RUNNING, ConnectorStatus.INITIALIZED),
            "metrics": self.metrics.model_dump(),
        }

    def buffer_event(self, event: Dict[str, Any]) -> bool:
        """Append event to internal bounded buffer with backpressure protection.

        Returns False if buffer is at full capacity (backpressure triggered).
        """
        if len(self._buffer) >= self.config.buffer_capacity:
            self.status = ConnectorStatus.DEGRADED
            return False

        self._buffer.append(event)
        self.metrics.events_received += 1
        self.metrics.buffer_usage = len(self._buffer)
        self.metrics.last_active = utc_now().isoformat()
        return True

    def flush_batch(self, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
        """Drain up to max_items from the internal buffer."""
        limit = max_items or self.config.batch_size
        batch = self._buffer[:limit]
        self._buffer = self._buffer[limit:]
        self.metrics.events_emitted += len(batch)
        self.metrics.buffer_usage = len(self._buffer)
        if (
            self.status == ConnectorStatus.DEGRADED
            and len(self._buffer) < self.config.buffer_capacity
        ):
            self.status = ConnectorStatus.RUNNING
        return batch

    @abstractmethod
    def supported_formats(self) -> List[str]:
        """Declare supported input log formats."""
        raise NotImplementedError

    @abstractmethod
    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        """Parse source payload into standardized raw dictionary records."""
        raise NotImplementedError
