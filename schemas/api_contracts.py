"""CyberSentinel AI — Phase 1 API Request and Response Contracts
Governing Decisions: ADR-0005, ADR-0007, and docs/17-API-SPECIFICATION.md
"""

from datetime import datetime, timezone
from typing import Dict, Generic, List, Optional, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from schemas.canonical_event import CanonicalEvent
from schemas.enums import ErrorCodeEnum

T = TypeVar("T")


class HealthResponse(BaseModel):
    """System health check response."""

    status: str = Field(
        default="healthy", description="Overall health state (healthy, degraded, unhealthy)"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = Field(default="0.1.0", description="Application service version")
    checks: Dict[str, str] = Field(
        default_factory=lambda: {"database": "connected", "ingestion": "active"}
    )


class ReadinessResponse(BaseModel):
    """System readiness check response for traffic routing."""

    ready: bool = Field(default=True, description="True if service is ready to receive traffic")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dependencies: Dict[str, bool] = Field(default_factory=lambda: {"database": True})


class EventIngestRequest(BaseModel):
    """Batch or single event ingestion payload."""

    model_config = ConfigDict(extra="forbid")

    client_id: Optional[str] = Field(
        default=None, max_length=128, description="Identifier of the ingestion client/connector"
    )
    events: List[CanonicalEvent] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of normalized canonical telemetry events",
    )


class EventIngestResponse(BaseModel):
    """Acknowledgement response for accepted and quarantined events."""

    accepted_count: int = Field(..., ge=0, description="Number of events successfully ingested")
    quarantined_count: int = Field(
        default=0,
        ge=0,
        description="Number of events routed to quarantine due to validation issues",
    )
    event_ids: List[UUID] = Field(default_factory=list, description="List of accepted event UUIDs")
    correlation_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Trace correlation identifier for the batch",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ErrorDetail(BaseModel):
    """Granular error message without leaking stack traces or internal secrets."""

    field: Optional[str] = Field(default=None, description="Affected field or property path")
    issue: str = Field(..., description="Description of the constraint violation or error")


class ErrorEnvelope(BaseModel):
    """Standardized error envelope returned on all non-2xx API responses."""

    error_code: ErrorCodeEnum = Field(..., description="Machine-readable error enum")
    message: str = Field(..., description="Human-readable error summary")
    request_id: str = Field(..., description="Unique request tracing identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Optional[List[ErrorDetail]] = Field(
        default=None, description="Optional list of specific field violations"
    )


class PaginationMeta(BaseModel):
    """Pagination metadata for collection resources."""

    page: int = Field(..., ge=1, description="Current page number (1-indexed)")
    page_size: int = Field(..., ge=1, le=500, description="Number of items per page")
    total_items: int = Field(..., ge=0, description="Total count of items across all pages")
    total_pages: int = Field(..., ge=0, description="Total number of pages")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic envelope for paginated collection responses."""

    data: List[T] = Field(default_factory=list, description="Page of items")
    meta: PaginationMeta = Field(..., description="Pagination metadata")
