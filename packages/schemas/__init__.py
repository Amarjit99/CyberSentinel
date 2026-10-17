"""CyberSentinel AI — Canonical Shared Schemas Package

This package exposes the canonical data contracts for CyberSentinel AI.
In accordance with the Phase 1 layout reconciliation plan, the canonical
model implementations reside in `schemas/`, and this package provides
typed compatibility re-exports to maintain single-source-of-truth semantics.
"""

from schemas.api_contracts import (
    ErrorDetail,
    ErrorEnvelope,
    EventIngestRequest,
    EventIngestResponse,
    HealthResponse,
    PaginatedResponse,
    PaginationMeta,
    ReadinessResponse,
)
from schemas.canonical_event import CanonicalEvent
from schemas.enums import (
    AgentIdEnum,
    ErrorCodeEnum,
    EventSeverityEnum,
    IncidentStateEnum,
    RBACRoleEnum,
    ResponseRiskTierEnum,
)

__all__ = [
    "CanonicalEvent",
    "IncidentStateEnum",
    "RBACRoleEnum",
    "AgentIdEnum",
    "ResponseRiskTierEnum",
    "EventSeverityEnum",
    "ErrorCodeEnum",
    "HealthResponse",
    "ReadinessResponse",
    "EventIngestRequest",
    "EventIngestResponse",
    "ErrorEnvelope",
    "ErrorDetail",
    "PaginationMeta",
    "PaginatedResponse",
]
