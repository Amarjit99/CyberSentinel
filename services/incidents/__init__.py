"""CyberSentinel AI — Incident Management Service Boundary (ADR-0001)
Manages the 11-state incident lifecycle, ownership, and audit trail.
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, CSAI-P4-CORRELATION
"""

from abc import ABC, abstractmethod
from typing import Any, Optional

from pydantic import BaseModel, Field

from schemas.enums import IncidentStateEnum


class IncidentTransitionRequest(BaseModel):
    """Request to transition incident state."""

    incident_id: str = Field(..., description="Target incident ID")
    from_state: IncidentStateEnum = Field(..., description="Expected current state")
    to_state: IncidentStateEnum = Field(..., description="Requested target state")
    actor_id: str = Field(..., description="Subject initiating transition")
    reason: Optional[str] = Field(default="State transition", description="Audit rationale for transition")
    expected_version: Optional[int] = Field(default=None, description="Optional optimistic concurrency lock")


class BaseIncidentManager(ABC):
    """Abstract interface for incident lifecycle operations."""

    @abstractmethod
    def transition_state(
        self,
        request: IncidentTransitionRequest,
        db_session: Any,
        actor_roles: Optional[list] = None,
        expected_version: Optional[int] = None,
    ) -> Any:
        """Validate and apply state transition obeying ADR-0001 state machine rules."""
        raise NotImplementedError



from services.incidents.lifecycle import (  # noqa: E402
    SENSITIVE_TRANSITION_ROLES,
    VALID_TRANSITIONS,
    IncidentConcurrencyError,
    IncidentLifecycleManager,
    InvalidIncidentTransitionError,
    lifecycle_manager,
)
from services.incidents.manager import IncidentManager, incident_manager  # noqa: E402

__all__ = [
    "IncidentTransitionRequest",
    "BaseIncidentManager",
    "VALID_TRANSITIONS",
    "SENSITIVE_TRANSITION_ROLES",
    "InvalidIncidentTransitionError",
    "IncidentConcurrencyError",
    "IncidentLifecycleManager",
    "lifecycle_manager",
    "IncidentManager",
    "incident_manager",
]
