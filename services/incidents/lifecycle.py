"""CyberSentinel AI — Incident Lifecycle State Machine (ADR-0001)
Enforces authoritative 11-state transition rules, optimistic locking, and audit logging.
Governing Decisions: ADR-0001, ADR-0004, ADR-0006, CSAI-P4-CORRELATION
"""

import logging
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from sqlalchemy.orm import Session

from packages.common import utc_now
from packages.observability.metrics import metrics
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.incidents import BaseIncidentManager, IncidentTransitionRequest
from services.persistence.models import AuditEvent, Incident

logger = logging.getLogger("cybersentinel.incidents.lifecycle")


class InvalidIncidentTransitionError(Exception):
    """Raised when an illegal or unauthorized incident state transition is attempted."""

    pass


class IncidentConcurrencyError(Exception):
    """Raised when an incident update encounters a version conflict (optimistic lock)."""

    pass


# Authoritative transition graph defined in ADR-0001
VALID_TRANSITIONS: Dict[IncidentStateEnum, Set[IncidentStateEnum]] = {
    IncidentStateEnum.NEW: {
        IncidentStateEnum.TRIAGE,
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.TRIAGE: {
        IncidentStateEnum.INVESTIGATING,
        IncidentStateEnum.BENIGN,
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.INVESTIGATING: {
        IncidentStateEnum.CONFIRMED,
        IncidentStateEnum.BENIGN,
        IncidentStateEnum.TRIAGE,
    },
    IncidentStateEnum.CONFIRMED: {
        IncidentStateEnum.AWAITING_APPROVAL,
        IncidentStateEnum.CONTAINMENT,
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.BENIGN: {
        IncidentStateEnum.CLOSED,
        IncidentStateEnum.REOPENED,
    },
    IncidentStateEnum.AWAITING_APPROVAL: {
        IncidentStateEnum.CONTAINMENT,
        IncidentStateEnum.INVESTIGATING,
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.CONTAINMENT: {
        IncidentStateEnum.ERADICATION,
        IncidentStateEnum.INVESTIGATING,
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.ERADICATION: {
        IncidentStateEnum.RECOVERY,
        IncidentStateEnum.CONTAINMENT,
    },
    IncidentStateEnum.RECOVERY: {
        IncidentStateEnum.CLOSED,
        IncidentStateEnum.INVESTIGATING,
    },
    IncidentStateEnum.CLOSED: {
        IncidentStateEnum.REOPENED,
        IncidentStateEnum.LESSONS_LEARNED,
    },
    IncidentStateEnum.LESSONS_LEARNED: {
        IncidentStateEnum.CLOSED,
    },
    IncidentStateEnum.REOPENED: {
        IncidentStateEnum.TRIAGE,
        IncidentStateEnum.INVESTIGATING,
    },
}

# Role permissions required for specific sensitive transitions
SENSITIVE_TRANSITION_ROLES: Dict[IncidentStateEnum, List[RBACRoleEnum]] = {
    IncidentStateEnum.CONTAINMENT: [
        RBACRoleEnum.SOC_MANAGER,
        RBACRoleEnum.SECURITY_ENGINEER,
        RBACRoleEnum.ADMIN,
    ],
    IncidentStateEnum.ERADICATION: [
        RBACRoleEnum.SOC_MANAGER,
        RBACRoleEnum.SECURITY_ENGINEER,
        RBACRoleEnum.ADMIN,
    ],
    IncidentStateEnum.CLOSED: [
        RBACRoleEnum.SOC_ANALYST,
        RBACRoleEnum.SOC_MANAGER,
        RBACRoleEnum.ADMIN,
    ],
    IncidentStateEnum.REOPENED: [
        RBACRoleEnum.SOC_ANALYST,
        RBACRoleEnum.SOC_MANAGER,
        RBACRoleEnum.ADMIN,
    ],
    IncidentStateEnum.LESSONS_LEARNED: [
        RBACRoleEnum.SOC_ANALYST,
        RBACRoleEnum.SOC_MANAGER,
        RBACRoleEnum.ADMIN,
    ],
}


class IncidentLifecycleManager(BaseIncidentManager):
    """Enforces the authoritative 11-state incident lifecycle state machine."""

    @staticmethod
    def is_transition_allowed(from_state: IncidentStateEnum, to_state: IncidentStateEnum) -> bool:
        """Check if transition between states exists in ADR-0001 graph."""
        allowed = VALID_TRANSITIONS.get(from_state, set())
        return to_state in allowed

    def transition_state(
        self,
        request: IncidentTransitionRequest,
        db_session: Session,
        actor_roles: Optional[List[RBACRoleEnum]] = None,
        expected_version: Optional[int] = None,
    ) -> Incident:
        """Validate, authorize, and execute an incident state transition with audit trail."""
        # 1. Fetch target incident
        incident = db_session.get(Incident, request.incident_id)
        if not incident:
            metrics.inc_counter("incident_transition_errors_total")
            raise InvalidIncidentTransitionError(f"Incident '{request.incident_id}' not found")

        current_state = IncidentStateEnum(incident.status)

        # 2. Check from_state precondition
        if current_state != request.from_state:
            metrics.inc_counter("incident_transition_errors_total")
            raise InvalidIncidentTransitionError(
                f"Incident '{request.incident_id}' current state is '{current_state.value}', "
                f"expected '{request.from_state.value}'"
            )

        # 3. Check transition validity in state graph
        if not self.is_transition_allowed(current_state, request.to_state):
            metrics.inc_counter("incident_transition_errors_total")
            raise InvalidIncidentTransitionError(
                f"Illegal transition from '{current_state.value}' to '{request.to_state.value}' "
                f"violates ADR-0001 state machine"
            )

        # 4. Check RBAC permissions for sensitive states
        if request.to_state in SENSITIVE_TRANSITION_ROLES:
            required_roles = SENSITIVE_TRANSITION_ROLES[request.to_state]
            if actor_roles is not None:
                has_permission = any(
                    r in required_roles or r == RBACRoleEnum.ADMIN for r in actor_roles
                )
                if not has_permission:
                    metrics.inc_counter("incident_transition_errors_total")
                    raise PermissionError(
                        f"Actor lacks required role for transition to '{request.to_state.value}'. "
                        f"Required roles: {[r.value for r in required_roles]}"
                    )

        # 5. Optimistic concurrency check
        if expected_version is not None and incident.version != expected_version:
            metrics.inc_counter("incident_transition_errors_total")
            raise IncidentConcurrencyError(
                f"Incident '{request.incident_id}' version mismatch: expected {expected_version}, found {incident.version}"
            )

        # 6. Apply state transition
        incident.status = request.to_state.value
        incident.version += 1
        incident.updated_at = utc_now()

        # 7. Record AuditEvent
        audit_event = AuditEvent(
            id=str(uuid4()),
            actor_type="USER" if "user" in request.actor_id.lower() or "analyst" in request.actor_id.lower() else "AGENT",
            actor_id=request.actor_id,
            action="incident:transition",
            object_type="incident",
            object_id=incident.id,
            outcome="SUCCESS",
            reason_code=request.to_state.value,
            occurred_at=utc_now(),
            metadata_redacted={
                "from_state": current_state.value,
                "to_state": request.to_state.value,
                "reason": request.reason,
                "version": incident.version,
            },
        )
        db_session.add(audit_event)

        try:
            db_session.commit()
            metrics.inc_counter("incident_transitions_total")
            logger.info(
                "Incident '%s' transitioned: %s -> %s by %s",
                incident.id,
                current_state.value,
                request.to_state.value,
                request.actor_id,
            )
            return incident
        except Exception as ex:
            db_session.rollback()
            metrics.inc_counter("incident_transition_errors_total")
            logger.error("Failed to commit incident transition for '%s': %s", incident.id, ex)
            raise

    def transition(
        self,
        session: Session,
        incident_id: str,
        to_state: IncidentStateEnum,
        operator: Any,
        expected_version: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> Incident:
        """Convenience method providing a unified transition interface for API and services."""
        inc = session.get(Incident, incident_id)
        if not inc:
            metrics.inc_counter("incident_transition_errors_total")
            raise InvalidIncidentTransitionError(f"Incident '{incident_id}' not found")
        from_state = IncidentStateEnum(inc.status)
        req = IncidentTransitionRequest(
            incident_id=incident_id,
            from_state=from_state,
            to_state=to_state,
            actor_id=getattr(operator, "id", getattr(operator, "sub", str(operator))),
            reason=reason or "State transition",
        )
        roles = getattr(operator, "roles", None)
        return self.transition_state(
            request=req,
            db_session=session,
            actor_roles=roles,
            expected_version=expected_version,
        )



lifecycle_manager = IncidentLifecycleManager()
