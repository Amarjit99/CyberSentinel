"""CyberSentinel AI — Response Proposal Lifecycle & Execution Boundary (ADR-0006)

Manages proposal persistence, human approval workflow, separation-of-duties,
dual-human authorization, and safety-gated execution.
Safety Invariant: LIVE_RESPONSE_DISABLED=true is strictly enforced.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.common import sanitize_raw_payload
from packages.policy import evaluate_action_policy
from schemas.enums import IncidentStateEnum, ResponseRiskTierEnum
from services.persistence.models import (
    Approval,
    AuditEvent,
    Incident,
    ResponseAction,
    ResponseProposal,
    User,
)
from services.response.lab_adapter import (
    LabExecutionTimeoutError,
    LabResponseAdapter,
    LabTargetNotPermittedError,
    UnsupportedLabActionError,
)
from services.response.models import (
    ApprovalDecisionEnum,
    CreateProposalRequest,
    ExecuteActionRequest,
    ProposalStateEnum,
    ResponseProposalResponse,
    SubmitApprovalRequest,
)
from services.response.policy import (
    PolicyOutcomeEnum,
    compute_payload_hash,
    evaluate_proposal_policy,
    validate_approval_submission,
)

logger = logging.getLogger("cybersentinel.response.manager")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ProposalPolicyViolationError(Exception):
    """Raised when proposal generation violates policy or safety rules."""

    pass


class ProposalNotFoundError(Exception):
    """Raised when a proposal ID cannot be found."""

    pass


class ProposalExpiredError(Exception):
    """Raised when attempting to interact with an expired proposal."""

    pass


class ApprovalViolationError(Exception):
    """Raised when an approval decision violates separation-of-duties or policy."""

    pass


class ActionExecutionBlockedError(Exception):
    """Raised when action execution is blocked by safety configuration or state."""

    pass


class ResponseManager:
    """Manages the full lifecycle of response proposals and approval governance."""

    def __init__(
        self,
        live_response_disabled: bool = True,
        lab_adapter: Optional[Any] = None,
    ) -> None:
        # Mandatory safety invariant: live response execution is disabled
        self.live_response_disabled = live_response_disabled
        self.lab_adapter = lab_adapter or LabResponseAdapter()
        self._proposal_cache: Dict[str, Dict[str, Any]] = {}

    def submit_proposal(
        self,
        incident_id: str,
        request: CreateProposalRequest,
        actor_id: str,
        db_session: Session,
    ) -> ResponseProposalResponse:
        """Evaluate, formulate, and persist a structured response proposal for an incident."""
        # 1. Fetch incident
        incident = db_session.execute(
            select(Incident).where(Incident.id == incident_id)
        ).scalar_one_or_none()
        if not incident:
            raise ProposalNotFoundError(f"Incident {incident_id} not found.")

        # 2. Evaluate policy
        evaluation = evaluate_proposal_policy(incident, request)
        if not evaluation.is_eligible or evaluation.outcome == PolicyOutcomeEnum.DENY:
            reason_str = "; ".join(evaluation.reasons)
            # Record audit denial
            audit_denied = AuditEvent(
                id=str(uuid4()),
                actor_type="USER" if "user" in actor_id.lower() or "analyst" in actor_id.lower() else "AGENT",
                actor_id=actor_id,
                action="proposal:denied",
                object_type="proposal",
                object_id=incident_id,
                outcome="DENIED",
                reason_code=evaluation.outcome.value,
                occurred_at=utc_now(),
                metadata_redacted={
                    "reasons": evaluation.reasons,
                    "action_type": request.action_type,
                    "target_entity": request.target_entity,
                },
            )
            db_session.add(audit_denied)
            db_session.commit()
            raise ProposalPolicyViolationError(
                f"Policy evaluation denied proposal for action '{request.action_type}': {reason_str}"
            )

        # 3. Compute expiration & payload hash
        now = utc_now()
        expires_at = now + timedelta(minutes=request.validity_minutes)
        payload_hash = compute_payload_hash(request.action_payload)

        # Initial state:
        initial_state = ProposalStateEnum.PENDING.value

        # 4. Create ResponseProposal model
        proposal = ResponseProposal(
            id=str(uuid4()),
            incident_id=incident_id,
            action_type=request.action_type,
            action_payload_hash=payload_hash,
            risk=evaluation.risk_tier.value,
            state=initial_state,
            created_by=actor_id,
            created_at=now,
            expires_at=expires_at,
        )
        db_session.add(proposal)

        # Store in proposal cache for enrichment
        self._proposal_cache[proposal.id] = {
            "target_entity": request.target_entity,
            "reason": request.reason,
            "evidence_refs": request.evidence_refs,
            "action_payload": sanitize_raw_payload(request.action_payload),
        }

        # 5. Incident state transition: If Tier 2 or Tier 3 proposal is submitted and incident
        # is in INVESTIGATING or CONFIRMED, transition incident to AWAITING_APPROVAL per ADR-0001
        if evaluation.risk_tier in [ResponseRiskTierEnum.TIER_2, ResponseRiskTierEnum.TIER_3]:
            if incident.status in [
                IncidentStateEnum.INVESTIGATING.value,
                IncidentStateEnum.CONFIRMED.value,
            ]:
                incident.status = IncidentStateEnum.AWAITING_APPROVAL.value
                incident.version += 1
                incident.updated_at = now

        # 6. Record AuditEvent
        audit_event = AuditEvent(
            id=str(uuid4()),
            actor_type="USER" if "user" in actor_id.lower() or "analyst" in actor_id.lower() else "AGENT",
            actor_id=actor_id,
            action="proposal:create",
            object_type="proposal",
            object_id=proposal.id,
            outcome="SUCCESS",
            reason_code=request.action_type,
            occurred_at=now,
            metadata_redacted={
                "risk_tier": evaluation.risk_tier.value,
                "target_entity": request.target_entity,
                "payload_hash": payload_hash,
                "required_approvals": evaluation.required_approvals,
                "evidence_refs": request.evidence_refs,
                "reason": request.reason,
                "action_payload": sanitize_raw_payload(request.action_payload),
            },
        )
        db_session.add(audit_event)

        db_session.commit()
        db_session.refresh(proposal)

        return self._format_proposal_response(proposal, evaluation, db_session=db_session)

    def get_proposal(
        self,
        proposal_id: str,
        db_session: Session,
    ) -> ResponseProposalResponse:
        """Retrieve proposal details and check for temporal expiration."""
        proposal = db_session.execute(
            select(ResponseProposal).where(ResponseProposal.id == proposal_id)
        ).scalar_one_or_none()
        if not proposal:
            raise ProposalNotFoundError(f"Proposal {proposal_id} not found.")

        # Check and apply temporal expiry if pending
        now = utc_now()
        exp = ensure_utc(proposal.expires_at)
        if proposal.state == ProposalStateEnum.PENDING.value and exp and exp < now:
            proposal.state = ProposalStateEnum.EXPIRED.value
            db_session.add(
                AuditEvent(
                    id=str(uuid4()),
                    actor_type="SYSTEM",
                    actor_id="system:expiry_checker",
                    action="proposal:expired",
                    object_type="proposal",
                    object_id=proposal.id,
                    outcome="SUCCESS",
                    reason_code="EXPIRED_TIMEOUT",
                    occurred_at=now,
                    metadata_redacted={"expires_at": proposal.expires_at.isoformat()},
                )
            )
            db_session.commit()
            db_session.refresh(proposal)

        return self._format_proposal_response(proposal)

    def list_proposals_for_incident(
        self,
        incident_id: str,
        db_session: Session,
    ) -> List[ResponseProposalResponse]:
        """List all proposals associated with an incident."""
        proposals = (
            db_session.execute(
                select(ResponseProposal)
                .where(ResponseProposal.incident_id == incident_id)
                .order_by(ResponseProposal.created_at.desc())
            )
            .scalars()
            .all()
        )

        results = []
        now = utc_now()
        for prop in proposals:
            # Check expiry
            exp = ensure_utc(prop.expires_at)
            if prop.state == ProposalStateEnum.PENDING.value and exp and exp < now:
                prop.state = ProposalStateEnum.EXPIRED.value
                db_session.commit()
            results.append(self._format_proposal_response(prop))

        return results

    def submit_approval(
        self,
        proposal_id: str,
        request: SubmitApprovalRequest,
        approver: Any,
        db_session: Session,
    ) -> ResponseProposalResponse:
        """Submit an approval or rejection decision for a response proposal.

        Enforces separation-of-duties, role eligibility, dual authorization for Tier 3,
        and cryptographic payload hash drift protection.
        """
        # Lock proposal row for update to prevent concurrent race conditions
        proposal = db_session.execute(
            select(ResponseProposal)
            .where(ResponseProposal.id == proposal_id)
            .with_for_update()
        ).scalar_one_or_none()

        if not proposal:
            raise ProposalNotFoundError(f"Proposal {proposal_id} not found.")

        # Fetch existing approvals
        existing_approvals = (
            db_session.execute(
                select(Approval).where(Approval.proposal_id == proposal_id)
            )
            .scalars()
            .all()
        )

        # Validate approval preconditions
        is_valid, error_msg = validate_approval_submission(
            proposal=proposal,
            approver=approver,
            request=request,
            existing_approvals=list(existing_approvals),
        )

        if not is_valid:
            # Audit denied approval attempt
            db_session.add(
                AuditEvent(
                    id=str(uuid4()),
                    actor_type="USER",
                    actor_id=approver.id,
                    action="proposal:approval_denied",
                    object_type="proposal",
                    object_id=proposal.id,
                    outcome="DENIED",
                    reason_code="SEPARATION_OF_DUTIES_OR_POLICY_VIOLATION",
                    occurred_at=utc_now(),
                    metadata_redacted={
                        "reason": error_msg,
                        "attempted_decision": request.decision.value,
                    },
                )
            )
            db_session.commit()
            raise ApprovalViolationError(error_msg)

        now = utc_now()
        risk_tier = ResponseRiskTierEnum(proposal.risk)
        policy_decision = evaluate_action_policy(risk_tier)

        # Ensure approver User record exists to satisfy FK constraint
        user_rec = db_session.execute(
            select(User).where(User.id == approver.id)
        ).scalar_one_or_none()
        if not user_rec:
            user_rec = User(
                id=approver.id,
                display_name=getattr(approver, "name", approver.id),
                status="active",
                created_at=now,
                updated_at=now,
            )
            db_session.add(user_rec)
            db_session.flush()

        # Record Approval record
        approval = Approval(
            id=str(uuid4()),
            proposal_id=proposal.id,
            approver_id=approver.id,
            decision=request.decision.value,
            policy_version=request.policy_version,
            action_payload_hash=proposal.action_payload_hash,
            reason=request.reason,
            decided_at=now,
        )
        db_session.add(approval)

        if request.decision == ApprovalDecisionEnum.REJECTED:
            proposal.state = ProposalStateEnum.REJECTED.value
            action_name = "proposal:rejected"
        else:
            # Check if approval quorum reached
            approved_count = (
                sum(1 for a in existing_approvals if a.decision == ApprovalDecisionEnum.APPROVED.value)
                + 1
            )
            if approved_count >= policy_decision.required_approvals:
                proposal.state = ProposalStateEnum.APPROVED.value
            action_name = "proposal:approved"

        # Record AuditEvent
        db_session.add(
            AuditEvent(
                id=str(uuid4()),
                actor_type="USER",
                actor_id=approver.id,
                action=action_name,
                object_type="proposal",
                object_id=proposal.id,
                outcome="SUCCESS",
                reason_code=request.decision.value,
                occurred_at=now,
                metadata_redacted={
                    "decision": request.decision.value,
                    "reason": request.reason,
                    "resulting_state": proposal.state,
                    "payload_hash": proposal.action_payload_hash,
                },
            )
        )

        db_session.commit()
        db_session.refresh(proposal)

        return self._format_proposal_response(proposal)

    def revoke_proposal(
        self,
        proposal_id: str,
        user: Any,
        reason: str,
        db_session: Session,
    ) -> ResponseProposalResponse:
        """Revoke a pending proposal."""
        proposal = db_session.execute(
            select(ResponseProposal)
            .where(ResponseProposal.id == proposal_id)
            .with_for_update()
        ).scalar_one_or_none()

        if not proposal:
            raise ProposalNotFoundError(f"Proposal {proposal_id} not found.")

        if proposal.state not in [
            ProposalStateEnum.PENDING.value,
            ProposalStateEnum.APPROVED.value,
        ]:
            raise ApprovalViolationError(
                f"Cannot revoke proposal {proposal_id} in state '{proposal.state}'."
            )

        now = utc_now()
        proposal.state = ProposalStateEnum.REVOKED.value

        db_session.add(
            AuditEvent(
                id=str(uuid4()),
                actor_type="USER",
                actor_id=user.id,
                action="proposal:revoked",
                object_type="proposal",
                object_id=proposal.id,
                outcome="SUCCESS",
                reason_code="REVOKED_BY_OPERATOR",
                occurred_at=now,
                metadata_redacted={"reason": reason},
            )
        )

        db_session.commit()
        db_session.refresh(proposal)
        return self._format_proposal_response(proposal)

    def execute_action(
        self,
        proposal_id: str,
        request: ExecuteActionRequest,
        actor_id: str,
        db_session: Session,
    ) -> Dict[str, Any]:
        """Dispatch action to execution boundary.

        SAFETY INVARIANT:
        When live_response_disabled is true, NO production-changing APIs are invoked.
        Simulates the action or blocks it with an immutable audit record.
        """
        proposal = db_session.execute(
            select(ResponseProposal)
            .where(ResponseProposal.id == proposal_id)
            .with_for_update()
        ).scalar_one_or_none()

        if not proposal:
            raise ProposalNotFoundError(f"Proposal {proposal_id} not found.")

        # Determine idempotency key
        idempotency_key = request.idempotency_key or f"exec-{proposal.id}"

        # Check for existing execution record with idempotency key OR for this proposal
        existing_action = db_session.execute(
            select(ResponseAction).where(
                (ResponseAction.idempotency_key == idempotency_key)
                | (ResponseAction.proposal_id == proposal.id)
            )
        ).scalar_one_or_none()

        if existing_action:
            return {
                "action_id": existing_action.id,
                "proposal_id": proposal.id,
                "state": existing_action.state,
                "idempotency_key": existing_action.idempotency_key,
                "result": existing_action.result_redacted,
                "started_at": existing_action.started_at.isoformat(),
                "finished_at": (
                    existing_action.finished_at.isoformat()
                    if existing_action.finished_at
                    else None
                ),
                "message": "Duplicate execution request suppressed by idempotency key.",
            }

        # Check proposal state: only APPROVED proposals are eligible for execution
        if proposal.state != ProposalStateEnum.APPROVED.value:
            raise ActionExecutionBlockedError(
                f"Cannot execute proposal {proposal_id} in state '{proposal.state}'. "
                "Only APPROVED proposals can be dispatched."
            )

        # Check expiration
        now = utc_now()
        exp = ensure_utc(proposal.expires_at)
        if exp and exp < now:
            proposal.state = ProposalStateEnum.EXPIRED.value
            db_session.commit()
            raise ProposalExpiredError(f"Proposal {proposal_id} has expired.")

        # Payload tampering / drift check at dispatch
        expected_hash = getattr(request, "expected_payload_hash", None)
        if expected_hash and expected_hash != proposal.action_payload_hash:
            raise ActionExecutionBlockedError(
                f"Payload drift detected: expected payload hash '{expected_hash}' "
                f"does not match registered proposal payload hash '{proposal.action_payload_hash}'."
            )

        if request.action_payload is not None:
            dispatched_hash = compute_payload_hash(request.action_payload)
            if dispatched_hash != proposal.action_payload_hash:
                raise ActionExecutionBlockedError(
                    f"Payload drift detected: dispatched payload hash '{dispatched_hash}' "
                    f"does not match registered proposal payload hash '{proposal.action_payload_hash}'."
                )

        # Resolve registered target_entity and action_payload for simulation/safety checks
        cached = self._proposal_cache.get(proposal.id, {})
        registered_target = cached.get("target_entity")
        action_payload = request.action_payload or cached.get("action_payload", {})

        if not registered_target:
            creation_audit = db_session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.object_id == proposal.id,
                    AuditEvent.action == "proposal:create",
                )
                .order_by(AuditEvent.occurred_at.asc())
            ).scalars().first()
            if creation_audit and creation_audit.metadata_redacted:
                registered_target = creation_audit.metadata_redacted.get("target_entity")
                if not action_payload:
                    action_payload = creation_audit.metadata_redacted.get("action_payload", {})

        # Verify target entity integrity: Dispatched target cannot differ from approved target
        if request.target_entity and registered_target:
            if str(request.target_entity).strip() != str(registered_target).strip():
                raise ActionExecutionBlockedError(
                    f"Target entity drift detected: dispatched target '{request.target_entity}' "
                    f"does not match approved proposal target '{registered_target}'."
                )

        target_entity = request.target_entity or registered_target
        target_entity_str = str(target_entity or "unknown-target")

        # SAFETY GATE EVALUATION
        # Invariant: When live_response_disabled=True, live execution (dry_run=False) is strictly blocked
        if not request.dry_run or request.target_environment == "production":
            action_state = ProposalStateEnum.BLOCKED_SAFETY.value
            result_payload = {
                "live_response_disabled": self.live_response_disabled,
                "dry_run": request.dry_run,
                "target_environment": request.target_environment,
                "action_type": proposal.action_type,
                "risk_tier": proposal.risk,
                "safety_barrier": "LIVE_RESPONSE_DISABLED=true enforced; zero containment APIs invoked.",
                "status": "BLOCKED_BY_SAFETY_CONFIGURATION",
                "message": "Live response execution is disabled by security configuration.",
            }
            audit_outcome = "BLOCKED"
            audit_reason = "LIVE_RESPONSE_DISABLED"
        else:
            # Lab simulation mode: execute through approved LabResponseAdapter
            try:
                lab_res = self.lab_adapter.execute_simulated_action(
                    action_type=proposal.action_type,
                    target_entity=target_entity_str,
                    action_payload=action_payload,
                )
                action_state = ProposalStateEnum.SIMULATED.value
                result_payload = {
                    "live_response_disabled": self.live_response_disabled,
                    "dry_run": request.dry_run,
                    "target_environment": request.target_environment,
                    "adapter": "LabResponseAdapter",
                    "action_type": proposal.action_type,
                    "risk_tier": proposal.risk,
                    "safety_barrier": "LIVE_RESPONSE_DISABLED=true enforced; zero containment APIs invoked.",
                    "status": "SIMULATED_SUCCESS",
                    "simulation_details": lab_res.model_dump(),
                }
                audit_outcome = "SIMULATED"
                audit_reason = "DRY_RUN"
            except LabTargetNotPermittedError as e:
                action_state = ProposalStateEnum.FAILED.value
                result_payload = {
                    "live_response_disabled": self.live_response_disabled,
                    "dry_run": request.dry_run,
                    "target_environment": request.target_environment,
                    "action_type": proposal.action_type,
                    "risk_tier": proposal.risk,
                    "safety_barrier": "LIVE_RESPONSE_DISABLED=true: Production target rejected by lab allowlist.",
                    "status": "REJECTED_PRODUCTION_TARGET",
                    "error": str(e),
                }
                audit_outcome = "FAILED"
                audit_reason = "PRODUCTION_TARGET_NOT_PERMITTED"
            except (UnsupportedLabActionError, LabExecutionTimeoutError) as e:
                action_state = ProposalStateEnum.FAILED.value
                result_payload = {
                    "live_response_disabled": self.live_response_disabled,
                    "dry_run": request.dry_run,
                    "target_environment": request.target_environment,
                    "action_type": proposal.action_type,
                    "risk_tier": proposal.risk,
                    "status": "FAILED",
                    "error": str(e),
                }
                audit_outcome = "FAILED"
                audit_reason = "LAB_SIMULATION_ERROR"

        action_record = ResponseAction(
            id=str(uuid4()),
            proposal_id=proposal.id,
            idempotency_key=idempotency_key,
            state=action_state,
            result_redacted=result_payload,
            started_at=now,
            finished_at=now,
            verified_at=now if action_state == ProposalStateEnum.SIMULATED.value else None,
        )
        db_session.add(action_record)

        # Update proposal state to reflect execution outcome
        proposal.state = action_state

        # Record AuditEvent
        db_session.add(
            AuditEvent(
                id=str(uuid4()),
                actor_type="USER" if "user" in actor_id.lower() or "analyst" in actor_id.lower() else "AGENT",
                actor_id=actor_id,
                action="action:execute",
                object_type="response_action",
                object_id=action_record.id,
                outcome=audit_outcome,
                reason_code=audit_reason,
                occurred_at=now,
                metadata_redacted={
                    "proposal_id": proposal.id,
                    "action_type": proposal.action_type,
                    "target_entity": target_entity_str,
                    "idempotency_key": idempotency_key,
                    "result": result_payload,
                },
            )
        )

        db_session.commit()
        db_session.refresh(action_record)

        return {
            "action_id": action_record.id,
            "proposal_id": proposal.id,
            "state": action_record.state,
            "idempotency_key": action_record.idempotency_key,
            "result": action_record.result_redacted,
            "started_at": action_record.started_at.isoformat(),
            "finished_at": (
                action_record.finished_at.isoformat()
                if action_record.finished_at
                else None
            ),
        }

    def _format_proposal_response(
        self,
        proposal: ResponseProposal,
        evaluation: Optional[Any] = None,
        db_session: Optional[Session] = None,
    ) -> ResponseProposalResponse:
        """Format a database proposal model into the canonical response schema."""
        risk_tier = ResponseRiskTierEnum(proposal.risk)
        policy_decision = evaluate_action_policy(risk_tier)

        approvals_list = []
        if proposal.approvals:
            for app in proposal.approvals:
                approvals_list.append(
                    {
                        "id": app.id,
                        "approver_id": app.approver_id,
                        "decision": app.decision,
                        "policy_version": app.policy_version,
                        "decided_at": app.decided_at.isoformat(),
                        "reason": app.reason,
                    }
                )

        # Retrieve target_entity, reason, evidence_refs, action_payload
        cached = self._proposal_cache.get(proposal.id, {})
        target_entity = cached.get("target_entity")
        reason = cached.get("reason")
        evidence_refs = cached.get("evidence_refs", [])
        action_payload = cached.get("action_payload")

        if (not target_entity or not reason) and db_session is not None:
            creation_audit = db_session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.object_id == proposal.id,
                    AuditEvent.action == "proposal:create",
                )
                .order_by(AuditEvent.occurred_at.asc())
            ).scalars().first()
            if creation_audit and creation_audit.metadata_redacted:
                target_entity = target_entity or creation_audit.metadata_redacted.get("target_entity")
                reason = reason or creation_audit.metadata_redacted.get("reason")
                evidence_refs = evidence_refs or creation_audit.metadata_redacted.get("evidence_refs", [])
                action_payload = action_payload or creation_audit.metadata_redacted.get("action_payload")
                self._proposal_cache[proposal.id] = {
                    "target_entity": target_entity,
                    "reason": reason,
                    "evidence_refs": evidence_refs,
                    "action_payload": action_payload,
                }

        return ResponseProposalResponse(
            id=proposal.id,
            incident_id=proposal.incident_id,
            action_type=proposal.action_type,
            action_payload_hash=proposal.action_payload_hash,
            risk=proposal.risk,
            state=proposal.state,
            created_by=proposal.created_by,
            created_at=proposal.created_at,
            expires_at=proposal.expires_at,
            required_approvals=policy_decision.required_approvals,
            current_approvals_count=sum(
                1 for a in approvals_list if a["decision"] == ApprovalDecisionEnum.APPROVED.value
            ),
            allowed_approver_roles=[r.value for r in policy_decision.allowed_approver_roles],
            approvals=approvals_list,
            target_entity=target_entity,
            reason=reason,
            evidence_refs=evidence_refs,
            action_payload=action_payload,
        )
