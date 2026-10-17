"""CyberSentinel AI — Response Policy & Approval Gating (ADR-0006)

Deterministic evaluation of proposal eligibility, target entity validation,
cryptographic payload hash binding, approver roles, separation-of-duties,
and dual-human authorization requirements.
"""

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from packages.policy import evaluate_action_policy
from schemas.enums import IncidentStateEnum, RBACRoleEnum, ResponseRiskTierEnum
from services.persistence.models import Approval, Incident, ResponseProposal
from services.response.catalogue import get_action_template
from services.response.models import CreateProposalRequest, SubmitApprovalRequest


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PolicyOutcomeEnum(str, Enum):
    """Authoritative policy evaluation outcome."""

    ALLOW_PROPOSAL = "ALLOW_PROPOSAL"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    BLOCKED_BY_SAFETY_CONFIGURATION = "BLOCKED_BY_SAFETY_CONFIGURATION"


class ProposalPolicyEvaluation(BaseModel):
    """Result of evaluating a response proposal against policy."""

    outcome: PolicyOutcomeEnum
    risk_tier: ResponseRiskTierEnum
    required_approvals: int
    allowed_approver_roles: List[RBACRoleEnum]
    action_payload_hash: str
    reasons: List[str] = Field(default_factory=list)
    is_eligible: bool


def compute_payload_hash(payload: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash of canonical JSON action payload.

    ADR-0006 §2: Approvals are cryptographically bound to the SHA-256 hash of
    the exact action payload. Any drift invalidates the approval.
    """
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def evaluate_proposal_policy(
    incident: Incident,
    request: CreateProposalRequest,
    target_entity_type: Optional[str] = None,
) -> ProposalPolicyEvaluation:
    """Evaluate whether an incident and proposal request can formulate a valid response proposal.

    Checks:
    1. Incident state eligibility: cannot create proposals on CLOSED, BENIGN, or LESSONS_LEARNED incidents.
    2. Action allowlist: action must exist in safe catalogue.
    3. Target entity and parameters: must satisfy template requirements.
    4. Evidence presence: must provide at least one evidence reference for Tier 2 or Tier 3 actions.
    5. Computes payload hash.
    6. Determines required approvals and allowed roles via ADR-0006 policy engine.
    """
    reasons: List[str] = []

    # 1. Action catalogue check
    template = get_action_template(request.action_type)
    if not template:
        return ProposalPolicyEvaluation(
            outcome=PolicyOutcomeEnum.DENY,
            risk_tier=ResponseRiskTierEnum.TIER_0,
            required_approvals=0,
            allowed_approver_roles=[],
            action_payload_hash=compute_payload_hash(request.action_payload),
            reasons=[f"Action '{request.action_type}' is not recognized in approved catalogue."],
            is_eligible=False,
        )

    risk_tier = template.risk_tier

    # 2. Incident state check
    terminal_or_ineligible_states = {
        IncidentStateEnum.CLOSED.value,
        IncidentStateEnum.BENIGN.value,
        IncidentStateEnum.LESSONS_LEARNED.value,
    }
    if incident.status in terminal_or_ineligible_states:
        reasons.append(
            f"Cannot create response proposal for incident in status '{incident.status}'. "
            "Incident must be in active state (e.g. TRIAGE, INVESTIGATING, CONFIRMED)."
        )

    # 3. Target type check (if target_entity_type provided)
    if target_entity_type:
        normalized_target_type = target_entity_type.strip().lower()
        if normalized_target_type not in [t.lower() for t in template.allowed_target_types]:
            reasons.append(
                f"Target type '{target_entity_type}' is not permitted for action '{request.action_type}'. "
                f"Permitted types: {template.allowed_target_types}"
            )

    # 4. Target entity identifier check
    if not request.target_entity or not request.target_entity.strip():
        reasons.append("Target entity identifier cannot be empty.")

    # 5. Required parameter validation
    for param in template.required_parameters:
        if param not in request.action_payload:
            reasons.append(f"Missing required parameter '{param}' in action_payload.")

    # 6. Evidence requirement check: Tier 2 and Tier 3 actions must be grounded in verified evidence
    if risk_tier in [ResponseRiskTierEnum.TIER_2, ResponseRiskTierEnum.TIER_3]:
        if not request.evidence_refs:
            reasons.append(
                f"{risk_tier.value} actions require at least one supporting evidence or finding reference."
            )

    # Calculate payload hash
    payload_hash = compute_payload_hash(request.action_payload)

    # Policy decision from ADR-0006 engine
    policy_decision = evaluate_action_policy(risk_tier)

    if reasons:
        return ProposalPolicyEvaluation(
            outcome=PolicyOutcomeEnum.DENY,
            risk_tier=risk_tier,
            required_approvals=policy_decision.required_approvals,
            allowed_approver_roles=policy_decision.allowed_approver_roles,
            action_payload_hash=payload_hash,
            reasons=reasons,
            is_eligible=False,
        )

    outcome = (
        PolicyOutcomeEnum.ALLOW_PROPOSAL
        if policy_decision.required_approvals == 0
        else PolicyOutcomeEnum.REQUIRE_APPROVAL
    )

    return ProposalPolicyEvaluation(
        outcome=outcome,
        risk_tier=risk_tier,
        required_approvals=policy_decision.required_approvals,
        allowed_approver_roles=policy_decision.allowed_approver_roles,
        action_payload_hash=payload_hash,
        reasons=[policy_decision.reason],
        is_eligible=True,
    )


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def validate_approval_submission(
    proposal: ResponseProposal,
    approver: Any,
    request: SubmitApprovalRequest,
    existing_approvals: List[Approval],
) -> Tuple[bool, Optional[str]]:
    """Validate a human approval submission against separation of duties and policy constraints.

    Enforces:
    1. Proposal state must be PENDING (cannot approve APPROVED, REJECTED, EXPIRED, etc.).
    2. Expiration check: current time must be before proposal.expires_at.
    3. Separation of duties: author/creator cannot approve their own proposal.
    4. Approver role: approver's role must be authorized for this risk tier.
    5. Payload hash binding: if expected_payload_hash is supplied, it must match proposal.action_payload_hash.
    6. Duplicate approval: the same user cannot approve twice.
    7. For Tier 3 dual authorization: approvers must be distinct individuals.
    """
    now = utc_now()

    # 1. State check
    if proposal.state != "PENDING":
        return False, f"Proposal {proposal.id} is in state '{proposal.state}', not 'PENDING'."

    # 2. Expiration check
    expires_at = ensure_utc(proposal.expires_at)
    if expires_at and now > expires_at:
        return False, f"Proposal {proposal.id} expired at {expires_at.isoformat()}."

    # 3. Separation of duties: author cannot approve own proposal
    if approver.id == proposal.created_by:
        return False, "Separation of duties violation: proposal creator cannot approve their own proposal."

    # 4. Approver role check
    risk_tier = ResponseRiskTierEnum(proposal.risk)
    policy_decision = evaluate_action_policy(risk_tier)
    allowed_role_values = [r.value for r in policy_decision.allowed_approver_roles]

    approver_roles: List[str] = []
    if hasattr(approver, "roles") and approver.roles:
        approver_roles = [r.value if hasattr(r, "value") else str(r) for r in approver.roles]
    elif hasattr(approver, "role") and approver.role:
        r = approver.role
        approver_roles = [r.value if hasattr(r, "value") else str(r)]

    is_authorized = any(
        r in allowed_role_values or r == RBACRoleEnum.ADMIN.value for r in approver_roles
    )
    if not is_authorized:
        return (
            False,
            f"User role '{approver_roles}' is not authorized to approve {proposal.risk} actions. "
            f"Required roles: {allowed_role_values}",
        )

    # 5. Payload hash binding / drift protection
    if request.expected_payload_hash and request.expected_payload_hash != proposal.action_payload_hash:
        return (
            False,
            f"Payload drift detected: expected hash '{request.expected_payload_hash}' "
            f"does not match registered proposal payload hash '{proposal.action_payload_hash}'.",
        )

    # 6. Duplicate approval check
    for prior in existing_approvals:
        if prior.approver_id == approver.id:
            return False, f"User {approver.id} has already submitted a decision for this proposal."

    return True, None
