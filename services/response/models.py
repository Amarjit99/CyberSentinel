"""CyberSentinel AI — Response Proposal & Playbook Models (ADR-0006, Doc 21)

Defines strongly-typed schemas for response action proposals, approval requests,
playbook templates, and execution gating.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.enums import ResponseRiskTierEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProposalStateEnum(str, Enum):
    """Lifecycle state machine for a response action proposal."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SIMULATED = "SIMULATED"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ActionExecutionStateEnum(str, Enum):
    """State of an action dispatched to the execution boundary."""

    QUEUED = "QUEUED"
    SIMULATED = "SIMULATED"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    FAILED = "FAILED"
    SUCCEEDED = "SUCCEEDED"


class CreateProposalRequest(BaseModel):
    """API request payload to formulate a response proposal."""

    action_type: str = Field(
        ...,
        description="Supported action identifier from catalogue (e.g. 'isolate_host', 'block_ip')",
    )
    target_entity: str = Field(
        ...,
        description="Target entity key (hostname, IP address, user account, domain, file hash)",
    )
    action_payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters required for the action",
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Human-readable justification for the proposal",
    )
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="IDs of backing evidence, detections, or findings supporting this proposal",
    )
    validity_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,
        description="Minutes until proposal expires",
    )


class ApprovalDecisionEnum(str, Enum):
    """Decision submitted by an authorized human approver."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class SubmitApprovalRequest(BaseModel):
    """Request payload to approve or reject a response proposal."""

    decision: ApprovalDecisionEnum = Field(..., description="Approval decision: APPROVED or REJECTED")
    reason: str = Field(
        ...,
        min_length=3,
        max_length=1000,
        description="Justification for the approval decision",
    )
    policy_version: str = Field(default="1.0.0", description="Policy version evaluated")
    expected_payload_hash: Optional[str] = Field(
        default=None,
        description="Optional client-side SHA-256 payload hash to guard against drift",
    )


class ExecuteActionRequest(BaseModel):
    """Request to dispatch an approved proposal to the execution boundary."""

    dry_run: bool = Field(
        default=True,
        description="Whether to run in simulated dry-run mode (live response remains disabled)",
    )
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Client-provided idempotency key",
    )
    target_environment: str = Field(
        default="lab",
        description="Target execution environment: 'lab' or 'production'. 'production' is strictly blocked by safety switches.",
    )
    action_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional action payload provided at dispatch to verify against approved cryptographic payload hash",
    )
    target_entity: Optional[str] = Field(
        default=None,
        description="Optional target entity to re-verify against proposal target at dispatch time",
    )
    expected_payload_hash: Optional[str] = Field(
        default=None,
        description="Optional client-side SHA-256 payload hash to guard against drift at dispatch",
    )


class ResponseProposalResponse(BaseModel):
    """Full detail response for a response proposal."""

    id: str
    incident_id: str
    action_type: str
    action_payload_hash: str
    risk: str
    state: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    required_approvals: int
    current_approvals_count: int
    allowed_approver_roles: List[str]
    target_entity: Optional[str] = None
    reason: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    approvals: List[Dict[str, Any]] = Field(default_factory=list)
    action_payload: Optional[Dict[str, Any]] = None


class PlaybookTemplate(BaseModel):
    """Definition of a supported response action in the safe catalogue."""

    action_type: str
    name: str
    description: str
    risk_tier: ResponseRiskTierEnum
    allowed_target_types: List[str]
    required_parameters: List[str]
    optional_parameters: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    rollback_description: str
