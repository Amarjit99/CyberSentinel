"""CyberSentinel AI — Response Proposal & Playbook Governance Subsystem (ADR-0006)

Manages response action proposals, human-in-the-loop approvals, separation of duties,
dual-human authorization, and safety-gated execution boundaries.
Mandatory safety invariant: LIVE_RESPONSE_DISABLED=true.
"""

from services.response.catalogue import (
    RESPONSE_ACTION_CATALOGUE,
    get_action_template,
    list_action_catalogue,
    validate_action_invocation,
)
from services.response.generator import PlaybookGenerator
from services.response.lab_adapter import (
    LabAdapterError,
    LabExecutionResult,
    LabExecutionTimeoutError,
    LabResponseAdapter,
    LabTargetAllowlist,
    LabTargetNotPermittedError,
    UnsupportedLabActionError,
)
from services.response.manager import (
    ActionExecutionBlockedError,
    ApprovalViolationError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalPolicyViolationError,
    ResponseManager,
)
from services.response.models import (
    ActionExecutionStateEnum,
    ApprovalDecisionEnum,
    CreateProposalRequest,
    ExecuteActionRequest,
    PlaybookTemplate,
    ProposalStateEnum,
    ResponseProposalResponse,
    SubmitApprovalRequest,
)
from services.response.policy import (
    PolicyOutcomeEnum,
    ProposalPolicyEvaluation,
    compute_payload_hash,
    evaluate_proposal_policy,
    validate_approval_submission,
)

__all__ = [
    # Manager & Generator
    "ResponseManager",
    "PlaybookGenerator",
    # Lab Adapter
    "LabResponseAdapter",
    "LabTargetAllowlist",
    "LabExecutionResult",
    "LabAdapterError",
    "LabTargetNotPermittedError",
    "UnsupportedLabActionError",
    "LabExecutionTimeoutError",
    # Catalogue
    "RESPONSE_ACTION_CATALOGUE",
    "get_action_template",
    "list_action_catalogue",
    "validate_action_invocation",
    # Policy
    "PolicyOutcomeEnum",
    "ProposalPolicyEvaluation",
    "compute_payload_hash",
    "evaluate_proposal_policy",
    "validate_approval_submission",
    # Models
    "CreateProposalRequest",
    "SubmitApprovalRequest",
    "ExecuteActionRequest",
    "ResponseProposalResponse",
    "PlaybookTemplate",
    "ProposalStateEnum",
    "ActionExecutionStateEnum",
    "ApprovalDecisionEnum",
    # Exceptions
    "ProposalPolicyViolationError",
    "ProposalNotFoundError",
    "ProposalExpiredError",
    "ApprovalViolationError",
    "ActionExecutionBlockedError",
]
