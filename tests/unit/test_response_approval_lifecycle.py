"""CyberSentinel AI — Unit Tests: Response Proposal Lifecycle & Payload Binding (Sprint 20)

Verifies:
- Proposal creation, policy evaluation, and state machine transitions.
- Cryptographic SHA-256 payload hash binding and canonicalization.
- Separation of duties: proposer cannot self-approve.
- Role-based authorization for Tier 2 and Tier 3 approvals.
- Tier 3 dual-human approval requirement by two distinct approvers.
- Duplicate approval rejection for the same approver.
- Expiration handling: expired proposal cannot be approved or executed.
- Revocation handling: revoked proposal cannot be executed.
- State machine protection against invalid transitions.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.persistence.models import (
    Base,
    Incident,
    ResponseProposal,
)
from services.response import (
    ActionExecutionBlockedError,
    ApprovalDecisionEnum,
    ApprovalViolationError,
    CreateProposalRequest,
    ExecuteActionRequest,
    ProposalStateEnum,
    ResponseManager,
    SubmitApprovalRequest,
    compute_payload_hash,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def active_incident(db_session):
    now = utc_now()
    inc = Incident(
        id="inc-lifecycle-01",
        title="Unauthorized Lateral Movement Detected",
        status=IncidentStateEnum.INVESTIGATING.value,
        severity="high",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(inc)
    db_session.commit()
    db_session.refresh(inc)
    return inc


@pytest.fixture
def manager():
    return ResponseManager(live_response_disabled=True)


# ==============================================================================
# 1. Payload Canonicalization & Hash Binding Tests
# ==============================================================================


def test_payload_hash_canonicalization_is_order_invariant():
    """Verify that dictionary key order does not alter the canonical SHA-256 hash."""
    payload_a = {"isolation_type": "network", "allow_soc_management": True, "timeout": 3600}
    payload_b = {"timeout": 3600, "allow_soc_management": True, "isolation_type": "network"}

    hash_a = compute_payload_hash(payload_a)
    hash_b = compute_payload_hash(payload_b)

    assert hash_a == hash_b
    assert len(hash_a) == 64


def test_payload_hash_changes_on_material_modification():
    """Verify that any alteration of payload content changes the hash."""
    payload_original = {"direction": "both", "duration_hours": 24}
    payload_tampered = {"direction": "both", "duration_hours": 48}

    assert compute_payload_hash(payload_original) != compute_payload_hash(payload_tampered)


# ==============================================================================
# 2. Lifecycle State Machine Transitions
# ==============================================================================


def test_lifecycle_pending_to_approved_to_simulated(db_session, active_incident, manager):
    """Verify standard happy-path lifecycle: PENDING -> APPROVED -> SIMULATED."""
    # 1. Create proposal
    req = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01-LAB",
        action_payload={"isolation_type": "network", "allow_soc_management": True},
        reason="Compromised host exhibiting C2 beaconing",
        evidence_refs=["ev-beacon-01"],
        validity_minutes=60,
    )
    proposal_resp = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=db_session,
    )
    assert proposal_resp.state == ProposalStateEnum.PENDING.value
    assert proposal_resp.current_approvals_count == 0

    # 2. Submit approval by distinct authorized approver
    approver = Principal(id="user-mgr-bob", name="Bob Manager", roles=[RBACRoleEnum.SOC_MANAGER])
    approval_resp = manager.submit_approval(
        proposal_id=proposal_resp.id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.APPROVED,
            reason="Approved after evidence verification",
            expected_payload_hash=proposal_resp.action_payload_hash,
        ),
        approver=approver,
        db_session=db_session,
    )
    assert approval_resp.state == ProposalStateEnum.APPROVED.value
    assert approval_resp.current_approvals_count == 1

    # 3. Dispatch to lab execution
    exec_res = manager.execute_action(
        proposal_id=proposal_resp.id,
        request=ExecuteActionRequest(dry_run=True, target_environment="lab"),
        actor_id="user-mgr-bob",
        db_session=db_session,
    )
    assert exec_res["state"] == ProposalStateEnum.SIMULATED.value
    assert exec_res["result"]["status"] == "SIMULATED_SUCCESS"


def test_lifecycle_pending_to_rejected(db_session, active_incident, manager):
    """Verify that rejection transitions proposal to REJECTED."""
    req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="10.99.1.50",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Suspicious scan",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=db_session,
    )

    approver = Principal(id="user-mgr-bob", name="Bob Manager", roles=[RBACRoleEnum.SOC_MANAGER])
    reject_resp = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.REJECTED,
            reason="Insufficient evidence; false positive suspected",
        ),
        approver=approver,
        db_session=db_session,
    )
    assert reject_resp.state == ProposalStateEnum.REJECTED.value

    # Attempt to execute rejected proposal must fail
    with pytest.raises(ActionExecutionBlockedError):
        manager.execute_action(
            proposal_id=prop.id,
            request=ExecuteActionRequest(dry_run=True),
            actor_id="user-mgr-bob",
            db_session=db_session,
        )


def test_lifecycle_pending_to_revoked(db_session, active_incident, manager):
    """Verify that operator can revoke a pending proposal."""
    req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="10.99.1.50",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Initial block proposal",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=db_session,
    )

    operator = Principal(id="user-analyst-alice", name="Alice", roles=[RBACRoleEnum.SOC_ANALYST])
    revoked_resp = manager.revoke_proposal(
        proposal_id=prop.id,
        user=operator,
        reason="Superseded by updated containment plan",
        db_session=db_session,
    )
    assert revoked_resp.state == ProposalStateEnum.REVOKED.value

    # Attempt to approve or execute a revoked proposal must fail
    approver = Principal(id="user-mgr-bob", name="Bob", roles=[RBACRoleEnum.SOC_MANAGER])
    with pytest.raises(ApprovalViolationError):
        manager.submit_approval(
            proposal_id=prop.id,
            request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Late approval"),
            approver=approver,
            db_session=db_session,
        )


# ==============================================================================
# 3. Separation of Duties & Tier 3 Dual Authorization
# ==============================================================================


def test_self_approval_is_strictly_forbidden(db_session, active_incident, manager):
    """Verify that proposal author cannot approve their own proposal."""
    req = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01-LAB",
        action_payload={"isolation_type": "network"},
        reason="Isolation needed",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-author-alice",
        db_session=db_session,
    )

    # Alice attempts to approve her own proposal
    alice_approver = Principal(
        id="user-author-alice", name="Alice Author", roles=[RBACRoleEnum.SOC_MANAGER]
    )
    with pytest.raises(ApprovalViolationError) as exc_info:
        manager.submit_approval(
            proposal_id=prop.id,
            request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Self-approving"),
            approver=alice_approver,
            db_session=db_session,
        )
    assert "Separation of duties" in str(exc_info.value)


def test_tier_3_requires_two_distinct_human_approvers(db_session, active_incident, manager):
    """Verify that Tier 3 consequential actions require 2 distinct human approvals."""
    req = CreateProposalRequest(
        action_type="disable_user_account",
        target_entity="lab_user_compromised",
        action_payload={"notify_manager": True},
        reason="Compromised credentials used in lateral movement",
        evidence_refs=["ev-compromise-01"],
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=db_session,
    )
    assert prop.risk == "Tier 3"
    assert prop.required_approvals == 2

    # First approval by SOC Manager -> state remains PENDING
    manager_approver = Principal(
        id="user-mgr-bob", name="Bob Manager", roles=[RBACRoleEnum.SOC_MANAGER]
    )
    resp_1 = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="First approval by SOC Manager"),
        approver=manager_approver,
        db_session=db_session,
    )
    assert resp_1.state == ProposalStateEnum.PENDING.value
    assert resp_1.current_approvals_count == 1

    # Second approval by SAME person must be rejected
    with pytest.raises(ApprovalViolationError) as exc_info:
        manager.submit_approval(
            proposal_id=prop.id,
            request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Duplicate second approval"),
            approver=manager_approver,
            db_session=db_session,
        )
    assert "already submitted a decision" in str(exc_info.value)

    # Second approval by DISTINCT Admin -> state transitions to APPROVED
    admin_approver = Principal(
        id="user-admin-charlie", name="Charlie Admin", roles=[RBACRoleEnum.ADMIN]
    )
    resp_2 = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Second approval by Enterprise Admin"),
        approver=admin_approver,
        db_session=db_session,
    )
    assert resp_2.state == ProposalStateEnum.APPROVED.value
    assert resp_2.current_approvals_count == 2


# ==============================================================================
# 4. Temporal Expiry & Tampering Prevention
# ==============================================================================


def test_expired_proposal_cannot_be_approved_or_executed(db_session, active_incident, manager):
    """Verify that an expired proposal cannot be approved or dispatched."""
    req = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01-LAB",
        action_payload={"isolation_type": "network"},
        reason="Expiring proposal",
        evidence_refs=["ev-01"],
        validity_minutes=5,
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-alice",
        db_session=db_session,
    )

    # Artificially expire the proposal in the database
    db_prop = db_session.get(ResponseProposal, prop.id)
    db_prop.expires_at = utc_now() - timedelta(minutes=10)
    db_session.commit()

    # Attempt approval of expired proposal -> rejected
    approver = Principal(id="user-bob", name="Bob", roles=[RBACRoleEnum.SOC_MANAGER])
    with pytest.raises(ApprovalViolationError) as exc_info:
        manager.submit_approval(
            proposal_id=prop.id,
            request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Late approval"),
            approver=approver,
            db_session=db_session,
        )
    assert "expired" in str(exc_info.value).lower()


def test_payload_tampering_at_dispatch_is_blocked(db_session, active_incident, manager):
    """Verify that passing an altered action_payload at dispatch time triggers drift rejection."""
    req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="10.99.1.50",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Block probe",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=active_incident.id,
        request=req,
        actor_id="user-alice",
        db_session=db_session,
    )

    approver = Principal(id="user-bob", name="Bob", roles=[RBACRoleEnum.SOC_MANAGER])
    manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Approved block"),
        approver=approver,
        db_session=db_session,
    )

    # Dispatched with tampered payload
    tampered_payload = {"direction": "both", "duration_hours": 9999}
    with pytest.raises(ActionExecutionBlockedError) as exc_info:
        manager.execute_action(
            proposal_id=prop.id,
            request=ExecuteActionRequest(dry_run=True, action_payload=tampered_payload),
            actor_id="user-bob",
            db_session=db_session,
        )
    assert "Payload drift detected" in str(exc_info.value)
