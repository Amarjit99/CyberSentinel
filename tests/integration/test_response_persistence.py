"""CyberSentinel AI — Integration Tests: Response Proposals, Approvals & Safety Boundary (Phase 6)

Verifies database persistence, foreign keys, dual-human approval workflow,
proposal state machine, audit trails, and execution safety gating.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.persistence.models import (
    Approval,
    AuditEvent,
    Base,
    Incident,
    ResponseAction,
    ResponseProposal,
)
from services.response import (
    ActionExecutionBlockedError,
    ApprovalDecisionEnum,
    ApprovalViolationError,
    CreateProposalRequest,
    ExecuteActionRequest,
    ResponseManager,
    SubmitApprovalRequest,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def sample_incident(test_db):
    now = utc_now()
    inc = Incident(
        id="inc-test-p6-01",
        title="Host Compromise and C2 Activity",
        status=IncidentStateEnum.INVESTIGATING.value,
        severity="high",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    test_db.add(inc)
    test_db.commit()
    test_db.refresh(inc)
    return inc


def test_proposal_submission_and_persistence(test_db, sample_incident):
    """Verify proposal persistence, payload hash calculation, and incident state sync."""
    manager = ResponseManager(live_response_disabled=True)

    request = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-01",
        action_payload={"isolation_type": "network", "allow_soc_management": True},
        reason="Host exhibits beaconing activity matching Cobalt Strike profile",
        evidence_refs=["ev-beacon-01"],
        validity_minutes=30,
    )

    result = manager.submit_proposal(
        incident_id=sample_incident.id,
        request=request,
        actor_id="user-analyst-alice",
        db_session=test_db,
    )

    # 1. Verify ResponseProposal in database
    db_proposal = test_db.get(ResponseProposal, result.id)
    assert db_proposal is not None
    assert db_proposal.incident_id == sample_incident.id
    assert db_proposal.action_type == "isolate_host"
    assert db_proposal.risk == "Tier 2"
    assert db_proposal.state == "PENDING"
    assert len(db_proposal.action_payload_hash) == 64
    assert db_proposal.created_by == "user-analyst-alice"

    # 2. Verify Incident transitioned to AWAITING_APPROVAL per ADR-0001
    updated_incident = test_db.get(Incident, sample_incident.id)
    assert updated_incident.status == IncidentStateEnum.AWAITING_APPROVAL.value

    # 3. Verify AuditEvent logged
    audit = test_db.execute(
        select(AuditEvent).where(
            AuditEvent.object_id == db_proposal.id,
            AuditEvent.action == "proposal:create",
        )
    ).scalar_one_or_none()
    assert audit is not None
    assert audit.outcome == "SUCCESS"
    assert audit.actor_id == "user-analyst-alice"


def test_dual_human_authorization_for_tier3_proposal(test_db, sample_incident):
    """Verify Tier 3 requires 2 distinct approvers (SOC Manager and Admin) before reaching APPROVED."""
    manager = ResponseManager(live_response_disabled=True)

    # 1. Create Tier 3 proposal (disable_user_account)
    request = CreateProposalRequest(
        action_type="disable_user_account",
        target_entity="john.doe@corp.local",
        action_payload={"notify_manager": True, "lockout_reason": "Credential theft"},
        reason="Compromised executive identity with active data exfiltration",
        evidence_refs=["ev-exfil-01"],
        validity_minutes=60,
    )
    proposal_resp = manager.submit_proposal(
        incident_id=sample_incident.id,
        request=request,
        actor_id="user-analyst-alice",
        db_session=test_db,
    )
    proposal_id = proposal_resp.id

    # 2. First approver: SOC Manager
    manager_approver = Principal(
        id="user-mgr-bob",
        name="Bob Manager",
        roles=[RBACRoleEnum.SOC_MANAGER],
    )
    first_resp = manager.submit_approval(
        proposal_id=proposal_id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.APPROVED,
            reason="Confirmed malicious exfiltration; account disablement approved.",
        ),
        approver=manager_approver,
        db_session=test_db,
    )

    # State must still be PENDING after only 1 approver for Tier 3
    assert first_resp.state == "PENDING"
    assert first_resp.current_approvals_count == 1
    assert first_resp.required_approvals == 2

    # 3. Attempting self-approval by author is blocked
    author_approver = Principal(
        id="user-analyst-alice",
        name="Alice Analyst",
        roles=[RBACRoleEnum.ADMIN],
    )
    with pytest.raises(ApprovalViolationError) as exc_info:
        manager.submit_approval(
            proposal_id=proposal_id,
            request=SubmitApprovalRequest(
                decision=ApprovalDecisionEnum.APPROVED,
                reason="Author attempting approval",
            ),
            approver=author_approver,
            db_session=test_db,
        )
    assert "Separation of duties" in str(exc_info.value)

    # 4. Attempting duplicate approval by same manager is blocked
    with pytest.raises(ApprovalViolationError) as exc_info:
        manager.submit_approval(
            proposal_id=proposal_id,
            request=SubmitApprovalRequest(
                decision=ApprovalDecisionEnum.APPROVED,
                reason="Duplicate approval attempt",
            ),
            approver=manager_approver,
            db_session=test_db,
        )
    assert "already submitted a decision" in str(exc_info.value)

    # 5. Second distinct approver: Security Admin
    admin_approver = Principal(
        id="user-admin-dave",
        name="Dave Admin",
        roles=[RBACRoleEnum.ADMIN],
    )
    second_resp = manager.submit_approval(
        proposal_id=proposal_id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.APPROVED,
            reason="Dual-authorization confirmed; second approval granted.",
        ),
        approver=admin_approver,
        db_session=test_db,
    )

    # Now both approvals are satisfied; proposal is APPROVED
    assert second_resp.state == "APPROVED"
    assert second_resp.current_approvals_count == 2

    # Verify both approvals persisted in Approval table
    approvals_in_db = test_db.execute(
        select(Approval).where(Approval.proposal_id == proposal_id)
    ).scalars().all()
    assert len(approvals_in_db) == 2


def test_rejection_workflow(test_db, sample_incident):
    """Verify proposal rejection transitions proposal state to REJECTED."""
    manager = ResponseManager(live_response_disabled=True)

    request = CreateProposalRequest(
        action_type="block_ip",
        target_entity="198.51.100.77",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Suspicious scan origin",
        evidence_refs=["ev-scan-01"],
    )
    prop = manager.submit_proposal(
        incident_id=sample_incident.id,
        request=request,
        actor_id="user-analyst-alice",
        db_session=test_db,
    )

    approver = Principal(
        id="user-mgr-bob",
        name="Bob Manager",
        roles=[RBACRoleEnum.SOC_MANAGER],
    )
    reject_resp = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.REJECTED,
            reason="IP belongs to authorized customer penetration testing partner.",
        ),
        approver=approver,
        db_session=test_db,
    )

    assert reject_resp.state == "REJECTED"
    db_proposal = test_db.get(ResponseProposal, prop.id)
    assert db_proposal.state == "REJECTED"


def test_safety_disabled_execution_boundary(test_db, sample_incident):
    """Verify LIVE_RESPONSE_DISABLED=true prevents live execution and logs SIMULATED or BLOCKED_SAFETY."""
    manager = ResponseManager(live_response_disabled=True)

    # 1. Create and approve proposal
    request = CreateProposalRequest(
        action_type="isolate_host",
        target_entity="WORKSTATION-02",
        action_payload={"isolation_type": "network"},
        reason="Ransomware containment",
        evidence_refs=["ev-ransomware-01"],
    )
    prop = manager.submit_proposal(
        incident_id=sample_incident.id,
        request=request,
        actor_id="user-alice",
        db_session=test_db,
    )

    approver = Principal(
        id="user-mgr-bob",
        name="Bob Manager",
        roles=[RBACRoleEnum.SOC_MANAGER],
    )
    manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(
            decision=ApprovalDecisionEnum.APPROVED,
            reason="Containment approved",
        ),
        approver=approver,
        db_session=test_db,
    )

    # 2. Execute in dry_run mode -> SIMULATED
    exec_dry = manager.execute_action(
        proposal_id=prop.id,
        request=ExecuteActionRequest(dry_run=True),
        actor_id="user-alice",
        db_session=test_db,
    )
    assert exec_dry["state"] == "SIMULATED"
    assert exec_dry["result"]["live_response_disabled"] is True
    assert exec_dry["result"]["status"] == "SIMULATED_SUCCESS"

    # Verify ResponseAction record in DB
    action_rec = test_db.get(ResponseAction, exec_dry["action_id"])
    assert action_rec is not None
    assert action_rec.state == "SIMULATED"

    # 3. Verify non-approved proposal cannot be executed
    unapproved_req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="198.51.100.99",
        action_payload={"direction": "both", "duration_hours": 24},
        reason="Pending scan",
        evidence_refs=["ev-01"],
    )
    unapproved = manager.submit_proposal(
        incident_id=sample_incident.id,
        request=unapproved_req,
        actor_id="user-alice",
        db_session=test_db,
    )
    with pytest.raises(ActionExecutionBlockedError):
        manager.execute_action(
            proposal_id=unapproved.id,
            request=ExecuteActionRequest(dry_run=True),
            actor_id="user-alice",
            db_session=test_db,
        )
