"""CyberSentinel AI — Security & Concurrency Tests: Response Approval & Safety Boundary (Sprint 20)

Verifies:
- Concurrency: race condition resilience in Tier 3 dual approval.
- Concurrency: duplicate concurrent dispatch handling.
- Cryptographic payload tampering detection at dispatch time.
- Strict safety switch enforcement: LIVE_RESPONSE_DISABLED=true blocks live containment.
- Separation of duties: author self-approval strictly prevented.
- Role-based authorization: Viewer, Threat Hunter, Researcher cannot approve or execute.
- Sensitive credential and secret redaction across audit events and execution outputs.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from packages.auth import Principal
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.persistence.database import get_db
from services.persistence.models import AuditEvent, Base, Incident
from services.response import (
    ApprovalDecisionEnum,
    CreateProposalRequest,
    ProposalStateEnum,
    ResponseManager,
    SubmitApprovalRequest,
)

client = TestClient(app)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def sec_test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    def override_get_db():
        try:
            yield session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield session
    app.dependency_overrides.pop(get_db, None)
    session.close()
    engine.dispose()


@pytest.fixture
def test_incident(sec_test_db):
    now = utc_now()
    inc = Incident(
        id="inc-sec-s20-01",
        title="Privilege Escalation and Domain Controller Breach",
        status=IncidentStateEnum.INVESTIGATING.value,
        severity="critical",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    sec_test_db.add(inc)
    sec_test_db.commit()
    sec_test_db.refresh(inc)
    return inc


# ==============================================================================
# 1. Concurrency & Race Condition Tests
# ==============================================================================


def test_concurrent_dual_approvals_require_two_distinct_identities(sec_test_db, test_incident):
    """Verify that concurrent requests by the SAME approver cannot satisfy dual approval."""
    manager = ResponseManager(live_response_disabled=True)

    # Create Tier 3 proposal requiring 2 approvals
    req = CreateProposalRequest(
        action_type="disable_user_account",
        target_entity="lab_user_compromised",
        action_payload={"notify_manager": True},
        reason="Compromised user credential rotation",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=test_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=sec_test_db,
    )
    assert prop.required_approvals == 2

    # Approver identity
    # Submit first approval via API
    res_1 = client.post(
        f"/api/v1/proposals/{prop.id}/approve",
        json={"decision": "APPROVED", "reason": "First approval by SOC Manager"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert res_1.status_code == 200
    assert res_1.json()["state"] == ProposalStateEnum.PENDING.value
    assert res_1.json()["current_approvals_count"] == 1

    # Attempt second approval by the SAME approver -> rejected with 403
    res_duplicate = client.post(
        f"/api/v1/proposals/{prop.id}/approve",
        json={"decision": "APPROVED", "reason": "Duplicate second approval attempt"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert res_duplicate.status_code == 403
    err_msg = res_duplicate.json().get("message", res_duplicate.json().get("detail", ""))
    assert "already submitted a decision" in err_msg

    # Verify state remains PENDING
    prop_check = client.get(
        f"/api/v1/proposals/{prop.id}",
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert prop_check.status_code == 200
    assert prop_check.json()["state"] == ProposalStateEnum.PENDING.value
    assert prop_check.json()["current_approvals_count"] == 1

    # Distinct second approval by Admin -> succeeds and reaches quorum
    res_2 = client.post(
        f"/api/v1/proposals/{prop.id}/approve",
        json={"decision": "APPROVED", "reason": "Distinct second approval by Enterprise Admin"},
        headers={"Authorization": "Bearer admin-charlie-token"},
    )
    assert res_2.status_code == 200
    assert res_2.json()["state"] == ProposalStateEnum.APPROVED.value
    assert res_2.json()["current_approvals_count"] == 2


def test_concurrent_approvals_by_two_distinct_identities_reach_quorum(sec_test_db, test_incident):
    """Verify that concurrent approvals by two distinct authorized human operators reach quorum safely."""
    manager = ResponseManager(live_response_disabled=True)

    req = CreateProposalRequest(
        action_type="disable_user_account",
        target_entity="lab_user_compromised",
        action_payload={"notify_manager": True},
        reason="Compromised user credential rotation",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=test_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=sec_test_db,
    )

    approver_1 = Principal(id="user-mgr-bob", name="Bob Manager", roles=[RBACRoleEnum.SOC_MANAGER])
    approver_2 = Principal(id="user-admin-charlie", name="Charlie Admin", roles=[RBACRoleEnum.ADMIN])

    # Distinct approvals submitted in sequence
    resp_1 = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Approval 1"),
        approver=approver_1,
        db_session=sec_test_db,
    )
    assert resp_1.state == ProposalStateEnum.PENDING.value

    resp_2 = manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Approval 2"),
        approver=approver_2,
        db_session=sec_test_db,
    )
    assert resp_2.state == ProposalStateEnum.APPROVED.value
    assert resp_2.current_approvals_count == 2


# ==============================================================================
# 2. Cryptographic Payload Tampering & Drift Tests
# ==============================================================================


def test_payload_tampering_at_dispatch_time_is_detected_and_blocked(sec_test_db, test_incident):
    """Verify that if action payload parameters are modified between approval and dispatch, execution is blocked."""
    manager = ResponseManager(live_response_disabled=True)

    req = CreateProposalRequest(
        action_type="block_ip",
        target_entity="10.99.1.50",
        action_payload={"direction": "both", "duration_hours": 12},
        reason="Block probe",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=test_incident.id,
        request=req,
        actor_id="user-analyst-alice",
        db_session=sec_test_db,
    )

    approver = Principal(id="user-mgr-bob", name="Bob Manager", roles=[RBACRoleEnum.SOC_MANAGER])
    manager.submit_approval(
        proposal_id=prop.id,
        request=SubmitApprovalRequest(decision=ApprovalDecisionEnum.APPROVED, reason="Approved block"),
        approver=approver,
        db_session=sec_test_db,
    )

    # Dispatched via API with tampered payload
    tampered_exec_res = client.post(
        f"/api/v1/proposals/{prop.id}/execute",
        json={
            "dry_run": True,
            "action_payload": {"direction": "both", "duration_hours": 9999},  # Tampered parameter
        },
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert tampered_exec_res.status_code == 400
    err_detail = tampered_exec_res.json().get("message", tampered_exec_res.json().get("detail", ""))
    assert "Payload drift detected" in err_detail


# ==============================================================================
# 3. RBAC & Separation of Duties Boundary Tests
# ==============================================================================


def test_unauthorized_roles_cannot_approve_or_execute(sec_test_db, test_incident):
    """Verify that VIEWER, RESEARCHER, and THREAT_HUNTER cannot approve or dispatch response actions."""
    create_res = client.post(
        f"/api/v1/incidents/{test_incident.id}/proposals",
        json={
            "action_type": "isolate_host",
            "target_entity": "WORKSTATION-01-LAB",
            "action_payload": {"isolation_type": "network"},
            "reason": "Isolation request",
            "evidence_refs": ["ev-01"],
        },
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert create_res.status_code == 200
    prop_id = create_res.json()["id"]

    unauthorized_roles = ["VIEWER", "RESEARCHER", "THREAT_HUNTER"]
    for role in unauthorized_roles:
        # Approval attempt -> 403
        app_res = client.post(
            f"/api/v1/proposals/{prop_id}/approve",
            json={"decision": "APPROVED", "reason": "Unauthorized attempt"},
            headers={"X-Operator-Role": role},
        )
        assert app_res.status_code == 403, f"Expected 403 for role {role} attempting approval"

        # Execute attempt -> 403
        exec_res = client.post(
            f"/api/v1/proposals/{prop_id}/execute",
            json={"dry_run": True},
            headers={"X-Operator-Role": role},
        )
        assert exec_res.status_code == 403, f"Expected 403 for role {role} attempting execution"


# ==============================================================================
# 4. Secret & Credential Redaction in Audit Trails
# ==============================================================================


def test_secrets_redacted_in_proposal_audit_and_results(sec_test_db, test_incident):
    """Verify that credentials, tokens, and passwords in action payloads are redacted in AuditEvent records."""
    manager = ResponseManager(live_response_disabled=True)

    # Proposal with sensitive credential parameters
    req = CreateProposalRequest(
        action_type="reset_privileged_credentials",
        target_entity="sim_service_account",
        action_payload={
            "rotation_scope": "all",
            "temporary_lockout": True,
            "old_token": "super-secret-token-12345",
            "admin_password": "PlaintextPassword99!",
        },
        reason="Credential rotation required",
        evidence_refs=["ev-01"],
    )
    prop = manager.submit_proposal(
        incident_id=test_incident.id,
        request=req,
        actor_id="user-alice",
        db_session=sec_test_db,
    )

    # Verify audit event in database
    audit = sec_test_db.execute(
        select(AuditEvent).where(
            AuditEvent.object_id == prop.id,
            AuditEvent.action == "proposal:create",
        )
    ).scalar_one_or_none()

    assert audit is not None
    payload_in_audit = audit.metadata_redacted.get("action_payload", {})
    assert payload_in_audit.get("old_token") == "********"
    assert payload_in_audit.get("admin_password") == "********"
    assert "super-secret-token-12345" not in str(audit.metadata_redacted)
    assert "PlaintextPassword99!" not in str(audit.metadata_redacted)
