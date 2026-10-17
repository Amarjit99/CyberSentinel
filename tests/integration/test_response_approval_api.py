"""CyberSentinel AI — Integration Tests: Response Approval & Controlled Execution API (Sprint 20)

Verifies:
- REST API response proposal lifecycle (create -> approve -> lab execute).
- Bounded response execution history endpoint /api/v1/incidents/{incident_id}/response-history.
- Action details endpoint /api/v1/response-actions/{action_id}.
- Alias execution endpoint /api/v1/proposals/{proposal_id}/execute.
- Idempotent execution suppression of duplicate requests.
- Target allowlist enforcement in lab simulation: synthetic targets succeed, production targets fail.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import IncidentStateEnum
from services.persistence.database import get_db
from services.persistence.models import Base, Incident

client = TestClient(app)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def api_test_db():
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
def active_incident(api_test_db):
    now = utc_now()
    inc = Incident(
        id="inc-api-test-01",
        title="Simulated Lab Compromise and Lateral Movement",
        status=IncidentStateEnum.INVESTIGATING.value,
        severity="high",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    api_test_db.add(inc)
    api_test_db.commit()
    api_test_db.refresh(inc)
    return inc


def test_api_full_response_proposal_and_lab_execution_flow(api_test_db, active_incident):
    """End-to-end API test: create proposal -> approve -> execute in lab mode."""
    # 1. Create proposal for a synthetic lab host
    create_payload = {
        "action_type": "isolate_host",
        "target_entity": "WORKSTATION-01-LAB",
        "action_payload": {"isolation_type": "network", "allow_soc_management": True},
        "reason": "Host exhibiting simulated C2 traffic",
        "evidence_refs": ["ev-c2-01"],
        "validity_minutes": 60,
    }
    create_res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert create_res.status_code == 200
    prop_data = create_res.json()
    assert prop_data["state"] == "PENDING"
    assert prop_data["action_type"] == "isolate_host"
    assert prop_data["risk"] == "Tier 2"
    assert prop_data["target_entity"] == "WORKSTATION-01-LAB"
    prop_id = prop_data["id"]

    # 2. Get proposal details
    get_res = client.get(
        f"/api/v1/proposals/{prop_id}",
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == prop_id

    # 3. Approve proposal with distinct SOC manager token
    approve_res = client.post(
        f"/api/v1/proposals/{prop_id}/approve",
        json={
            "decision": "APPROVED",
            "reason": "Approved for lab isolation testing",
            "expected_payload_hash": prop_data["action_payload_hash"],
        },
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["state"] == "APPROVED"
    assert approve_res.json()["current_approvals_count"] == 1

    # 4. Dispatch to lab execution via primary endpoint
    exec_res = client.post(
        f"/api/v1/response-actions/{prop_id}/execute",
        json={"dry_run": True, "target_environment": "lab", "idempotency_key": f"key-{prop_id}"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["state"] == "SIMULATED"
    assert exec_data["result"]["status"] == "SIMULATED_SUCCESS"
    assert exec_data["result"]["adapter"] == "LabResponseAdapter"
    action_id = exec_data["action_id"]

    # 5. Retrieve response action details
    action_res = client.get(
        f"/api/v1/response-actions/{action_id}",
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert action_res.status_code == 200
    assert action_res.json()["id"] == action_id
    assert action_res.json()["state"] == "SIMULATED"

    # 6. Retrieve incident response history
    history_res = client.get(
        f"/api/v1/incidents/{active_incident.id}/response-history",
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert history_res.status_code == 200
    history = history_res.json()
    assert len(history) >= 1
    assert any(h["id"] == action_id for h in history)


def test_api_execute_proposal_alias_endpoint(api_test_db, active_incident):
    """Verify alias endpoint /api/v1/proposals/{proposal_id}/execute dispatches properly."""
    create_payload = {
        "action_type": "block_ip",
        "target_entity": "10.99.1.50",
        "action_payload": {"direction": "both", "duration_hours": 12},
        "reason": "Block synthetic probe",
        "evidence_refs": ["ev-01"],
    }
    create_res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    prop_id = create_res.json()["id"]

    # Approve
    client.post(
        f"/api/v1/proposals/{prop_id}/approve",
        json={"decision": "APPROVED", "reason": "Approved block"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )

    # Execute via alias endpoint
    exec_res = client.post(
        f"/api/v1/proposals/{prop_id}/execute",
        json={"dry_run": True, "target_environment": "lab"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert exec_res.status_code == 200
    assert exec_res.json()["state"] == "SIMULATED"


def test_api_idempotency_suppresses_duplicate_execution(api_test_db, active_incident):
    """Verify that duplicate execute requests with the same idempotency key return the existing record."""
    create_payload = {
        "action_type": "block_ip",
        "target_entity": "10.99.1.50",
        "action_payload": {"direction": "both", "duration_hours": 12},
        "reason": "Idempotent block testing",
        "evidence_refs": ["ev-01"],
    }
    create_res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    prop_id = create_res.json()["id"]

    # Approve
    client.post(
        f"/api/v1/proposals/{prop_id}/approve",
        json={"decision": "APPROVED", "reason": "Approved block"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )

    # First execution
    idempotency_key = f"idem-key-{prop_id}"
    res_1 = client.post(
        f"/api/v1/proposals/{prop_id}/execute",
        json={"dry_run": True, "idempotency_key": idempotency_key},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert res_1.status_code == 200
    action_id_1 = res_1.json()["action_id"]

    # Second execution with same idempotency key
    res_2 = client.post(
        f"/api/v1/proposals/{prop_id}/execute",
        json={"dry_run": True, "idempotency_key": idempotency_key},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert res_2.status_code == 200
    data_2 = res_2.json()
    assert data_2["action_id"] == action_id_1
    assert "Duplicate execution request suppressed" in data_2["message"]


def test_api_production_target_rejected_in_lab_execution(api_test_db, active_incident):
    """Verify that targeting a production asset during lab execution returns state=FAILED with REJECTED_PRODUCTION_TARGET."""
    create_payload = {
        "action_type": "isolate_host",
        "target_entity": "PROD-DC01",
        "action_payload": {"isolation_type": "network"},
        "reason": "Attempting to isolate production DC in lab mode",
        "evidence_refs": ["ev-dc-01"],
    }
    create_res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"Authorization": "Bearer analyst-alice-token"},
    )
    assert create_res.status_code == 200
    prop_id = create_res.json()["id"]

    # Approve
    client.post(
        f"/api/v1/proposals/{prop_id}/approve",
        json={"decision": "APPROVED", "reason": "Approved"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )

    # Execute in lab mode -> rejected by lab allowlist
    exec_res = client.post(
        f"/api/v1/proposals/{prop_id}/execute",
        json={"dry_run": True, "target_environment": "lab"},
        headers={"Authorization": "Bearer manager-bob-token"},
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["state"] == "FAILED"
    assert exec_data["result"]["status"] == "REJECTED_PRODUCTION_TARGET"
    assert "production indicator" in exec_data["result"]["error"].lower()
