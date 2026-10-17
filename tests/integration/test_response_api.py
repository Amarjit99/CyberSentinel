"""CyberSentinel AI — Integration Tests: Response REST API Endpoints (Phase 6)"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import IncidentStateEnum
from services.persistence.database import get_db
from services.persistence.models import (
    AgentFinding,
    AgentRun,
    Base,
    Incident,
    IncidentEntity,
)

client = TestClient(app)


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
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-api-resp-01",
        title="Active Beaconing Investigation",
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


def test_get_response_action_catalogue_api():
    """Verify GET /api/v1/response/catalogue returns bounded safe catalogue."""
    res = client.get(
        "/api/v1/response/catalogue",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    catalogue = res.json()
    assert isinstance(catalogue, list)
    assert len(catalogue) >= 10
    action_types = [item["action_type"] for item in catalogue]
    assert "isolate_host" in action_types
    assert "block_ip" in action_types
    assert "disable_user_account" in action_types


def test_create_and_list_proposals_api(api_test_db, active_incident):
    """Verify POST and GET /api/v1/incidents/{id}/proposals."""
    # 1. Create valid proposal
    create_payload = {
        "action_type": "isolate_host",
        "target_entity": "WORKSTATION-09",
        "action_payload": {"isolation_type": "network", "allow_soc_management": True},
        "reason": "Host beaconing detected matching adversary C2",
        "evidence_refs": ["ev-c2-01"],
        "validity_minutes": 45,
    }
    res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == active_incident.id
    assert data["action_type"] == "isolate_host"
    assert data["risk"] == "Tier 2"
    assert data["state"] == "PENDING"
    assert len(data["action_payload_hash"]) == 64
    proposal_id = data["id"]

    # 2. List proposals for incident
    list_res = client.get(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert list_res.status_code == 200
    proposals = list_res.json()
    assert len(proposals) == 1
    assert proposals[0]["id"] == proposal_id

    # 3. Get single proposal details
    get_res = client.get(
        f"/api/v1/proposals/{proposal_id}",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == proposal_id


def test_create_proposal_validation_errors(api_test_db, active_incident):
    """Verify unknown action or missing required parameters return 422."""
    # Unknown action
    bad_action_payload = {
        "action_type": "reformat_disk",
        "target_entity": "SERVER-01",
        "action_payload": {},
        "reason": "Invalid action proposal",
        "evidence_refs": ["ev-01"],
    }
    res_bad = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=bad_action_payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_bad.status_code == 422

    # Missing required parameter in payload (block_ip requires duration_hours)
    missing_param_payload = {
        "action_type": "block_ip",
        "target_entity": "198.51.100.22",
        "action_payload": {"direction": "both"},
        "reason": "Block IP missing duration",
        "evidence_refs": ["ev-01"],
    }
    res_missing = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=missing_param_payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_missing.status_code == 422


def test_generate_playbook_proposals_api(api_test_db, active_incident):
    """Verify POST /api/v1/incidents/{id}/proposals/generate synthesizes proposals from findings."""
    now = datetime.now(timezone.utc)
    run = AgentRun(
        id="run-synth-01",
        incident_id=active_incident.id,
        task_type="triage",
        state="COMPLETED",
        model_ref="mock-v1",
        template_version="1.0",
        budget_json={},
        started_at=now,
        finished_at=now,
    )
    finding = AgentFinding(
        id="find-synth-01",
        run_id=run.id,
        finding_type="detection_analysis",
        claim="Malicious beaconing detected connecting to remote command and control infrastructure",
        confidence=0.95,
        evidence_refs_json=["ev-net-01"],
        created_at=now,
    )
    entity = IncidentEntity(
        incident_id=active_incident.id,
        entity_type="ip",
        entity_key="203.0.113.195",
        relation="c2_destination",
        first_seen=now,
        last_seen=now,
    )
    api_test_db.add_all([run, finding, entity])
    api_test_db.commit()

    res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals/generate",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    generated = res.json()
    assert len(generated) > 0
    assert any(p["action_type"] == "block_ip" for p in generated)


def test_approve_revoke_and_execute_api(api_test_db, active_incident):
    """Verify approval, revocation, and simulated execution via REST API."""
    # 1. Create Tier 2 proposal
    create_payload = {
        "action_type": "block_ip",
        "target_entity": "198.51.100.33",
        "action_payload": {"direction": "both", "duration_hours": 24},
        "reason": "Suspicious ingress probe",
        "evidence_refs": ["ev-probe-01"],
    }
    create_res = client.post(
        f"/api/v1/incidents/{active_incident.id}/proposals",
        json=create_payload,
        headers={"Authorization": "Bearer analyst-user-alice"},
    )
    assert create_res.status_code == 200
    prop_id = create_res.json()["id"]

    # 2. Approve proposal with distinct manager token
    approve_res = client.post(
        f"/api/v1/proposals/{prop_id}/approve",
        json={
            "decision": "APPROVED",
            "reason": "Firewall block approved per security policy",
        },
        headers={"Authorization": "Bearer admin-user-bob"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["state"] == "APPROVED"

    # 3. Dispatch to execution boundary in dry_run mode
    exec_res = client.post(
        f"/api/v1/response-actions/{prop_id}/execute",
        json={"dry_run": True},
        headers={"Authorization": "Bearer admin-user-bob"},
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["state"] == "SIMULATED"
    assert exec_data["result"]["live_response_disabled"] is True
    assert exec_data["result"]["status"] == "SIMULATED_SUCCESS"
