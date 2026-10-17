"""CyberSentinel AI — Integration Tests: Investigation REST API Endpoints (Phase 5)"""

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
    AgentRun,
    Base,
    Detection,
    Incident,
    IncidentDetection,
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


def test_start_and_query_investigation_api(api_test_db):
    """Verify POST /api/v1/incidents/{id}/investigations and GET /api/v1/investigations/{run_id}."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-api-01",
        title="Lateral Movement Lead",
        status=IncidentStateEnum.TRIAGE.value,
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    det = Detection(
        id="det-api-01",
        rule_id="sigma-wmi-exec",
        rule_version="1.0",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    link = IncidentDetection(
        incident_id=inc.id,
        detection_id=det.id,
        link_reason="Correlated",
        linked_by="engine",
        linked_at=now,
    )
    api_test_db.add_all([inc, det, link])
    api_test_db.commit()

    # 1. Start investigation with analyst role
    res = client.post(
        f"/api/v1/incidents/{inc.id}/investigations",
        json={"task_type": "comprehensive_triage", "budget_limit_usd": 1.5},
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 201
    data = res.json()
    assert "run_id" in data
    assert data["state"] == "COMPLETED"
    run_id = data["run_id"]

    # 2. Query status
    res_status = client.get(
        f"/api/v1/investigations/{run_id}",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["run_id"] == run_id
    assert status_data["state"] == "COMPLETED"

    # 3. Query findings
    res_findings = client.get(
        f"/api/v1/investigations/{run_id}/findings",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_findings.status_code == 200
    findings_data = res_findings.json()
    assert findings_data["findings_count"] > 0
    assert len(findings_data["findings"]) > 0

    # 4. Query summary
    res_summary = client.get(
        f"/api/v1/investigations/{run_id}/summary",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_summary.status_code == 200
    summary_data = res_summary.json()
    assert "observed_facts" in summary_data
    assert "hypotheses" in summary_data


def test_list_investigation_runs_api(api_test_db):
    """Verify analysts can list bounded investigation runs for the workspace."""
    now = datetime.now(timezone.utc)
    run = AgentRun(
        id="run-api-list-01",
        incident_id=None,
        task_type="triage",
        state="COMPLETED",
        model_ref="mock-1",
        template_version="1.0",
        budget_json={"max_tokens": 500},
        started_at=now,
        finished_at=now,
    )
    api_test_db.add(run)
    api_test_db.commit()

    response = client.get(
        "/api/v1/investigations?limit=10",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["investigations"][0]["id"] == run.id
    assert data["investigations"][0]["budget"] == {"max_tokens": 500}


def test_review_investigation_api(api_test_db):
    """Verify POST /api/v1/investigations/{run_id}/review transitions incident and records audit."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-api-rev-01",
        title="Web Exploit Lead",
        status=IncidentStateEnum.TRIAGE.value,
        severity="medium",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    run = AgentRun(
        id="run-api-rev-01",
        incident_id=inc.id,
        task_type="triage",
        state="COMPLETED",
        model_ref="mock-1",
        template_version="1.0",
        budget_json={},
        started_at=now,
        finished_at=now,
    )
    api_test_db.add_all([inc, run])
    api_test_db.commit()

    review_payload = {
        "decision": "ACCEPTED",
        "review_notes": "Confirmed exploit pattern. Transitioning to active investigation.",
        "target_lifecycle_transition": "INVESTIGATING",
        "expected_version": 1,
    }

    res = client.post(
        f"/api/v1/investigations/{run.id}/review",
        json=review_payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ACCEPTED"
    assert data["lifecycle_transition"]["new_status"] == "INVESTIGATING"

    # Verify incident updated in DB
    updated = api_test_db.get(Incident, inc.id)
    assert updated.status == "INVESTIGATING"
    assert updated.version == 2


def test_cancel_investigation_api(api_test_db):
    """Verify POST /api/v1/investigations/{run_id}/cancel cancels an ongoing run."""
    now = datetime.now(timezone.utc)
    run = AgentRun(
        id="run-api-cancel-01",
        incident_id="inc-001",
        task_type="triage",
        state="RUNNING",
        model_ref="mock-1",
        template_version="1.0",
        budget_json={},
        started_at=now,
    )
    api_test_db.add(run)
    api_test_db.commit()

    res = client.post(
        f"/api/v1/investigations/{run.id}/cancel",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "CANCELLED"

    updated_run = api_test_db.get(AgentRun, run.id)
    assert updated_run.state == "CANCELLED"
