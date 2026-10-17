"""CyberSentinel AI — Integration Tests: AI Provider & Incident Triage API (Sprint 15)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.4-TRIAGE-AGENT
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.persistence.database import get_db
from services.persistence.models import (
    AuditEvent,
    Base,
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
    IncidentTriageAssessmentModel,
)

client = TestClient(app)


@pytest.fixture
def triage_test_db():
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


def _seed_incident(db, inc_id="inc-api-01", severity="high"):
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Kerberoasting & Lateral Movement",
        status="TRIAGE",
        severity=severity,
        confidence=0.88,
        first_seen=now,
        last_seen=now,
    )
    db.add(incident)

    det = Detection(
        id=f"det-{uuid4().hex[:8]}",
        rule_id="sigma-kerberoast-01",
        rule_version="1.0",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db.add(det)

    inc_det = IncidentDetection(
        incident_id=inc_id,
        detection_id=det.id,
        link_reason="correlated",
        linked_by="system",
    )
    db.add(inc_det)

    ev = Evidence(
        id=f"ev-{uuid4().hex[:8]}",
        incident_id=inc_id,
        evidence_type="log_event",
        source_ref="security_event_log",
        checksum="sha256:444",
        provenance_json={"event_id": 4769, "service_name": "MSSQLSvc"},
        created_by="system",
    )
    db.add(ev)

    ent = IncidentEntity(
        incident_id=inc_id,
        entity_type="ip",
        entity_key="10.0.0.50",
        relation="source",
        first_seen=now,
        last_seen=now,
    )
    db.add(ent)
    db.commit()
    return incident


def test_execute_incident_triage_endpoint(triage_test_db):
    """Verify POST /api/v1/incidents/{incident_id}/triage executes and persists triage."""
    inc = _seed_incident(triage_test_db, inc_id="inc-triage-post-01")

    res = client.post(
        f"/api/v1/incidents/{inc.id}/triage?force_fallback=true",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == inc.id
    assert "summary" in data
    assert "suspected_activity" in data
    assert data["confidence"] > 0.0
    assert data["recommended_priority"] in ("P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW")
    assert "risk_assessment" in data
    assert data["is_fallback"] is True

    # Verify persistence in database
    stmt = select(IncidentTriageAssessmentModel).where(
        IncidentTriageAssessmentModel.incident_id == inc.id
    )
    persisted = triage_test_db.execute(stmt).scalars().first()
    assert persisted is not None
    assert persisted.id == data["id"]
    assert persisted.recommended_priority == data["recommended_priority"]

    # Verify immutable audit event
    audit_stmt = select(AuditEvent).where(
        AuditEvent.object_id == inc.id,
        AuditEvent.action == "incident:triage_completed",
    )
    audit = triage_test_db.execute(audit_stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "SUCCESS"


def test_get_current_incident_triage_endpoint(triage_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/triage auto-triages and retrieves assessment."""
    inc = _seed_incident(triage_test_db, inc_id="inc-triage-get-01")

    # First call with auto_triage=True (auto-creates)
    res = client.get(
        f"/api/v1/incidents/{inc.id}/triage?auto_triage=true&force_fallback=true",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    triage_id = data["id"]

    # Second call fetches the persisted assessment
    res2 = client.get(
        f"/api/v1/incidents/{inc.id}/triage",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["id"] == triage_id


def test_get_current_incident_triage_not_found(triage_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/triage returns 404 when auto_triage=False and none exists."""
    inc = _seed_incident(triage_test_db, inc_id="inc-triage-notfound-01")

    res = client.get(
        f"/api/v1/incidents/{inc.id}/triage?auto_triage=false",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 404
    data = res.json()
    msg = data.get("message") or data.get("detail", "")
    assert "No triage assessment found" in msg


def test_get_incident_triage_history_endpoint(triage_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/triage/history returns paginated results."""
    inc = _seed_incident(triage_test_db, inc_id="inc-triage-hist-01")

    # Run triage twice
    client.post(
        f"/api/v1/incidents/{inc.id}/triage?force_fallback=true",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    client.post(
        f"/api/v1/incidents/{inc.id}/triage?force_fallback=true",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )

    res = client.get(
        f"/api/v1/incidents/{inc.id}/triage/history?limit=10&offset=0",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    assert data["total"] == 2
    assert len(data["assessments"]) == 2


def test_get_triage_provider_diagnostics_endpoint(triage_test_db):
    """Verify GET /api/v1/triage/providers returns secret-safe provider info and safety invariants."""
    res = client.get(
        "/api/v1/triage/providers",
        headers={"X-Operator-Role": "ADMIN"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "primary_provider" in data
    assert "fallback_provider" in data
    assert data["safety_invariants"]["LIVE_RESPONSE_DISABLED"] is True
    assert data["safety_invariants"]["deterministic_risk_authoritative"] is True
    assert data["safety_invariants"]["read_only_tools_enforced"] is True


def test_triage_rbac_protection(triage_test_db):
    """Verify unauthorized role cannot execute or inspect triage."""
    inc = _seed_incident(triage_test_db, inc_id="inc-triage-rbac-01")

    # Viewer or missing role
    res = client.post(
        f"/api/v1/incidents/{inc.id}/triage",
        headers={"X-Operator-Role": "GUEST"},
    )
    assert res.status_code in (401, 403)
