"""CyberSentinel AI — Integration Tests: Explainable Incident Risk API (Sprint 14)"""

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
    Incident,
    IncidentDetection,
    IncidentRiskAssessmentModel,
)

client = TestClient(app)


@pytest.fixture
def risk_test_db():
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


def test_calculate_risk_assessment_endpoint(risk_test_db):
    """Verify POST /api/v1/incidents/{incident_id}/risk-assessment calculates and persists score."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Cobalt Strike C2 Beaconing",
        status="TRIAGE",
        severity="critical",
        confidence=0.95,
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(incident)

    det = Detection(
        id="det-c2",
        rule_id="d75a894b-1428-4f81-a953-bca908291410",  # Active C2 Sigma rule
        rule_version="1.0",
        severity="critical",
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(det)

    inc_det = IncidentDetection(
        incident_id=inc_id,
        detection_id=det.id,
        link_reason="C2 correlation",
        linked_by="correlation_engine",
    )
    risk_test_db.add(inc_det)
    risk_test_db.commit()

    res = client.post(
        f"/api/v1/incidents/{inc_id}/risk-assessment",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert 0.0 <= data["overall_score"] <= 100.0
    assert data["risk_band"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "detection_severity" in data["factors"]
    assert "attack_context" in data["factors"]
    assert len(data["primary_drivers"]) > 0

    # Verify database persistence
    saved = risk_test_db.execute(
        select(IncidentRiskAssessmentModel).where(IncidentRiskAssessmentModel.incident_id == inc_id)
    ).scalars().first()
    assert saved is not None
    assert saved.overall_score == data["overall_score"]

    # Verify audit event creation
    audit = risk_test_db.execute(
        select(AuditEvent).where(
            AuditEvent.object_id == inc_id,
            AuditEvent.action == "incident:risk_assessed",
        )
    ).scalars().first()
    assert audit is not None
    assert audit.outcome == "SUCCESS"


def test_get_current_risk_assessment_endpoint(risk_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/risk-assessment retrieves latest record."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Kerberoasting Detection",
        status="INVESTIGATING",
        severity="high",
        confidence=0.9,
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(incident)
    risk_test_db.commit()

    # Pre-calculate via GET with auto_calculate=True
    res = client.get(
        f"/api/v1/incidents/{inc_id}/risk-assessment",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert "overall_score" in data
    assert "risk_band" in data


def test_get_risk_assessment_history_endpoint(risk_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/risk-assessment/history returns paginated history."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Multi-Assessment Incident",
        status="INVESTIGATING",
        severity="medium",
        confidence=0.8,
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(incident)
    risk_test_db.commit()

    # Trigger 2 consecutive assessments
    client.post(
        f"/api/v1/incidents/{inc_id}/risk-assessment",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    client.post(
        f"/api/v1/incidents/{inc_id}/risk-assessment",
        headers={"X-Operator-Role": "SOC_MANAGER"},
    )

    res = client.get(
        f"/api/v1/incidents/{inc_id}/risk-assessment/history?limit=10&offset=0",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert data["total"] == 2
    assert len(data["assessments"]) == 2


def test_get_risk_explanation_endpoint(risk_test_db):
    """Verify GET /api/v1/incidents/{incident_id}/risk-assessment/explanation provides weights and drivers."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Explained Incident",
        status="TRIAGE",
        severity="high",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(incident)
    risk_test_db.commit()

    res = client.get(
        f"/api/v1/incidents/{inc_id}/risk-assessment/explanation",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert "formula_description" in data
    assert len(data["weights_used"]) == 7
    assert len(data["factors"]) == 7


def test_risk_endpoints_404_for_unknown_incident(risk_test_db):
    """Verify 404 error is returned when querying risk assessment for non-existent incident."""
    res = client.get(
        "/api/v1/incidents/inc-nonexistent-12345/risk-assessment",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 404
    data = res.json()
    assert "not found" in data["message"].lower()


def test_risk_endpoints_rbac_enforcement(risk_test_db):
    """Verify unauthorized roles cannot calculate or access risk assessments."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="RBAC Guarded Incident",
        status="NEW",
        severity="low",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_test_db.add(incident)
    risk_test_db.commit()

    # VIEWER role is prohibited from risk calculation endpoints
    res = client.post(
        f"/api/v1/incidents/{inc_id}/risk-assessment",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res.status_code == 403
