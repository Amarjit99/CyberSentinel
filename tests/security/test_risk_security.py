"""CyberSentinel AI — Security Tests: Explainable Incident Risk Engine (Sprint 14)"""

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.agents.tools import ReadOnlyInvestigationTools
from services.persistence.database import get_db
from services.persistence.models import (
    Base,
    Incident,
    IncidentEntity,
    IncidentRiskAssessmentModel,
    ResponseProposal,
)
from services.response.manager import ResponseManager
from services.risk import DeterministicRiskEngine, IncidentRiskBandEnum

client = TestClient(app)


@pytest.fixture
def risk_security_db():
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


def test_safety_invariant_live_response_disabled_during_risk_scoring():
    """Verify LIVE_RESPONSE_DISABLED=true invariant is strictly respected."""
    assert os.environ.get("LIVE_RESPONSE_DISABLED", "true").lower() == "true"
    mgr = ResponseManager()
    assert mgr.live_response_disabled is True


def test_critical_risk_score_cannot_bypass_approval_policy(risk_security_db):
    """Verify that even a CRITICAL risk score cannot auto-execute or bypass Tier 2/3 approvals."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Critical Ransomware Incident",
        status="TRIAGE",
        severity="critical",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_security_db.add(incident)

    # Persist a CRITICAL risk assessment
    crit_assessment = IncidentRiskAssessmentModel(
        id=f"ira-{uuid4().hex[:24]}",
        incident_id=inc_id,
        overall_score=98.5,
        risk_band=IncidentRiskBandEnum.CRITICAL.value,
        policy_version="1.0.0",
        factors_json={},
        primary_drivers_json=["Ransomware confirmed"],
        uncertainties_json=[],
        limitations_json=[],
        evidence_refs_json=[],
        assessed_by="system:risk_engine",
        assessed_at=now,
    )
    risk_security_db.add(crit_assessment)

    # Create a Tier 2 containment proposal for this incident
    proposal = ResponseProposal(
        id=f"prop-{uuid4().hex[:12]}",
        incident_id=inc_id,
        action_type="isolate_host",
        action_payload_hash="dummy-hash",
        risk="Tier 2",
        state="PENDING",
        created_by="agent:response",
        created_at=now,
        expires_at=now,
    )
    risk_security_db.add(proposal)
    risk_security_db.commit()

    # Attempting to execute the proposal without human approval must fail
    res = client.post(
        f"/api/v1/response-actions/{proposal.id}/execute",
        json={"idempotency_key": "sec-test-key", "force": False},
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    # Blocked by safety governance: proposal is not in APPROVED state
    assert res.status_code == 400


def test_missing_intelligence_is_not_treated_as_benign(risk_security_db):
    """Verify that absence of threat intelligence produces a neutral baseline, not a zero/benign score."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Unknown IP Incident",
        status="NEW",
        severity="medium",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_security_db.add(incident)

    # Unknown IP not in any intelligence feed
    entity = IncidentEntity(
        incident_id=inc_id,
        entity_type="ipv4",
        entity_key="198.51.100.99",
        relation="observed",
        first_seen=now,
        last_seen=now,
    )
    risk_security_db.add(entity)
    risk_security_db.commit()

    engine = DeterministicRiskEngine()
    assessment = engine.assess_incident(incident, risk_security_db, persist=False)

    ti_factor = assessment.factors["threat_intel_context"]
    # Baseline must be non-zero (35.0 neutral baseline)
    assert ti_factor.raw_score == 35.0
    # Must flag absence of proof
    assert any("not found in local threat intel feeds" in u for u in ti_factor.uncertainties)


def test_phase5_agent_tool_retrieves_real_risk_assessment(risk_security_db):
    """Verify Phase 5 ReadOnlyInvestigationTools queries the real risk engine without hallucinating."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Agent Investigated Incident",
        status="INVESTIGATING",
        severity="high",
        confidence=0.9,
        first_seen=now,
        last_seen=now,
    )
    risk_security_db.add(incident)
    risk_security_db.commit()

    tools = ReadOnlyInvestigationTools(session=risk_security_db, incident_id=inc_id)
    result = tools.execute_tool("get_incident_risk_assessment")

    assert "assessment_id" in result
    assert result["incident_id"] == inc_id
    assert 0.0 <= result["overall_score"] <= 100.0
    assert result["risk_band"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "primary_drivers" in result
    assert "uncertainties" in result


def test_history_pagination_bounds_enforced():
    """Verify that history pagination parameter limits are validated."""
    # limit > 100 should be rejected by FastAPI Query validation
    res = client.get(
        "/api/v1/incidents/inc-test/risk-assessment/history?limit=500",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 422
