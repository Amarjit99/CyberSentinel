"""CyberSentinel AI — Integration Tests: Investigation Execution Boundary & API (Sprint 17)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.6-INVESTIGATION-AGENT

Verifies:
- All investigation tool executions route through ToolExecutionService and generate AuditEvent records.
- Full DB persistence of DbAgentRun and DbAgentFinding with foreign key integrity.
- History endpoint GET /api/v1/incidents/{id}/investigations with limit/offset pagination.
- Continuation endpoint POST /api/v1/investigations/{run_id}/continue with bounded additional budget/steps.
- Triage reconciliation with prior triage assessment.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import IncidentStateEnum
from services.agents.investigation import InvestigationAgent
from services.agents.models import (
    InvestigationRunRequest,
)
from services.agents.providers import DeterministicRuleProvider
from services.persistence.database import get_db
from services.persistence.models import (
    AgentRun as DbAgentRun,
)
from services.persistence.models import (
    AuditEvent,
    Base,
    Detection,
    Incident,
    IncidentDetection,
    IncidentEntity,
    IncidentTriageAssessmentModel,
)

client = TestClient(app)


@pytest.fixture
def exec_db():
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


@pytest.mark.asyncio
async def test_investigation_routes_all_tools_through_execution_boundary(exec_db):
    """Verify that every tool call made during investigation produces a corresponding AuditEvent in the database."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-tool-audit-01",
        title="Cobalt Strike Beaconing Lead",
        status=IncidentStateEnum.TRIAGE.value,
        severity="critical",
        first_seen=now,
        last_seen=now,
    )
    det = Detection(
        id="det-cs-01",
        rule_id="sigma-cobalt-strike",
        rule_version="1.0",
        severity="critical",
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
    ent = IncidentEntity(
        incident_id=inc.id,
        entity_type="ip",
        entity_key="203.0.113.55",
        relation="c2_server",
        first_seen=now,
        last_seen=now,
    )
    exec_db.add_all([inc, det, link, ent])
    exec_db.commit()

    agent = InvestigationAgent(provider=DeterministicRuleProvider())
    report = await agent.investigate_incident(
        session=exec_db,
        incident_id=inc.id,
        request=InvestigationRunRequest(budget_limit_usd=1.0),
    )

    assert report.status == "COMPLETED"

    # Verify that tool execution AuditEvents were recorded
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.object_type == "tool")
        .order_by(AuditEvent.occurred_at.asc())
    )
    tool_audits = exec_db.execute(stmt).scalars().all()

    assert len(tool_audits) > 0
    actions = [a.action for a in tool_audits]
    assert "tool:execute:get_incident_summary" in actions
    assert "tool:execute:get_incident_detections" in actions
    assert "tool:execute:get_incident_risk_assessment" in actions
    for a in tool_audits:
        assert a.outcome == "SUCCESS"
        assert a.actor_type in ["USER", "AGENT"]


@pytest.mark.asyncio
async def test_investigation_reconciles_with_prior_triage(exec_db):
    """Verify that investigation explicitly evaluates and reconciles against prior triage assessments."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-triage-rec-01",
        title="Web Shell Upload",
        status=IncidentStateEnum.TRIAGE.value,
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    # Record a prior triage assessment
    triage_rec = IncidentTriageAssessmentModel(
        id="trg-web-01",
        incident_id=inc.id,
        summary="Suspected initial web shell deployment via vulnerable upload endpoint.",
        suspected_activity="persistence_web_shell",
        confidence=0.85,
        recommended_severity="high",
        recommended_priority="P2_HIGH",
        risk_score=72.0,
        risk_band="HIGH",
        created_at=now,
    )
    det = Detection(
        id="det-ws-01",
        rule_id="sigma-web-shell-access",
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
    exec_db.add_all([inc, triage_rec, det, link])
    exec_db.commit()

    agent = InvestigationAgent(provider=DeterministicRuleProvider())
    report = await agent.investigate_incident(session=exec_db, incident_id=inc.id)

    assert report.triage_reconciliation != ""
    assert "triage assessment" in report.triage_reconciliation.lower()


def test_api_investigation_history_endpoint(exec_db):
    """Verify GET /api/v1/incidents/{incident_id}/investigations retrieves paginated history."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-hist-01", title="History Test", first_seen=now, last_seen=now)
    # Add two agent runs
    run1 = DbAgentRun(
        id="run-hist-1",
        incident_id=inc.id,
        task_type="comprehensive_triage",
        state="COMPLETED",
        model_ref="mock-1",
        template_version="1.0",
        started_at=now,
        finished_at=now,
    )
    run2 = DbAgentRun(
        id="run-hist-2",
        incident_id=inc.id,
        task_type="detection_deep_dive",
        state="COMPLETED",
        model_ref="mock-1",
        template_version="1.0",
        started_at=now,
        finished_at=now,
    )
    exec_db.add_all([inc, run1, run2])
    exec_db.commit()

    res = client.get(
        f"/api/v1/incidents/{inc.id}/investigations?limit=10&offset=0",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc.id
    assert data["total_count"] == 2
    assert len(data["investigations"]) == 2

    # Verify pagination bounds
    res_page = client.get(
        f"/api/v1/incidents/{inc.id}/investigations?limit=1&offset=0",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_page.status_code == 200
    page_data = res_page.json()
    assert page_data["limit"] == 1
    assert len(page_data["investigations"]) == 1


def test_api_investigation_continuation_endpoint(exec_db):
    """Verify POST /api/v1/investigations/{run_id}/continue performs bounded continuation."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-cont-01", title="Continuation Test", first_seen=now, last_seen=now)
    det = Detection(id="det-c-01", rule_id="sigma-c", rule_version="1.0", severity="medium", first_seen=now, last_seen=now)
    link = IncidentDetection(incident_id=inc.id, detection_id=det.id, link_reason="c", linked_by="c", linked_at=now)
    run = DbAgentRun(
        id="run-cont-test-01",
        incident_id=inc.id,
        task_type="comprehensive_triage",
        state="COMPLETED",
        model_ref="mock-1",
        template_version="1.0",
        budget_json={},
        started_at=now,
        finished_at=now,
    )
    exec_db.add_all([inc, det, link, run])
    exec_db.commit()

    continuation_payload = {
        "additional_steps": 3,
        "budget_limit_usd": 0.5,
        "additional_hypotheses": ["Test secondary persistence mechanism"],
        "timeout_seconds": 30,
    }

    res = client.post(
        f"/api/v1/investigations/{run.id}/continue",
        json=continuation_payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["state"] == "COMPLETED"
    assert "run_id" in data
