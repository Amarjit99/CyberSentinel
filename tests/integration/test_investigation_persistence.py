"""CyberSentinel AI — Integration Tests: Investigation Persistence & Review (Phase 5)"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.agents.models import (
    HumanReviewDecisionEnum,
    InvestigationReviewRequest,
    InvestigationRunRequest,
)
from services.agents.orchestrator import orchestrator
from services.persistence.models import (
    AgentFinding as DbAgentFinding,
)
from services.persistence.models import (
    AgentRun as DbAgentRun,
)
from services.persistence.models import (
    AuditEvent,
    Base,
    Detection,
    Incident,
    IncidentDetection,
)


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


@pytest.mark.asyncio
async def test_investigation_run_and_findings_persistence(test_db):
    """Verify that agent runs and findings are persisted with valid foreign keys in PostgreSQL/SQLite."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-persist-01",
        title="Suspicious SSH Activity",
        status=IncidentStateEnum.TRIAGE.value,
        severity="medium",
        first_seen=now,
        last_seen=now,
    )
    det = Detection(
        id="det-ssh-01",
        rule_id="sigma-ssh-failed",
        rule_version="1.0",
        severity="medium",
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
    test_db.add_all([inc, det, link])
    test_db.commit()

    req = InvestigationRunRequest(task_type="comprehensive_triage", budget_limit_usd=1.0)
    run_status = await orchestrator.execute_investigation(test_db, inc.id, req)

    # 1. Verify DbAgentRun record
    db_run = test_db.get(DbAgentRun, run_status.run_id)
    assert db_run is not None
    assert db_run.incident_id == inc.id
    assert db_run.state == "COMPLETED"
    assert db_run.finished_at is not None

    # 2. Verify DbAgentFinding records linked via foreign key
    findings = test_db.query(DbAgentFinding).filter(DbAgentFinding.run_id == run_status.run_id).all()
    assert len(findings) > 0
    for f in findings:
        assert f.run_id == db_run.id
        assert f.claim != ""
        assert 0.0 <= f.confidence <= 1.0


def test_human_review_applies_lifecycle_transition_and_audit(test_db):
    """Verify analyst review can transition incident lifecycle and creates an AuditEvent."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-review-01",
        title="Phishing Email Lead",
        status=IncidentStateEnum.TRIAGE.value,
        severity="low",
        version=1,
        first_seen=now,
        last_seen=now,
    )
    run = DbAgentRun(
        id="run-rev-01",
        incident_id=inc.id,
        task_type="triage",
        state="COMPLETED",
        model_ref="mock-v1",
        template_version="1.0",
        budget_json={},
        started_at=now,
        finished_at=now,
    )
    test_db.add_all([inc, run])
    test_db.commit()

    operator = Principal(
        id="soc-analyst-bob",
        name="Bob Analyst",
        roles=[RBACRoleEnum.SOC_ANALYST],
    )

    review_req = InvestigationReviewRequest(
        decision=HumanReviewDecisionEnum.ACCEPTED,
        review_notes="Confirmed initial malicious indicators; promoting to active investigation.",
        target_lifecycle_transition=IncidentStateEnum.INVESTIGATING,
        expected_version=1,
    )

    review_res = orchestrator.review_investigation(
        session=test_db,
        run_id=run.id,
        review_request=review_req,
        operator=operator,
    )

    assert review_res["decision"] == "ACCEPTED"
    assert review_res["lifecycle_transition"]["new_status"] == "INVESTIGATING"

    # Verify incident status updated in DB
    updated_inc = test_db.get(Incident, inc.id)
    assert updated_inc.status == IncidentStateEnum.INVESTIGATING.value
    assert updated_inc.version == 2

    # Verify AuditEvent was logged
    audit = test_db.query(AuditEvent).filter(AuditEvent.object_id == run.id).first()
    assert audit is not None
    assert audit.action == "investigation.review"
    assert audit.actor_id == "soc-analyst-bob"
