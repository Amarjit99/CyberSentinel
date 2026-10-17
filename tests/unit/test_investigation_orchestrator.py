"""CyberSentinel AI — Unit Tests: Investigation Orchestrator & Tool Safety (Phase 5)"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from schemas.enums import IncidentStateEnum, RBACRoleEnum
from services.agents.models import (
    InvestigationRunRequest,
)
from services.agents.orchestrator import InvestigationOrchestrator
from services.agents.providers import DeterministicRuleProvider, MockLLMProvider
from services.agents.tools import ReadOnlyInvestigationTools, UnauthorizedToolError
from services.persistence.models import (
    AgentRun,
    Base,
    Detection,
    Incident,
    IncidentDetection,
    IncidentEntity,
)


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


def test_investigation_plan_bounded():
    """Verify orchestrator builds bounded investigation plan with valid dependencies."""
    orchestrator = InvestigationOrchestrator()
    plan = orchestrator.build_investigation_plan("inc-12345", max_steps=5, budget_usd=2.0)

    assert plan.incident_id == "inc-12345"
    assert len(plan.tasks) <= 5
    assert plan.max_steps == 5
    assert plan.budget_limit_usd == 2.0

    task_types = [t.task_type for t in plan.tasks]
    assert "context_collection" in task_types
    assert "detection_analysis" in task_types
    assert "triage_assessment" in task_types


def test_read_only_tools_rejects_unauthorized_commands(memory_db):
    """Verify tool registry raises UnauthorizedToolError on shell or write actions."""
    tools = ReadOnlyInvestigationTools(session=memory_db, incident_id="inc-001")

    # Approved tool must not raise UnauthorizedToolError
    assert "get_incident_summary" in tools.ALLOWED_TOOLS

    # Prohibited shell and live response actions must be strictly rejected
    prohibited_tools = [
        "bash",
        "sh",
        "cmd",
        "powershell",
        "isolate_host",
        "block_ip",
        "drop_table",
        "execute_code",
    ]

    for bad_tool in prohibited_tools:
        with pytest.raises(UnauthorizedToolError):
            tools.execute_tool(bad_tool)


@pytest.mark.asyncio
async def test_orchestrator_execute_investigation_deterministic(memory_db):
    """Verify end-to-end execution of investigation using DeterministicRuleProvider."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-sec-01",
        title="Unauthorized PowerShell Execution",
        severity="high",
        status=IncidentStateEnum.TRIAGE.value,
        first_seen=now,
        last_seen=now,
    )
    det = Detection(
        id="det-ps-01",
        rule_id="sigma-powershell-download",
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
    ent = IncidentEntity(
        incident_id=inc.id,
        entity_type="host",
        entity_key="WORKSTATION-01",
        relation="target",
        first_seen=now,
        last_seen=now,
    )
    memory_db.add_all([inc, det, link, ent])
    memory_db.commit()

    orchestrator = InvestigationOrchestrator(default_provider=DeterministicRuleProvider())
    req = InvestigationRunRequest(task_type="comprehensive_triage", budget_limit_usd=1.0)

    status_result = await orchestrator.execute_investigation(
        session=memory_db,
        incident_id=inc.id,
        request=req,
    )

    assert status_result.state.value == "COMPLETED"
    assert status_result.incident_id == inc.id
    assert status_result.findings_count > 0

    # Verify findings were persisted
    findings = orchestrator.get_run_findings(memory_db, status_result.run_id)
    assert len(findings) > 0
    assert any("sigma-powershell-download" in f.claim for f in findings)


@pytest.mark.asyncio
async def test_orchestrator_handles_provider_failure_gracefully(memory_db):
    """Verify orchestrator marks run as FAILED and captures failure code when provider errors."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-fail-01", title="Fail Test", first_seen=now, last_seen=now)
    memory_db.add(inc)
    memory_db.commit()

    failing_provider = MockLLMProvider(should_fail=True)
    orchestrator = InvestigationOrchestrator(default_provider=failing_provider)
    req = InvestigationRunRequest()

    with pytest.raises(Exception):
        await orchestrator.execute_investigation(
            session=memory_db,
            incident_id=inc.id,
            request=req,
            provider=failing_provider,
        )

    # Verify that run record in DB was marked FAILED
    run = memory_db.query(AgentRun).filter(AgentRun.incident_id == inc.id).first()
    assert run is not None
    assert run.state == "FAILED"
    assert run.failure_code is not None


def test_orchestrator_cancel_run(memory_db):
    """Verify cancellation of an active investigation run."""
    now = datetime.now(timezone.utc)
    run = AgentRun(
        id="run-cancel-test",
        incident_id="inc-001",
        task_type="triage",
        state="RUNNING",
        model_ref="mock-model",
        template_version="1.0.0",
        budget_json={},
        started_at=now,
    )
    memory_db.add(run)
    memory_db.commit()

    operator = Principal(id="analyst-1", name="Analyst Alice", roles=[RBACRoleEnum.SOC_ANALYST])
    orchestrator = InvestigationOrchestrator()

    cancelled = orchestrator.cancel_investigation(memory_db, "run-cancel-test", operator)
    assert cancelled is True

    updated_run = memory_db.get(AgentRun, "run-cancel-test")
    assert updated_run.state == "CANCELLED"
    assert "Cancelled by analyst-1" in (updated_run.failure_code or "")
