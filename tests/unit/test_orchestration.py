"""Unit tests for Multi-Agent Investigation Orchestration (Sprint 18)
Governing Decisions: ADR-0002, ADR-0005, Phase 18 Specification
"""

from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from packages.auth import Principal, RBACRoleEnum
from schemas.enums import AgentIdEnum, IncidentStateEnum
from services.agents.models import (
    InvestigationPlan,
    InvestigationTask,
    TaskStatusEnum,
)
from services.agents.orchestrator import InvestigationOrchestrator
from services.persistence.models import Base, Incident


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        now = datetime.now(timezone.utc)
        inc = Incident(
            id="inc-orch-test",
            status=IncidentStateEnum.INVESTIGATING.value,
            severity="high",
            title="Suspicious Orchestration Test Incident",
            first_seen=now,
            last_seen=now,
        )
        session.add(inc)
        session.commit()
        yield session


@pytest.fixture
def analyst_principal() -> Principal:
    return Principal(id="analyst-1", name="SOC Analyst", roles=[RBACRoleEnum.SOC_ANALYST])


@pytest.fixture
def viewer_principal() -> Principal:
    return Principal(id="viewer-1", name="Viewer", roles=[RBACRoleEnum.VIEWER])


def test_build_investigation_plan_dag():
    """Verify investigation plan builds a valid directed acyclic graph with bounded steps."""
    orch = InvestigationOrchestrator()
    plan = orch.build_investigation_plan(incident_id="inc-12345678", max_steps=7)

    assert plan.incident_id == "inc-12345678"
    assert len(plan.tasks) <= 7
    assert plan.tasks[0].task_type == "context_collection"
    assert plan.tasks[0].dependencies == []

    # Verify task IDs are unique and dependencies point to prior tasks
    task_ids = [t.task_id for t in plan.tasks]
    assert len(task_ids) == len(set(task_ids))

    for task in plan.tasks:
        for dep in task.dependencies:
            assert dep in task_ids


def test_orchestration_plan_bounds():
    """Verify plan enforces hard bound on max steps (max 10)."""
    orch = InvestigationOrchestrator()
    plan = orch.build_investigation_plan(incident_id="inc-12345678", max_steps=50)
    assert len(plan.tasks) <= 10


@pytest.mark.asyncio
async def test_orchestration_execution_success(db_session: Session, analyst_principal: Principal):
    """Verify execution of an orchestrated investigation plan succeeds and updates task statuses."""
    orch = InvestigationOrchestrator()
    plan = orch.build_investigation_plan(incident_id="inc-orch-test", max_steps=3)

    result = await orch.execute_orchestrated_plan(
        session=db_session, plan=plan, operator=analyst_principal
    )

    assert result.incident_id == "inc-orch-test"
    assert result.state in ["COMPLETED", "PARTIAL_SUCCESS"]
    assert result.completed_tasks >= 1
    assert result.total_tasks == len(plan.tasks)

    # Check that individual task statuses were updated
    for task in result.tasks:
        if task.status == TaskStatusEnum.SUCCESS:
            assert task.started_at is not None
            assert task.finished_at is not None
            assert len(task.tools_called) >= 1


@pytest.mark.asyncio
async def test_orchestration_dependency_failure_skips_dependents(
    db_session: Session, analyst_principal: Principal
):
    """Verify that when a prerequisite task fails, dependent tasks are cleanly marked SKIPPED."""
    orch = InvestigationOrchestrator()

    # Create a plan where task-1 is invalid/failing, and task-2 depends on task-1
    task1 = InvestigationTask(
        task_id="t1-fail",
        task_type="non_existent_exploding_task",
        agent_id=AgentIdEnum.INVESTIGATION_AGENT,
        dependencies=[],
        max_retries=0,
    )
    task2 = InvestigationTask(
        task_id="t2-dependent",
        task_type="detection_analysis",
        agent_id=AgentIdEnum.INVESTIGATION_AGENT,
        dependencies=["t1-fail"],
    )
    plan = InvestigationPlan(
        plan_id="plan-fail-dep",
        incident_id="inc-orch-test",
        tasks=[task1, task2],
        max_steps=2,
    )

    result = await orch.execute_orchestrated_plan(
        session=db_session, plan=plan, operator=analyst_principal
    )

    # Task 2 should be skipped because task 1 failed
    assert result.state in ["PARTIAL_SUCCESS", "FAILED"]
    t1_res = next(t for t in result.tasks if t.task_id == "t1-fail")
    t2_res = next(t for t in result.tasks if t.task_id == "t2-dependent")

    assert t1_res.status == TaskStatusEnum.FAILED
    assert t2_res.status == TaskStatusEnum.SKIPPED
    assert "dependency" in (t2_res.error_message or "").lower()


@pytest.mark.asyncio
async def test_orchestration_rbac_denial(db_session: Session, viewer_principal: Principal):
    """Verify unauthorized principal (VIEWER) is blocked from executing orchestration."""
    orch = InvestigationOrchestrator()
    plan = orch.build_investigation_plan(incident_id="inc-orch-test", max_steps=2)

    with pytest.raises(PermissionError, match="lacks authorized role"):
        await orch.execute_orchestrated_plan(
            session=db_session, plan=plan, operator=viewer_principal
        )
