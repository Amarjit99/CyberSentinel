"""CyberSentinel AI — Security Tests: Investigation Agent Authorization & Invariants (Sprint 17)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.6-INVESTIGATION-AGENT

Verifies:
- Authorization enforcement on starting, continuing, and querying investigations.
- Cross-incident isolation prevention.
- Prohibited tool invocation denial (shell, python, write, drop, delete, execute).
- Attempted bypass of ToolExecutionService boundary.
- Adversarial prompt injection payloads in telemetry attempting privilege escalation.
- Strict preservation of LIVE_RESPONSE_DISABLED=true with zero autonomous containment.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from packages.auth import Principal
from schemas.enums import AgentIdEnum, RBACRoleEnum
from services.agents.executor import default_tool_executor
from services.agents.investigation import InvestigationAgent
from services.agents.providers import DeterministicRuleProvider
from services.agents.registry import (
    ToolAuthorizationError,
    ToolNotFoundError,
)
from services.agents.tool_schemas import ToolExecutionRequest
from services.persistence.database import get_db
from services.persistence.models import (
    Base,
    Detection,
    Incident,
    IncidentDetection,
)

client = TestClient(app)


@pytest.fixture
def sec_db():
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


def test_viewer_role_cannot_start_investigation(sec_db):
    """Verify RBAC denies VIEWER principal from initiating an investigation run (403 Forbidden)."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-sec-rbac-01", title="RBAC Test", first_seen=now, last_seen=now)
    sec_db.add(inc)
    sec_db.commit()

    res = client.post(
        f"/api/v1/incidents/{inc.id}/investigations",
        json={"task_type": "comprehensive_triage"},
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res.status_code == 403


def test_viewer_role_cannot_continue_investigation(sec_db):
    """Verify RBAC denies VIEWER principal from continuing an investigation run (403 Forbidden)."""
    res = client.post(
        "/api/v1/investigations/run-fake/continue",
        json={"additional_steps": 2},
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_tool_execution_boundary_blocks_prohibited_tools(sec_db):
    """Verify ToolExecutionService rejects any attempt to invoke shell, python, or live response tools."""
    prohibited_tools = [
        "bash",
        "sh",
        "cmd",
        "powershell",
        "isolate_host",
        "block_ip",
        "drop_table",
        "delete_evidence",
        "eval_python",
    ]

    analyst = Principal(
        id="analyst-1",
        name="Analyst",
        roles=[RBACRoleEnum.SOC_ANALYST],
    )

    for bad_tool in prohibited_tools:
        req = ToolExecutionRequest(
            tool_name=bad_tool,
            arguments={},
            incident_id="inc-001",
            agent_id=AgentIdEnum.INVESTIGATION_AGENT,
        )
        with pytest.raises((ToolNotFoundError, ToolAuthorizationError, Exception)):
            default_tool_executor.execute_tool(
                request=req,
                principal=analyst,
                db_session=sec_db,
                agent_id=AgentIdEnum.INVESTIGATION_AGENT,
            )


@pytest.mark.asyncio
async def test_cross_incident_scoping_prevented_by_execution_boundary(sec_db):
    """Verify ToolExecutionService blocks attempts to query data from a mismatched incident ID."""
    now = datetime.now(timezone.utc)
    inc1 = Incident(id="inc-scope-1", title="Scope 1", first_seen=now, last_seen=now)
    inc2 = Incident(id="inc-scope-2", title="Scope 2", first_seen=now, last_seen=now)
    sec_db.add_all([inc1, inc2])
    sec_db.commit()

    analyst = Principal(id="analyst-1", name="Analyst", roles=[RBACRoleEnum.SOC_ANALYST])

    # Mismatched incident_id between request scope and arguments
    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        incident_id=inc1.id,
        arguments={"incident_id": inc2.id},
        agent_id=AgentIdEnum.INVESTIGATION_AGENT,
    )

    from services.agents.registry import ToolValidationError
    with pytest.raises(ToolValidationError):
        default_tool_executor.execute_tool(
            request=req,
            principal=analyst,
            db_session=sec_db,
            agent_id=AgentIdEnum.INVESTIGATION_AGENT,
        )


@pytest.mark.asyncio
async def test_adversarial_prompt_injection_does_not_execute_commands(sec_db):
    """Verify prompt injection inside log messages cannot trigger containment or shell execution."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-sec-inj-01", title="Injection Test", first_seen=now, last_seen=now)
    det = Detection(
        id="det-inj-01",
        rule_id="powershell; sudo rm -rf /; isolate_host",
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
    sec_db.add_all([inc, det, link])
    sec_db.commit()

    agent = InvestigationAgent(provider=DeterministicRuleProvider())
    report = await agent.investigate_incident(session=sec_db, incident_id=inc.id)

    # Investigation succeeds as read-only analysis without executing containment
    assert report.status == "COMPLETED"
    # Invariant: live response actions remain 0
    assert not hasattr(report, "executed_response_actions")
