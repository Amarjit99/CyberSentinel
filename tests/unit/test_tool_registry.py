"""CyberSentinel AI — Unit Tests: Typed Agent Tool Registry & Server-Side Authorization (Sprint 16)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
"""

from datetime import datetime, timezone

import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from packages.auth import Principal
from schemas.enums import AgentIdEnum, RBACRoleEnum
from services.agents.executor import ToolExecutionService
from services.agents.registry import (
    DuplicateToolError,
    ToolAuthorizationError,
    ToolDefinition,
    ToolDisabledError,
    ToolExecutionLimitError,
    ToolNotFoundError,
    ToolRegistry,
    ToolValidationError,
    UnsafeToolError,
    create_default_tool_registry,
)
from services.agents.tool_schemas import (
    ToolExecutionRequest,
)
from services.persistence.models import AuditEvent, Base, Incident


@pytest.fixture
def unit_db_session():
    """Isolated in-memory SQLite database session for unit testing."""
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
def test_principal():
    return Principal(
        id="usr-analyst-01",
        name="Security Analyst",
        roles={RBACRoleEnum.SOC_ANALYST},
    )


@pytest.fixture
def sample_incident(unit_db_session):
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-unit-001",
        title="Suspicious Kerberos TGS Requests",
        status="TRIAGE",
        severity="medium",
        confidence=0.85,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    unit_db_session.add(inc)
    unit_db_session.commit()
    return inc


# ============================================================================
# 1. Tool Registry Structure and Default Tools
# ============================================================================


def test_default_tool_registry_initialization():
    """Verify default registry loads all 9 authoritative tools with correct metadata."""
    registry = create_default_tool_registry()
    assert len(registry) == 9
    assert registry.registry_version == "1.0.0"
    assert registry.policy_version == "2026.04"

    expected_tools = [
        "get_incident_summary",
        "get_incident_detections",
        "get_canonical_events",
        "get_incident_timeline",
        "get_incident_entities",
        "get_incident_evidence",
        "get_prior_findings",
        "lookup_threat_intel",
        "get_incident_risk_assessment",
    ]
    for tool_name in expected_tools:
        tool = registry.get(tool_name)
        assert tool is not None
        assert tool.name == tool_name
        assert tool.is_read_only is True
        assert tool.is_enabled is True
        meta = tool.to_metadata()
        assert meta.name == tool_name
        assert meta.is_read_only is True
        assert "incident_id" in meta.input_schema_json["properties"] or "indicator_value" in meta.input_schema_json["properties"]


def test_tool_registry_rejects_duplicate_names():
    """Verify registry raises DuplicateToolError when registering existing tool name."""
    registry = create_default_tool_registry()

    class DummyInput(BaseModel):
        x: int

    class DummyOutput(BaseModel):
        y: int

    duplicate_def = ToolDefinition(
        name="get_incident_summary",
        version="1.0.0",
        description="Duplicate registration attempt",
        permitted_purpose="Testing duplicate rejection",
        input_schema=DummyInput,
        output_schema=DummyOutput,
        required_capability="incident:read",
        allowed_roles={RBACRoleEnum.SOC_ANALYST},
        allowed_agents={AgentIdEnum.TRIAGE_AGENT},
        handler=lambda **kwargs: {"y": 1},
    )

    with pytest.raises(DuplicateToolError) as exc_info:
        registry.register(duplicate_def)
    assert "already registered" in str(exc_info.value)


def test_tool_registry_rejects_invalid_names():
    """Verify registry rejects names with uppercase letters, spaces, or invalid characters."""
    registry = ToolRegistry()

    class DummyInput(BaseModel):
        x: int

    class DummyOutput(BaseModel):
        y: int

    invalid_names = ["GetIncident", "get incident", "get-incident!", "get_incident@123"]
    for bad_name in invalid_names:
        bad_def = ToolDefinition(
            name=bad_name,
            version="1.0.0",
            description="Invalid name test",
            permitted_purpose="Testing name validation",
            input_schema=DummyInput,
            output_schema=DummyOutput,
            required_capability="test:read",
            allowed_roles={RBACRoleEnum.SOC_ANALYST},
            allowed_agents={AgentIdEnum.TRIAGE_AGENT},
            handler=lambda **kwargs: {"y": 1},
        )
        with pytest.raises(ToolValidationError):
            registry.register(bad_def)


def test_tool_registry_rejects_unsafe_tools():
    """Verify registry strictly rejects non-read-only or dangerous tools."""
    registry = ToolRegistry()

    class DummyInput(BaseModel):
        cmd: str

    class DummyOutput(BaseModel):
        res: str

    # 1. State-changing / non-read-only tool
    unsafe_write = ToolDefinition(
        name="update_incident_status",
        version="1.0.0",
        description="Modifies state",
        permitted_purpose="State mutation",
        input_schema=DummyInput,
        output_schema=DummyOutput,
        required_capability="incident:write",
        allowed_roles={RBACRoleEnum.SOC_ANALYST},
        allowed_agents={AgentIdEnum.TRIAGE_AGENT},
        is_read_only=False,
        handler=lambda **kwargs: {"res": "ok"},
    )
    with pytest.raises(UnsafeToolError) as exc1:
        registry.register(unsafe_write)
    assert "must be read-only" in str(exc1.value)

    # 2. Forbidden command injection keywords
    dangerous_keywords = ["run_shell_cmd", "exec_python", "eval_expression", "system_call", "write_file_data", "arbitrary_sql_query", "drop_table_records"]
    for danger in dangerous_keywords:
        danger_def = ToolDefinition(
            name=danger,
            version="1.0.0",
            description="Dangerous capability",
            permitted_purpose="Exploitation",
            input_schema=DummyInput,
            output_schema=DummyOutput,
            required_capability="sys:exec",
            allowed_roles={RBACRoleEnum.ADMIN},
            allowed_agents={AgentIdEnum.TRIAGE_AGENT},
            handler=lambda **kwargs: {"res": "ok"},
        )
        with pytest.raises(UnsafeToolError) as exc2:
            registry.register(danger_def)
        assert "prohibited execution pattern" in str(exc2.value)


# ============================================================================
# 2. Tool Enablement and Filtering
# ============================================================================


def test_tool_enablement_and_listing():
    """Verify disabling tools excludes them from active listings."""
    registry = create_default_tool_registry()
    tool_name = "lookup_threat_intel"

    assert registry.get(tool_name).is_enabled is True
    registry.set_enabled(tool_name, False)
    assert registry.get(tool_name).is_enabled is False

    enabled_tools = registry.list_tools(enabled_only=True)
    assert len(enabled_tools) == 8
    assert all(t.name != tool_name for t in enabled_tools)

    all_tools = registry.list_tools(enabled_only=False)
    assert len(all_tools) == 9

    # Filter by role
    analyst_tools = registry.list_tools(role="SOC_ANALYST")
    assert len(analyst_tools) == 8  # 1 disabled, 8 enabled


# ============================================================================
# 3. Execution Boundary: Authorization, Scoping & Schemas
# ============================================================================


def test_tool_execution_success(unit_db_session, test_principal, sample_incident):
    """Verify valid tool execution succeeds and records audit event."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-unit-01",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    result = executor.execute_tool(
        request=req,
        db_session=unit_db_session,
        principal=test_principal,
    )

    assert result.success is True
    assert result.tool_name == "get_incident_summary"
    assert result.result["id"] == sample_incident.id
    assert result.result["title"] == "Suspicious Kerberos TGS Requests"
    assert result.duration_ms >= 0

    # Verify audit event in DB
    stmt = select(AuditEvent).where(AuditEvent.action == "tool:execute:get_incident_summary")
    audit = unit_db_session.execute(stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "SUCCESS"
    assert audit.object_id == "get_incident_summary"
    assert audit.metadata_redacted["incident_id"] == sample_incident.id


def test_tool_execution_denied_for_unauthorized_role(unit_db_session, sample_incident):
    """Verify principal without required role is denied execution."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    unauthorized_principal = Principal(
        id="usr-viewer-01",
        name="Auditor / Readonly User",
        roles={RBACRoleEnum.VIEWER},
    )

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-unit-02",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolAuthorizationError) as exc_info:
        executor.execute_tool(
            request=req,
            db_session=unit_db_session,
            principal=unauthorized_principal,
        )
    assert "does not possess required role" in str(exc_info.value)

    # Check DENIED audit record
    stmt = select(AuditEvent).where(AuditEvent.reason_code == "ROLE_NOT_AUTHORIZED")
    audit = unit_db_session.execute(stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "DENIED"


def test_tool_execution_denied_for_unauthorized_agent(unit_db_session, test_principal, sample_incident):
    """Verify tool execution is denied if agent_id is not in tool allowlist."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Restrict tool to TRIAGE_AGENT only for this test
    tool_def = registry.get("get_incident_summary")
    tool_def.allowed_agents = {AgentIdEnum.TRIAGE_AGENT}

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-unit-03",
        agent_id=AgentIdEnum.RESPONSE_AGENT,  # Response agent not allowed on triage tool
    )

    with pytest.raises(ToolAuthorizationError) as exc_info:
        executor.execute_tool(
            request=req,
            db_session=unit_db_session,
            principal=test_principal,
        )
    assert "is not authorized to invoke tool" in str(exc_info.value)


def test_tool_execution_disabled_tool_denied(unit_db_session, test_principal, sample_incident):
    """Verify disabled tool invocation raises ToolDisabledError."""
    registry = create_default_tool_registry()
    registry.set_enabled("get_incident_summary", False)
    executor = ToolExecutionService(registry=registry)

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-unit-04",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolDisabledError) as exc_info:
        executor.execute_tool(
            request=req,
            db_session=unit_db_session,
            principal=test_principal,
        )
    assert "currently disabled" in str(exc_info.value)


def test_tool_execution_input_schema_validation(unit_db_session, test_principal, sample_incident):
    """Verify invalid input payload fails validation before handler is called."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    # Malformed arguments (empty for tool expecting incident_id)
    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": ""},  # Empty string rejected by validator
        incident_id=sample_incident.id,
        task_id="task-unit-05",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolValidationError):
        executor.execute_tool(
            request=req,
            db_session=unit_db_session,
            principal=test_principal,
        )


def test_tool_execution_unknown_tool_raises(unit_db_session, test_principal, sample_incident):
    """Verify calling an unregistered tool raises ToolNotFoundError."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    req = ToolExecutionRequest(
        tool_name="non_existent_tool",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-unit-06",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    with pytest.raises(ToolNotFoundError):
        executor.execute_tool(
            request=req,
            db_session=unit_db_session,
            principal=test_principal,
        )


def test_tool_execution_task_quota_limit(unit_db_session, test_principal, sample_incident):
    """Verify exceeding per-task invocation limit raises ToolExecutionLimitError."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry, max_calls_per_task=3)

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={"incident_id": sample_incident.id},
        incident_id=sample_incident.id,
        task_id="task-quota-test",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    # 3 allowed
    for _ in range(3):
        res = executor.execute_tool(request=req, db_session=unit_db_session, principal=test_principal)
        assert res.success is True

    # 4th exceeds quota
    with pytest.raises(ToolExecutionLimitError) as exc_info:
        executor.execute_tool(request=req, db_session=unit_db_session, principal=test_principal)
    assert "quota" in str(exc_info.value).lower()


def test_tool_execution_redacts_sensitive_arguments(unit_db_session, test_principal, sample_incident):
    """Verify sensitive arguments like API tokens or passwords are redacted in audit logs."""
    registry = create_default_tool_registry()
    executor = ToolExecutionService(registry=registry)

    req = ToolExecutionRequest(
        tool_name="get_incident_summary",
        arguments={
            "incident_id": sample_incident.id,
            "api_key": "secret-token-xyz-12345",
            "password": "SuperSecretPassword123!",
        },
        incident_id=sample_incident.id,
        task_id="task-redact-test",
        agent_id=AgentIdEnum.TRIAGE_AGENT,
    )

    executor.execute_tool(
        request=req,
        db_session=unit_db_session,
        principal=test_principal,
    )

    stmt = select(AuditEvent).where(AuditEvent.action == "tool:execute:get_incident_summary")
    audit = unit_db_session.execute(stmt).scalars().first()
    assert audit is not None
    args = audit.metadata_redacted.get("arguments", {})
    assert args.get("api_key") == "[REDACTED]"
    assert args.get("password") == "[REDACTED]"
    assert "secret-token-xyz-12345" not in str(audit.metadata_redacted)
