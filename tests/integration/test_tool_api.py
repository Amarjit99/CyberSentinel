"""CyberSentinel AI — Integration Tests: Tool Registry & Execution API (Sprint 16)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
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
)

client = TestClient(app)


@pytest.fixture
def tool_api_db():
    """In-memory SQLite database session override for tool API integration testing."""
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


def _seed_incident_with_context(db, inc_id="inc-api-tool-01"):
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=inc_id,
        title="Active Directory Kerberoasting Attack",
        status="INVESTIGATING",
        severity="high",
        confidence=0.88,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db.add(inc)

    det = Detection(
        id=f"det-{uuid4().hex[:8]}",
        rule_id="sigma-win-kerberoast",
        rule_version="1.0.0",
        severity="high",
        first_seen=now,
        last_seen=now,
        status="open",
        created_at=now,
    )
    db.add(det)
    db.flush()

    inc_det = IncidentDetection(
        incident_id=inc_id,
        detection_id=det.id,
        link_reason="correlated",
        linked_by="system",
        linked_at=now,
    )
    db.add(inc_det)

    ent = IncidentEntity(
        incident_id=inc_id,
        entity_type="account",
        entity_key="svc_backup",
        relation="target",
        first_seen=now,
        last_seen=now,
    )
    db.add(ent)

    ev = Evidence(
        id=f"ev-{uuid4().hex[:8]}",
        incident_id=inc_id,
        evidence_type="log",
        source_ref="event-4769",
        checksum="abc123hash",
        provenance_json={"TicketOptions": "0x40810000", "TicketEncryptionType": "0x17"},
        collected_at=now,
        created_by="system",
    )
    db.add(ev)
    db.commit()
    return inc


# ============================================================================
# 1. Tool Discovery Endpoints
# ============================================================================


def test_api_list_tools_endpoint(tool_api_db):
    """GET /api/v1/tools returns all enabled tools in registry."""
    res = client.get(
        "/api/v1/tools",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert data["total"] == 9
    assert data["registry_version"] == "1.0.0"
    assert len(data["tools"]) == 9

    tool_names = [t["name"] for t in data["tools"]]
    assert "get_incident_summary" in tool_names
    assert "lookup_threat_intel" in tool_names
    assert "get_incident_risk_assessment" in tool_names


def test_api_list_tools_filtering(tool_api_db):
    """GET /api/v1/tools with role filter."""
    res = client.get(
        "/api/v1/tools?role=SOC_ANALYST&enabled_only=true",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 9


def test_api_get_tool_details_endpoint(tool_api_db):
    """GET /api/v1/tools/{tool_name} returns metadata for registered tool."""
    res = client.get(
        "/api/v1/tools/get_incident_summary",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "get_incident_summary"
    assert data["version"] == "1.0.0"
    assert data["read_only"] is True
    assert "input_schema_json" in data
    assert "output_schema_json" in data


def test_api_get_unknown_tool_returns_404(tool_api_db):
    """GET /api/v1/tools/{tool_name} for unregistered tool returns 404."""
    res = client.get(
        "/api/v1/tools/unknown_malicious_tool",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 404
    data = res.json()
    assert "not found" in data["message"].lower()


# ============================================================================
# 2. Tool Execution Endpoint
# ============================================================================


def test_api_execute_tool_success(tool_api_db):
    """POST /api/v1/incidents/{incident_id}/tools/execute executes tool and logs audit."""
    inc = _seed_incident_with_context(tool_api_db, inc_id="inc-api-exec-01")

    payload = {
        "tool_name": "get_incident_summary",
        "arguments": {"incident_id": inc.id},
        "incident_id": inc.id,
        "task_id": "task-api-01",
        "agent_id": "triage-agent",
    }

    res = client.post(
        f"/api/v1/incidents/{inc.id}/tools/execute",
        json=payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["tool_name"] == "get_incident_summary"
    assert data["data"]["id"] == inc.id
    assert data["data"]["title"] == "Active Directory Kerberoasting Attack"

    # Confirm audit event was committed in DB
    stmt = select(AuditEvent).where(AuditEvent.action == "tool:execute:get_incident_summary")
    audit = tool_api_db.execute(stmt).scalars().first()
    assert audit is not None
    assert audit.outcome == "SUCCESS"
    assert audit.object_id == "get_incident_summary"
    assert audit.metadata_redacted["incident_id"] == inc.id


def test_api_execute_tool_mismatched_incident_id(tool_api_db):
    """POST /api/v1/incidents/{id}/tools/execute fails with 400 if body incident_id differs."""
    inc = _seed_incident_with_context(tool_api_db, inc_id="inc-api-exec-02")

    payload = {
        "tool_name": "get_incident_summary",
        "arguments": {"incident_id": "inc-api-other"},
        "incident_id": "inc-api-other",
        "task_id": "task-api-02",
        "agent_id": "triage-agent",
    }

    res = client.post(
        f"/api/v1/incidents/{inc.id}/tools/execute",
        json=payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 400
    assert "Mismatched incident_id" in res.json()["message"]


def test_api_execute_tool_unknown_incident_returns_422(tool_api_db):
    """POST /api/v1/incidents/{id}/tools/execute fails with 422 if incident doesn't exist."""
    payload = {
        "tool_name": "get_incident_summary",
        "arguments": {"incident_id": "inc-non-existent"},
        "incident_id": "inc-non-existent",
        "task_id": "task-api-03",
        "agent_id": "triage-agent",
    }

    res = client.post(
        "/api/v1/incidents/inc-non-existent/tools/execute",
        json=payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 422
    assert "not found" in res.json()["message"].lower()


def test_api_execute_tool_unknown_tool_returns_404(tool_api_db):
    """POST /api/v1/incidents/{id}/tools/execute fails with 404 for unregistered tool."""
    inc = _seed_incident_with_context(tool_api_db, inc_id="inc-api-exec-03")

    payload = {
        "tool_name": "exploit_system",
        "arguments": {"incident_id": inc.id},
        "incident_id": inc.id,
        "task_id": "task-api-04",
        "agent_id": "triage-agent",
    }

    res = client.post(
        f"/api/v1/incidents/{inc.id}/tools/execute",
        json=payload,
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 404
    assert "not registered" in res.json()["message"].lower()


def test_api_execute_tool_unauthorized_role_returns_403(tool_api_db):
    """POST /api/v1/incidents/{id}/tools/execute fails with 403 for unauthorized principal role."""
    inc = _seed_incident_with_context(tool_api_db, inc_id="inc-api-exec-04")

    payload = {
        "tool_name": "get_incident_summary",
        "arguments": {"incident_id": inc.id},
        "incident_id": inc.id,
        "task_id": "task-api-05",
        "agent_id": "triage-agent",
    }

    res = client.post(
        f"/api/v1/incidents/{inc.id}/tools/execute",
        json=payload,
        headers={"X-Operator-Role": "VIEWER"},
    )
    # The endpoint level require_roles denies VIEWER with 403
    assert res.status_code == 403
