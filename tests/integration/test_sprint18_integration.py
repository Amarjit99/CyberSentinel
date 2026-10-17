"""Integration tests for Sprint 18: Orchestration, RAG, and Threat Hunting APIs
Governing Decisions: ADR-0002, ADR-0005, Phase 18 Specification
"""

from datetime import datetime, timezone
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import IncidentStateEnum
from services.persistence.database import get_db
from services.persistence.models import (
    Base,
    Detection,
    EventMetadata,
    Incident,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def client_with_session() -> Generator[tuple[TestClient, Session], None, None]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        now = utc_now()
        inc = Incident(
            id="inc-s18-test",
            status=IncidentStateEnum.INVESTIGATING.value,
            severity="high",
            title="Sprint 18 Integration Incident",
            first_seen=now,
            last_seen=now,
        )
        session.add(inc)

        # Seed detection for hunting
        det = Detection(
            id="det-s18-1",
            rule_id="proc_powershell_download",
            rule_version="1.0.0",
            severity="high",
            first_seen=now,
            last_seen=now,
            status="NEW",
        )
        session.add(det)

        # Seed events for brute force hunt
        for i in range(5):
            ev = EventMetadata(
                id=f"ev-s18-{i}",
                source_id="inc-s18-test",
                event_time=now,
                schema_version="1.0.0",
                raw_ref=f"raw-{i}",
                checksum=f"sha256:s18-auth-{i}",
                classification="auth_failed",
            )
            session.add(ev)

        session.commit()

        def override_get_db():
            yield session

        app.dependency_overrides[get_db] = override_get_db

        with TestClient(app) as client:
            yield client, session

        app.dependency_overrides.clear()


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {
        "X-Operator-Role": "SOC_ANALYST",
    }


def test_api_rag_query_and_sources(
    client_with_session: tuple[TestClient, Session], auth_headers: dict[str, str]
):
    """Verify RAG query and index sources endpoints."""
    client, _ = client_with_session

    # 1. Check sources
    src_resp = client.get("/api/v1/rag/sources", headers=auth_headers)
    assert src_resp.status_code == 200
    src_data = src_resp.json()
    assert src_data["status"] == "HEALTHY"
    assert src_data["retrieval_backend"] == "in_memory_lexical_bm25"
    assert src_data["total_chunks"] > 0

    # 2. Query RAG
    query_resp = client.post(
        "/api/v1/rag/query",
        json={"query": "powershell script execution", "top_k": 3},
        headers=auth_headers,
    )
    assert query_resp.status_code == 200
    query_data = query_resp.json()
    assert query_data["retrieval_method"] == "lexical_bm25"
    assert query_data["total_candidates"] > 0
    assert len(query_data["results"]) <= 3
    assert len(query_data["citations"]) > 0


def test_api_threat_hunting_lifecycle(
    client_with_session: tuple[TestClient, Session], auth_headers: dict[str, str]
):
    """Verify launching a hunt, getting hunt status, and listing hunts via API."""
    client, session = client_with_session

    # 1. Launch a brute force hunt
    hunt_payload = {
        "hunt_type": "brute_force_auth",
        "incident_id": "inc-s18-test",
        "time_window_minutes": 60,
        "threshold": 3,
    }
    launch_resp = client.post("/api/v1/hunting/jobs", json=hunt_payload, headers=auth_headers)
    assert launch_resp.status_code == 201
    launch_data = launch_resp.json()
    assert launch_data["state"] == "COMPLETED"
    assert launch_data["hunt_type"] == "brute_force_auth"
    assert launch_data["matched_events_count"] >= 3
    hunt_id = launch_data["hunt_id"]

    # 2. Get hunt status by ID
    get_resp = client.get(f"/api/v1/hunting/jobs/{hunt_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["hunt_id"] == hunt_id
    assert len(get_data["findings"]) >= 1

    # 3. List hunt jobs
    list_resp = client.get("/api/v1/hunting/jobs?limit=10", headers=auth_headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert any(j["hunt_id"] == hunt_id for j in list_data)


def test_api_orchestrator_lifecycle(
    client_with_session: tuple[TestClient, Session], auth_headers: dict[str, str]
):
    """Verify generating plans, executing orchestrated plans, and fetching orchestration history."""
    client, session = client_with_session

    # 1. Generate plan
    plan_payload = {
        "incident_id": "inc-s18-test",
        "max_steps": 5,
        "budget_limit_usd": 1.0,
    }
    plan_resp = client.post("/api/v1/orchestrator/plans", json=plan_payload, headers=auth_headers)
    assert plan_resp.status_code == 200
    plan_data = plan_resp.json()
    assert plan_data["incident_id"] == "inc-s18-test"
    assert len(plan_data["tasks"]) == 5

    # 2. Execute plan
    exec_resp = client.post("/api/v1/orchestrator/execute", json=plan_data, headers=auth_headers)
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["state"] in ["COMPLETED", "PARTIAL_SUCCESS"]
    assert exec_data["total_tasks"] == 5
    assert exec_data["completed_tasks"] >= 1
    assert "orch-" in exec_data["run_id"]

    # 3. Get orchestration history
    hist_resp = client.get("/api/v1/orchestrator/history", headers=auth_headers)
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert any(r["run_id"] == exec_data["run_id"] for r in hist_data)


def test_tool_execution_boundary_rag_and_hunt(
    client_with_session: tuple[TestClient, Session], auth_headers: dict[str, str]
):
    """Verify that search_knowledge_base and run_threat_hunt execute through ToolExecutionService."""
    client, session = client_with_session

    # 1. Execute search_knowledge_base tool
    tool_req = {
        "tool_name": "search_knowledge_base",
        "incident_id": "inc-s18-test",
        "arguments": {
            "query": "powershell execution",
            "incident_id": "inc-s18-test",
            "limit": 3,
        },
    }
    tool_resp = client.post(
        "/api/v1/incidents/inc-s18-test/tools/execute", json=tool_req, headers=auth_headers
    )
    assert tool_resp.status_code == 200
    res_data = tool_resp.json()
    assert res_data["status"] == "SUCCESS"
    assert res_data["data"]["retrieval_method"] == "lexical_bm25"
    assert len(res_data["data"]["results"]) > 0

    # 2. Execute run_threat_hunt tool
    hunt_tool_req = {
        "tool_name": "run_threat_hunt",
        "incident_id": "inc-s18-test",
        "arguments": {
            "hunt_type": "brute_force_auth",
            "incident_id": "inc-s18-test",
            "time_window_minutes": 60,
            "threshold": 3,
        },
    }
    hunt_tool_resp = client.post(
        "/api/v1/incidents/inc-s18-test/tools/execute", json=hunt_tool_req, headers=auth_headers
    )
    assert hunt_tool_resp.status_code == 200
    hunt_res_data = hunt_tool_resp.json()
    assert hunt_res_data["status"] == "SUCCESS"
    assert hunt_res_data["data"]["status"] == "COMPLETED"
    assert hunt_res_data["data"]["matched_events_count"] >= 3
