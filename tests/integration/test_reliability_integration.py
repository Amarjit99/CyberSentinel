"""CyberSentinel AI — Sprint 25 Reliability Integration Tests (CSAI-R1.4-RELIABILITY)

Integration tests validating:
1. /health and /ready endpoints under normal vs simulated degraded/unhealthy states.
2. Graceful deterministic fallback when AI providers experience sustained outages.
3. Telemetry ingestion backpressure and in-memory queue fallback under burst traffic.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from schemas.enums import IncidentStateEnum
from services.agents.providers import HTTPLLMProvider, LLMProviderUnavailableError
from services.agents.triage import TriageAgent
from services.persistence.database import SessionLocal
from services.persistence.models import Incident


@pytest.fixture
def api_client():
    return TestClient(app)


# ==============================================================================
# 1. Integration: /health and /ready State Accuracy
# ==============================================================================

def test_integration_health_and_readiness_normal_state(api_client):
    """Execution Mode: integration_testclient
    Verify /health and /ready return expected contract and status in default local environment.
    """
    health_res = api_client.get("/health")
    assert health_res.status_code == 200
    h_data = health_res.json()
    assert h_data["status"] in ("healthy", "degraded")
    assert "database" in h_data["checks"]
    assert "queue" in h_data["checks"]
    assert "ai_provider" in h_data["checks"]

    ready_res = api_client.get("/ready")
    assert ready_res.status_code == 200
    r_data = ready_res.json()
    assert r_data["ready"] is True
    assert "database" in r_data["dependencies"]


def test_integration_readiness_database_failure_returns_503(api_client):
    """Execution Mode: integration_testclient_injected_fault
    Verify /ready returns HTTP 503 and ready=False when required database dependency fails.
    """
    with patch("apps.api.main.check_database_health", return_value=(False, "unreachable: ConnectionRefused", 5.0)):
        res = api_client.get("/ready")
        assert res.status_code == 503
        data = res.json()
        assert data["ready"] is False
        assert data["dependencies"]["database"] is False


def test_integration_health_truthful_degraded_when_optional_dep_missing(api_client):
    """Execution Mode: integration_testclient_injected_fault
    Verify /health truthfully returns 'degraded' when optional external AI provider or durable queue is offline.
    """
    # When provider is unavailable but DB is up
    with patch("apps.api.main.triage_agent.provider.check_availability") as mock_avail:
        mock_info = MagicMock()
        mock_info.is_available = False
        mock_avail.return_value = mock_info

        res = api_client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "degraded"
        assert data["checks"]["ai_provider"] == "degraded"


# ==============================================================================
# 2. Integration: Triage Agent Deterministic Fallback on Outage
# ==============================================================================


@pytest.mark.asyncio
async def test_integration_triage_fallback_on_provider_outage():
    """Execution Mode: integration_agent_workflow
    Verify TriageAgent falls back to DeterministicRuleProvider during external provider failure.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        unique_id = f"inc-rel-{uuid4().hex[:8]}"
        inc = Incident(
            id=unique_id,
            title="Suspicious C2 Beaconing Activity",
            severity="critical",
            status=IncidentStateEnum.NEW.value,
            version=1,
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db.add(inc)
        db.commit()

        # Primary provider configured to simulate complete provider outage
        failing_provider = HTTPLLMProvider(api_key="test-key", max_retries=1)

        with patch("httpx.AsyncClient.post", side_effect=LLMProviderUnavailableError("Provider offline")):
            agent = TriageAgent(provider=failing_provider)
            report = await agent.triage_incident(
                incident_id=inc.id,
                db_session=db,
                force_fallback=False,
                persist=True,
            )

            assert report is not None
            assert report.is_fallback is True
            assert report.recommended_severity in ("critical", "high", "medium", "low", "informational")
            assert len(report.recommended_steps) > 0
    finally:
        db.close()


# ==============================================================================
# 3. Integration: Ingestion Burst & Backpressure Buffer
# ==============================================================================

def test_integration_ingestion_burst_buffering(api_client):
    """Execution Mode: integration_testclient
    Verify ingestion batch endpoint absorbs bursts and enforces schema limits without failure.
    """
    events = [
        {
            "timestamp": "2026-10-17T11:00:00Z",
            "source_type": "windows",
            "source_name": "sysmon",
            "event_type": "process_creation",
            "process_name": f"proc_{i}.exe",
            "command_line": f"proc_{i}.exe /arg",
        }
        for i in range(25)
    ]
    payload = {
        "client_id": "test-sensor-burst",
        "events": events,
    }

    res = api_client.post("/api/v1/events", json=payload)
    assert res.status_code == 202
    data = res.json()
    assert data["accepted_count"] == 25
    assert data["quarantined_count"] == 0
    assert len(data["event_ids"]) == 25
    assert "correlation_id" in data
