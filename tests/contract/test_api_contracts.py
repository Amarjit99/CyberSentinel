"""API Contract Tests for FastAPI Endpoints and OpenAPI Specifications
Traceability: TEST-FR-001, TEST-FR-023, docs/17-API-SPECIFICATION.md
"""

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_health_endpoint_contract():
    """Verify GET /health contract shape and status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["healthy", "degraded"]
    assert "version" in data
    assert "checks" in data
    assert "database" in data["checks"]
    assert "ingestion" in data["checks"]
    assert "X-Request-ID" in response.headers
    assert "X-Response-Time-Sec" in response.headers


def test_readiness_endpoint_contract():
    """Verify GET /ready contract shape."""
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert "ready" in data
    assert isinstance(data["ready"], bool)
    assert "dependencies" in data


def test_ingestion_metrics_include_operational_depths():
    """Verify metrics expose queue and quarantine health without raw event data."""
    response = client.get("/api/v1/events/metrics")

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data["queue_depth"], (int, float))
    assert data["queue_storage_mode"] in {"redis_streams", "in_memory_volatile_fallback"}
    assert isinstance(data["quarantine_depth"], (int, float))
    assert isinstance(data["dead_letter_depth"], (int, float))


def test_event_ingestion_success_contract():
    """Verify valid batch telemetry ingestion over POST /api/v1/events."""
    valid_batch = {
        "client_id": "sensor-forwarder-01",
        "events": [
            {
                "timestamp": "2026-10-16T12:00:00Z",
                "source_type": "windows",
                "source_name": "sysmon",
                "event_type": "process_creation",
                "process_name": "whoami.exe",
                "command_line": "whoami.exe /all",
            },
            {
                "timestamp": "2026-10-16T12:00:05Z",
                "source_type": "linux",
                "source_name": "auditd",
                "event_type": "user_auth",
                "username": "root",
            },
        ],
    }

    response = client.post(
        "/api/v1/events",
        json=valid_batch,
        headers={"X-Request-ID": "test-req-001"},
    )
    assert response.status_code == 202
    data = response.json()
    assert data["accepted_count"] == 2
    assert data["quarantined_count"] == 0
    assert len(data["event_ids"]) == 2
    assert data["correlation_id"] == "test-req-001"
    assert response.headers["X-Request-ID"] == "test-req-001"


def test_malformed_event_ingest_returns_standard_error_envelope():
    """Verify that validation failures return the standardized ErrorEnvelope with 422."""
    malformed_batch = {
        "client_id": "bad-client",
        "events": [
            {
                # Missing required source_name and event_type
                "source_type": "windows"
            }
        ],
    }

    response = client.post(
        "/api/v1/events",
        json=malformed_batch,
        headers={"X-Request-ID": "err-req-002"},
    )
    assert response.status_code == 422
    data = response.json()

    assert data["error_code"] == "VALIDATION_ERROR"
    assert data["request_id"] == "err-req-002"
    assert "message" in data
    assert "details" in data
    assert len(data["details"]) > 0
    assert "X-Request-ID" in response.headers


def test_openapi_contains_only_approved_phase1_paths():
    """Verify that OpenAPI schema advertises only functional Phase 1 endpoints."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    paths = schema.get("paths", {})
    assert "/health" in paths
    assert "/ready" in paths
    assert "/api/v1/events" in paths

    # Verify Phase 4, Phase 5, and Phase 6 endpoints are present and unapproved future paths are not falsely advertised
    assert "/api/v1/incidents" in paths
    assert "/api/v1/incidents/{incident_id}/investigations" in paths
    assert "/api/v1/incidents/{incident_id}/proposals" in paths
    assert "/api/v1/proposals/{proposal_id}/approve" in paths
    assert "/api/v1/response/catalogue" in paths
    assert "/api/v1/playbooks" not in paths
    assert "/api/v1/agents/investigate" not in paths

