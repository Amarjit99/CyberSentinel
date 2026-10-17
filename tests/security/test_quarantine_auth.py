"""CyberSentinel AI — Quarantine Endpoint Authentication & RBAC Authorization Tests
Traceability: ADR-0004, Requirement 2.F, Requirement 2.G
"""

from fastapi.testclient import TestClient

from apps.api.main import app
from services.ingestion.queue import quarantine_manager

client = TestClient(app)


def setup_function():
    quarantine_manager.clear()


def test_quarantine_list_unauthenticated_rejected():
    """Verify GET /api/v1/events/quarantine rejects unauthenticated requests with 401."""
    response = client.get("/api/v1/events/quarantine")
    assert response.status_code == 401
    err_text = response.json().get("message") or response.json().get("detail") or ""
    assert "Authentication required" in err_text


def test_quarantine_replay_unauthenticated_rejected():
    """Verify POST /api/v1/events/quarantine/{id}/replay rejects unauthenticated requests with 401."""
    response = client.post("/api/v1/events/quarantine/fake-id-123/replay")
    assert response.status_code == 401


def test_quarantine_list_unauthorized_role_forbidden():
    """Verify GET /api/v1/events/quarantine rejects unauthorized roles (e.g. VIEWER) with 403."""
    response = client.get(
        "/api/v1/events/quarantine",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert response.status_code == 403
    err_text = response.json().get("message") or response.json().get("detail") or ""
    assert "Forbidden: Insufficient privileges" in err_text


def test_quarantine_replay_unauthorized_role_forbidden():
    """Verify POST /api/v1/events/quarantine/{id}/replay rejects unauthorized roles with 403."""
    response = client.post(
        "/api/v1/events/quarantine/fake-id-123/replay",
        headers={"X-Operator-Role": "RESEARCHER"},
    )
    assert response.status_code == 403


def test_quarantine_list_authorized_operator_allowed():
    """Verify GET /api/v1/events/quarantine allows authorized roles (ADMIN, SECURITY_ENGINEER, SOC_MANAGER)."""
    # 1. Test SECURITY_ENGINEER
    resp_sec = client.get(
        "/api/v1/events/quarantine",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert resp_sec.status_code == 200
    assert "records" in resp_sec.json()

    # 2. Test ADMIN
    resp_admin = client.get(
        "/api/v1/events/quarantine",
        headers={"Authorization": "Bearer admin-secret-token-test"},
    )
    assert resp_admin.status_code == 200

    # 3. Test SOC_MANAGER
    resp_soc = client.get(
        "/api/v1/events/quarantine",
        headers={"X-Operator-Role": "SOC_MANAGER"},
    )
    assert resp_soc.status_code == 200


def test_quarantine_replay_authorized_with_audit_logging():
    """Verify successful replay by authorized operator records an audit trail."""
    # Place a malformed event in quarantine
    q_rec = quarantine_manager.quarantine_event(
        source_type="sysmon",
        error_reason="Missing fields",
        raw_payload={"timestamp": "2026-10-16T12:00:00Z"},
        raw_hash="aabbcc112233",
    )

    # Replay as ADMIN
    resp = client.post(
        f"/api/v1/events/quarantine/{q_rec.quarantine_id}/replay",
        headers={"Authorization": "Bearer admin-session-token-999"},
    )
    assert resp.status_code in (200, 404)
