"""Integration Tests for Detection Engineering API Endpoints
Traceability: CSAI-P3-DETECTION, ADR-0004, Gate G3
"""

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_rules_list_endpoint_requires_auth():
    """Verify GET /api/v1/rules rejects unauthenticated requests with 401."""
    response = client.get("/api/v1/rules")
    assert response.status_code == 401


def test_rules_list_endpoint_succeeds_for_analyst():
    """Verify GET /api/v1/rules returns active rules for SOC_ANALYST role."""
    headers = {"X-Operator-Role": "SOC_ANALYST"}
    response = client.get("/api/v1/rules", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "rules" in data
    assert isinstance(data["rules"], list)


def test_rules_reload_forbidden_for_analyst():
    """Verify POST /api/v1/rules/reload returns 403 Forbidden for SOC_ANALYST role."""
    headers = {"X-Operator-Role": "SOC_ANALYST"}
    response = client.post("/api/v1/rules/reload", headers=headers)
    assert response.status_code == 403


def test_rules_reload_allowed_for_detection_engineer():
    """Verify POST /api/v1/rules/reload succeeds for DETECTION_ENGINEER role."""
    headers = {"X-Operator-Role": "DETECTION_ENGINEER"}
    response = client.post("/api/v1/rules/reload", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "reloaded"
    assert "active_rule_count" in data


def test_detections_list_endpoint_requires_auth():
    """Verify GET /api/v1/detections rejects unauthenticated callers."""
    response = client.get("/api/v1/detections")
    assert response.status_code == 401


def test_detections_list_endpoint_with_auth():
    """Verify GET /api/v1/detections succeeds with valid role."""
    headers = {"X-Operator-Role": "SOC_ANALYST"}
    response = client.get("/api/v1/detections?limit=10", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "detections" in data
    assert isinstance(data["detections"], list)


def test_detection_by_id_not_found():
    """Verify GET /api/v1/detections/{id} returns 404 for non-existent detection."""
    headers = {"X-Operator-Role": "SOC_ANALYST"}
    response = client.get("/api/v1/detections/det-nonexistent-99999", headers=headers)
    assert response.status_code == 404
