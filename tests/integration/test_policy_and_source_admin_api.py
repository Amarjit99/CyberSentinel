from uuid import uuid4

from fastapi.testclient import TestClient

from apps.api.main import app
from services.persistence.database import SessionLocal
from services.persistence.models import ThreatSource

client = TestClient(app)


def test_risk_policy_update_requires_privileged_role_and_version_change():
    analyst = client.put(
        "/api/v1/risk/policy",
        headers={"X-Operator-Role": "SOC_ANALYST"},
        json={"version": "1.1.0", "change_reason": "test"},
    )
    assert analyst.status_code == 403

    current = client.get("/api/v1/risk/policy", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert current.status_code == 200
    policy = current.json()
    updated = dict(policy)
    updated["version"] = f"test-{uuid4().hex[:8]}"
    updated["change_reason"] = "Tested policy revision"
    response = client.put(
        "/api/v1/risk/policy",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
        json=updated,
    )
    assert response.status_code == 200
    assert response.json()["version"] == updated["version"]
    history = client.get(
        "/api/v1/risk/policy/history",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert history.status_code == 200
    assert any(item["version"] == updated["version"] and item["active"] for item in history.json())
    rollback_version = next(
        item["version"] for item in history.json() if not item["active"]
    )
    rollback = client.post(
        f"/api/v1/risk/policy/{rollback_version}/rollback",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert rollback.status_code == 200
    assert rollback.json()["version"] == rollback_version


def test_threat_source_update_is_role_protected_and_audited():
    source_id = "test-admin-source"
    with SessionLocal() as db:
        db.merge(ThreatSource(id=source_id, name="Admin Test", source_type="json_feed", reliability="B"))
        db.commit()
    try:
        forbidden = client.patch(
            f"/api/v1/threat-intel/sources/{source_id}",
            headers={"X-Operator-Role": "SOC_ANALYST"},
            json={"reliability": "A"},
        )
        assert forbidden.status_code == 403
        response = client.patch(
            f"/api/v1/threat-intel/sources/{source_id}",
            headers={"X-Operator-Role": "SECURITY_ENGINEER"},
            json={
                "reliability": "A",
                "description": "Reviewed source",
                "enabled": False,
                "endpoint_url": "https://feed.example.test/intel",
                "polling_interval_minutes": 60,
            },
        )
        assert response.status_code == 200
        assert response.json()["reliability"] == "A"
        assert response.json()["enabled"] is False
        assert response.json()["polling_interval_minutes"] == 60
    finally:
        with SessionLocal() as db:
            source = db.get(ThreatSource, source_id)
            if source:
                db.delete(source)
                db.commit()
