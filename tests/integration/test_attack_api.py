"""CyberSentinel AI — Integration Tests: MITRE ATT&CK APIs & Incident Coverage (Sprint 12)"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.persistence.database import get_db
from services.persistence.models import (
    Base,
    Detection,
    Incident,
    IncidentDetection,
)

client = TestClient(app)


@pytest.fixture
def attack_test_db():
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


def test_list_attack_tactics_endpoint():
    """Verify GET /api/v1/attack/tactics returns 14 authoritative tactics."""
    res = client.get(
        "/api/v1/attack/tactics",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["catalog_version"] == "15.1"
    assert data["count"] == 14
    short_names = [t["short_name"] for t in data["tactics"]]
    assert "execution" in short_names
    assert "credential_access" in short_names
    assert "discovery" in short_names


def test_list_and_filter_attack_techniques_endpoint():
    """Verify GET /api/v1/attack/techniques filtering by tactic."""
    res = client.get(
        "/api/v1/attack/techniques?tactic=execution&limit=10",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] > 0
    for tech in data["techniques"]:
        assert "execution" in tech["tactics"]


def test_get_technique_by_id_endpoint():
    """Verify GET /api/v1/attack/techniques/{technique_id} returns 200 for valid, 404 for unknown."""
    res_ok = client.get(
        "/api/v1/attack/techniques/T1059.001",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_ok.status_code == 200
    tech = res_ok.json()["technique"]
    assert tech["id"] == "T1059.001"
    assert tech["parent_id"] == "T1059"

    res_404 = client.get(
        "/api/v1/attack/techniques/T9999.999",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_404.status_code == 404


def test_get_attack_mappings_and_coverage():
    """Verify GET /api/v1/attack/mappings and /api/v1/attack/coverage reflect active rules."""
    res_map = client.get(
        "/api/v1/attack/mappings",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_map.status_code == 200
    map_data = res_map.json()
    assert map_data["total_tags"] > 0
    assert map_data["valid_mappings"] > 0

    res_cov = client.get(
        "/api/v1/attack/coverage",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_cov.status_code == 200
    cov_data = res_cov.json()
    assert cov_data["total_catalog_techniques"] > 0
    assert cov_data["unique_techniques_covered"] > 0
    assert cov_data["overall_coverage_percentage"] > 0.0


def test_incident_attack_coverage_and_timeline(attack_test_db):
    """Verify incident-scoped ATT&CK coverage and timeline reflect linked detections."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=f"inc-att-{uuid4().hex[:6]}",
        title="PowerShell Download Cradle Incident",
        status="INVESTIGATING",
        severity="high",
        confidence=0.95,
        first_seen=now,
        last_seen=now,
    )
    attack_test_db.add(inc)

    # Add detection linked to proc_powershell_download rule (T1059.001)
    det = Detection(
        id=f"det-att-{uuid4().hex[:6]}",
        rule_id="f38b9397-6a4a-4d2c-80a5-296839d3c52a",  # proc_powershell_download rule ID
        rule_version="1.0.0",
        severity="high",
        first_seen=now,
        last_seen=now,
        status="open",
        created_at=now,
    )
    attack_test_db.add(det)
    attack_test_db.flush()

    link = IncidentDetection(
        incident_id=inc.id,
        detection_id=det.id,
        link_reason="PowerShell download cradle detected on target host",
        linked_by="correlation_engine",
        linked_at=now,
    )
    attack_test_db.add(link)
    attack_test_db.commit()

    # 1. Check Incident Coverage
    res_cov = client.get(
        f"/api/v1/incidents/{inc.id}/attack-coverage",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_cov.status_code == 200
    cov_data = res_cov.json()
    assert cov_data["detection_count"] == 1
    tech_ids = [t["id"] for t in cov_data["techniques"]]
    assert "T1059.001" in tech_ids
    assert "execution" in cov_data["tactics_observed"]

    # 2. Check Incident Timeline
    res_time = client.get(
        f"/api/v1/incidents/{inc.id}/attack-timeline",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_time.status_code == 200
    time_data = res_time.json()
    assert time_data["timeline_items_count"] >= 1
    item = time_data["timeline"][0]
    assert item["technique_id"] == "T1059.001"
    assert item["detection_id"] == det.id


def test_rbac_denies_unauthorized_roles():
    """Verify VIEWER role cannot access ATT&CK catalog or coverage endpoints."""
    res = client.get(
        "/api/v1/attack/coverage",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res.status_code == 403
