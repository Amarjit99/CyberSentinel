"""CyberSentinel AI — Integration Tests: Threat Intel APIs (Sprint 13)"""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.persistence.database import get_db
from services.persistence.models import Base, EventMetadata
from services.threat_intel.service import ThreatIntelService

client = TestClient(app)


@pytest.fixture
def ti_api_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Pre-populate sample JSON feed
    service = ThreatIntelService(session=session)
    service.ingest_feed_file(session, Path("datasets/threat_intel/sample_feed.json"))

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


def test_threat_intel_lookup_api_endpoint(ti_api_db):
    """Verify GET /api/v1/threat-intel/lookup returns structured enrichment."""
    res = client.get(
        "/api/v1/threat-intel/lookup?type=ipv4&value=198.51.100.55",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["found"] is True
    assert data["verdict"] == "malicious"
    assert data["threat_actor"] == "APT-29 (Cozy Bear)"
    assert data["normalized_score"] == 95.0
    assert data["reliability_weighted_score"] == 95.0


def test_threat_intel_preserves_handling_metadata(ti_api_db):
    response = client.post(
        "/api/v1/threat-intel/feeds/ingest",
        json={
            "source_id": "handling-feed",
            "source_name": "Handling Feed",
            "feed_payload": {
                "indicators": [
                    {
                        "id": "handling-1",
                        "type": "domain",
                        "value": "restricted.example.com",
                        "classification": "malicious",
                        "tlp": "TLP:AMBER",
                    }
                ]
            },
        },
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert response.status_code == 200

    lookup = client.get(
        "/api/v1/threat-intel/lookup?type=domain&value=restricted.example.com",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["records"][0]["handling_tlp"] == "TLP:AMBER"


def test_threat_intel_indicators_list_api_endpoint(ti_api_db):
    """Verify GET /api/v1/threat-intel/indicators returns paginated indicators."""
    res = client.get(
        "/api/v1/threat-intel/indicators?type=domain&limit=10",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] > 0
    assert any("evil-powershell" in ind["value"] for ind in data["indicators"])


def test_threat_intel_sources_api_endpoint(ti_api_db):
    """Verify GET /api/v1/threat-intel/sources lists registered feeds and reliability."""
    res = client.get(
        "/api/v1/threat-intel/sources",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 1
    assert data["sources"][0]["reliability"] in ("A", "B", "C", "unknown")


def test_threat_intel_source_health_reports_freshness_policy(ti_api_db):
    res = client.get(
        "/api/v1/threat-intel/sources/health",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["freshness_policy"]["fresh_within_hours"] == 24
    assert data["freshness_policy"]["stale_within_hours"] == 72
    assert data["source_count"] >= 1
    assert data["sources"][0]["freshness_state"] == "fresh"


def test_threat_intel_matches_event_iocs(ti_api_db):
    event = EventMetadata(
        id="event-ti-match",
        source_id="test-source",
        event_time=datetime.now(timezone.utc),
        raw_ref="raw://event-ti-match",
        checksum="a" * 64,
        hostname="evil-powershell-payloads.org",
        src_ip="198.51.100.55",
    )
    ti_api_db.add(event)
    ti_api_db.commit()

    res = client.get(
        "/api/v1/events/event-ti-match/threat-intel",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["matched_count"] == 2
    assert {item["indicator_value"] for item in data["matches"]} == {
        "198.51.100.55",
        "evil-powershell-payloads.org",
    }


def test_threat_intel_event_match_returns_not_found(ti_api_db):
    res = client.get(
        "/api/v1/events/missing-event/threat-intel",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 404


def test_threat_intel_feed_ingest_via_api(ti_api_db):
    """Verify POST /api/v1/threat-intel/feeds/ingest with inline payload."""
    payload = {
        "source_id": "api_test_feed",
        "source_name": "API Test Feed",
        "feed_payload": {
            "feed_name": "Inline API Feed",
            "version": "1.0",
            "indicators": [
                {
                    "type": "domain",
                    "value": "api-ingested-malware.com",
                    "reputation_score": 85.0,
                    "classification": "malicious",
                }
            ],
        },
    }
    res = client.post(
        "/api/v1/threat-intel/feeds/ingest",
        json=payload,
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["accepted_count"] == 1
    assert data["quarantined_count"] == 0

    # Verify queryable immediately
    res_lookup = client.get(
        "/api/v1/threat-intel/lookup?type=domain&value=api-ingested-malware.com",
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_lookup.status_code == 200
    assert res_lookup.json()["verdict"] == "malicious"


def test_threat_intel_rbac_protection(ti_api_db):
    """Verify VIEWER role cannot access threat intel endpoints or ingest feeds."""
    res_lookup = client.get(
        "/api/v1/threat-intel/lookup?type=ipv4&value=198.51.100.55",
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_lookup.status_code == 403

    res_ingest = client.post(
        "/api/v1/threat-intel/feeds/ingest",
        json={"file_path": "datasets/threat_intel/sample_feed.json"},
        headers={"X-Operator-Role": "SOC_ANALYST"},  # Only SECURITY_ENGINEER or ADMIN
    )
    assert res_ingest.status_code == 403
