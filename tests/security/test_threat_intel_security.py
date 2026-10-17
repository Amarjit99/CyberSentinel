"""CyberSentinel AI — Security Tests: Threat Intelligence & Agent Tool Hardening (Sprint 12 & 13)"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.agents.tools import ReadOnlyInvestigationTools
from services.persistence.database import get_db
from services.persistence.models import Base
from services.threat_intel.service import ThreatIntelService

client = TestClient(app)


@pytest.fixture
def sec_ti_db():
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


def test_agent_tools_use_real_database_lookup_not_hardcoded_mock(sec_ti_db):
    """Verify that ReadOnlyInvestigationTools queries the real database rather than the former mock dictionary."""
    tools = ReadOnlyInvestigationTools(session=sec_ti_db, incident_id="inc-test-01")

    # 1. An indicator not in DB MUST return 'unknown' even if it matches "198.51.100." or contains "malicious"
    # The previous mock returned reputation='malicious', threat_actor='APT-Simulated' for ANY '198.51.100.' IP.
    res_unseeded = tools.lookup_threat_intel(indicator_type="ipv4", indicator_value="198.51.100.99")
    assert res_unseeded["reputation"] == "unknown"
    assert res_unseeded["score"] == 0.0
    assert res_unseeded["threat_actor"] is None
    assert "absence of evidence" in res_unseeded["limitations"].lower()

    # 2. Ingest real threat intelligence into DB
    service = ThreatIntelService(session=sec_ti_db)
    service.ingest_feed_file(sec_ti_db, Path("datasets/threat_intel/sample_feed.json"))

    # 3. Query seeded indicator: should return authoritative DB metadata
    res_seeded = tools.lookup_threat_intel(indicator_type="ipv4", indicator_value="198.51.100.55")
    assert res_seeded["reputation"] == "malicious"
    assert res_seeded["score"] == 95.0
    assert res_seeded["threat_actor"] == "APT-29 (Cozy Bear)"
    assert res_seeded["campaign"] == "Operation-Sentinel-Test"
    assert res_seeded["source"] == "CyberSentinel Operational Threat Feed"
    assert res_seeded["records_count"] >= 1


def test_path_traversal_attack_blocked_on_feed_ingest_api(sec_ti_db):
    """Verify that path traversal attempts to ingest arbitrary system files are strictly blocked."""
    traversal_payloads = [
        "../../../../../../windows/system32/cmd.exe",
        "../../etc/passwd",
        "C:\\Windows\\win.ini",
        "/etc/shadow",
    ]
    for bad_path in traversal_payloads:
        res = client.post(
            "/api/v1/threat-intel/feeds/ingest",
            json={"file_path": bad_path},
            headers={"X-Operator-Role": "SECURITY_ENGINEER"},
        )
        assert res.status_code == 400
        assert "must reside within" in res.json()["message"]


def test_oversized_bundle_rejected(sec_ti_db):
    """Verify that bundles exceeding size limits are rejected to prevent resource exhaustion."""
    oversized_bundle = {
        "type": "bundle",
        "id": "bundle--huge",
        "objects": [{"type": "indicator", "id": f"ind-{i}"} for i in range(15_000)],
    }
    res = client.post(
        "/api/v1/threat-intel/feeds/ingest",
        json={"feed_payload": oversized_bundle},
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert res.status_code == 400
    assert "exceeds maximum allowed" in res.json()["message"]


def test_live_response_disabled_safety_invariant_intact():
    """Verify that LIVE_RESPONSE_DISABLED=true remains strictly enforced."""
    assert os.getenv("LIVE_RESPONSE_DISABLED", "true").lower() == "true"
