"""CyberSentinel AI — Integration Tests: Threat Intel Persistence & Enrichment (Sprint 13)"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from services.persistence.models import (
    Base,
    ThreatIndicator,
    ThreatIndicatorRecord,
    ThreatSource,
)
from services.threat_intel.parsers import ParsedFeedRecord
from services.threat_intel.service import ThreatIntelService


@pytest.fixture
def ti_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


def test_ingest_feed_file_stix_and_json_fixtures(ti_db):
    """Verify end-to-end ingestion of local STIX 2.1 and JSON feed files into relational tables."""
    service = ThreatIntelService(session=ti_db)

    # 1. Ingest STIX bundle fixture
    stix_path = Path("datasets/threat_intel/sample_stix_bundle.json")
    res_stix = service.ingest_feed_file(ti_db, stix_path)
    assert res_stix.accepted_count == 4
    assert res_stix.quarantined_count == 0

    # 2. Ingest JSON feed fixture
    json_path = Path("datasets/threat_intel/sample_feed.json")
    res_json = service.ingest_feed_file(ti_db, json_path)
    assert res_json.accepted_count == 4
    assert res_json.quarantined_count == 0

    # Verify tables populated
    sources = ti_db.query(ThreatSource).all()
    assert len(sources) >= 2

    indicators = ti_db.query(ThreatIndicator).all()
    assert len(indicators) >= 7

    records = ti_db.query(ThreatIndicatorRecord).all()
    assert len(records) >= 8


def test_duplicate_feed_ingestion_is_idempotent(ti_db):
    """Verify that repeated feed imports do not duplicate records and update existing entries."""
    service = ThreatIntelService(session=ti_db)
    stix_path = Path("datasets/threat_intel/sample_stix_bundle.json")

    # First run
    res1 = service.ingest_feed_file(ti_db, stix_path)
    assert res1.accepted_count == 4
    assert res1.duplicate_count == 0

    # Second run with same fixture
    res2 = service.ingest_feed_file(ti_db, stix_path)
    assert res2.accepted_count == 0
    assert res2.duplicate_count == 4


def test_indicator_lookup_active_malicious(ti_db):
    """Verify lookup of known active malicious indicator returns structured attribution and score."""
    service = ThreatIntelService(session=ti_db)
    json_path = Path("datasets/threat_intel/sample_feed.json")
    service.ingest_feed_file(ti_db, json_path)

    # Query 198.51.100.55
    result = service.lookup_indicator(
        indicator_type="ipv4", indicator_value="198.51.100.55", session=ti_db
    )
    assert result.found is True
    assert result.is_valid is True
    assert result.verdict == "malicious"
    assert result.threat_actor == "APT-29 (Cozy Bear)"
    assert result.campaign == "Operation-Sentinel-Test"
    assert result.normalized_score == 95.0
    assert result.has_score is True
    assert result.is_expired is False
    assert len(result.records) >= 1

    agent_dict = result.to_agent_dict()
    assert agent_dict["reputation"] == "malicious"
    assert agent_dict["score"] == 95.0
    assert "APT-29" in agent_dict["threat_actor"]


def test_indicator_lookup_expired_record(ti_db):
    """Verify that an expired indicator observation is flagged as expired and not active."""
    service = ThreatIntelService(session=ti_db)
    stix_path = Path("datasets/threat_intel/sample_stix_bundle.json")
    service.ingest_feed_file(ti_db, stix_path)

    # 203.0.113.99 is expired in the STIX fixture (valid_until 2023)
    result = service.lookup_indicator(
        indicator_type="ipv4", indicator_value="203.0.113.99", session=ti_db, include_expired=False
    )
    assert result.found is True
    assert result.verdict == "expired"
    assert result.is_expired is True
    assert "expired" in result.limitations.lower()


def test_indicator_lookup_unknown_record(ti_db):
    """Verify that an unknown indicator returns unknown verdict and explicit limitations."""
    service = ThreatIntelService(session=ti_db)

    result = service.lookup_indicator(
        indicator_type="ipv4", indicator_value="192.0.2.1", session=ti_db
    )
    assert result.found is False
    assert result.verdict == "unknown"
    assert result.normalized_score is None
    assert "absence of evidence" in result.limitations.lower()


def test_conflicting_sources_handling(ti_db):
    """Verify that conflicting classifications (malicious vs benign) from different sources are detected."""
    service = ThreatIntelService(session=ti_db)
    now = datetime.now(timezone.utc)

    # Source 1: malicious
    records_src1 = [
        ParsedFeedRecord(
            indicator_type="domain",
            indicator_value="conflicted.example.com",
            raw_value="conflicted.example.com",
            external_record_id="c1",
            source_classification="malicious",
            source_reputation_score=90.0,
            confidence=80.0,
            expires_at=now + timedelta(days=30),
        )
    ]
    service.ingest_records(ti_db, "src_evil", "Adversary Tracker", "json_feed", records_src1)

    # Source 2: benign
    records_src2 = [
        ParsedFeedRecord(
            indicator_type="domain",
            indicator_value="conflicted.example.com",
            raw_value="conflicted.example.com",
            external_record_id="c2",
            source_classification="benign",
            source_reputation_score=0.0,
            confidence=95.0,
            expires_at=now + timedelta(days=30),
        )
    ]
    service.ingest_records(ti_db, "src_good", "Legitimate CDN Allowlist", "json_feed", records_src2)

    result = service.lookup_indicator(
        indicator_type="domain", indicator_value="conflicted.example.com", session=ti_db
    )
    assert result.found is True
    assert len(result.conflicts) > 0
    assert any("conflicting" in c.lower() for c in result.conflicts)
    assert len(result.records) == 2
    assert result.reliability_weighted_score is not None
    assert result.reliability_summary["B"] == 2
