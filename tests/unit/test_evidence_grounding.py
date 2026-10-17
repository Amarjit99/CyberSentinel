"""CyberSentinel AI — Unit Tests: Evidence Grounding & Reference Validation (Phase 5)"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.agents.evidence_validator import EvidenceValidator
from services.agents.models import AgentFinding
from services.persistence.models import (
    Base,
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
)


@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()
    engine.dispose()


def test_evidence_validator_accepts_genuine_records(memory_db):
    """Verify EvidenceValidator accepts genuinely linked incident records."""
    now = datetime.now(timezone.utc)
    inc = Incident(
        id="inc-test-01",
        title="Brute Force Alert",
        first_seen=now,
        last_seen=now,
    )
    det = Detection(
        id="det-test-01",
        rule_id="sigma-auth-fail",
        rule_version="1.0",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    link = IncidentDetection(
        incident_id=inc.id,
        detection_id=det.id,
        link_reason="Correlated",
        linked_by="engine",
        linked_at=now,
    )
    ent = IncidentEntity(
        incident_id=inc.id,
        entity_type="user",
        entity_key="admin_user",
        relation="target",
        first_seen=now,
        last_seen=now,
    )
    ev = Evidence(
        id="ev-test-01",
        incident_id=inc.id,
        evidence_type="log_slice",
        source_ref="s3://evidence/01.log",
        checksum="abc123hash",
        created_by="agent",
        collected_at=now,
    )

    memory_db.add_all([inc, det, link, ent, ev])
    memory_db.commit()

    validator = EvidenceValidator(session=memory_db)

    # 1. Test detection verification
    is_valid, rtype, _ = validator.validate_reference(inc.id, "det-test-01")
    assert is_valid is True
    assert rtype == "detection"

    # 2. Test entity verification
    is_valid, rtype, _ = validator.validate_reference(inc.id, "admin_user")
    assert is_valid is True
    assert rtype == "entity"

    # 3. Test evidence verification
    is_valid, rtype, _ = validator.validate_reference(inc.id, "ev-test-01")
    assert is_valid is True
    assert rtype == "evidence"


def test_evidence_validator_rejects_hallucinated_and_cross_incident_references(memory_db):
    """Verify EvidenceValidator rejects hallucinated references and records from another incident."""
    now = datetime.now(timezone.utc)
    inc_a = Incident(id="inc-A", title="Incident A", first_seen=now, last_seen=now)
    inc_b = Incident(id="inc-B", title="Incident B", first_seen=now, last_seen=now)
    ev_b = Evidence(
        id="ev-B-01",
        incident_id="inc-B",
        evidence_type="pcap",
        source_ref="s3://evidence/b.pcap",
        checksum="hash-b",
        created_by="agent",
        collected_at=now,
    )
    memory_db.add_all([inc_a, inc_b, ev_b])
    memory_db.commit()

    validator = EvidenceValidator(session=memory_db)

    # 1. Hallucinated / Non-existent record ID
    is_valid, _, _ = validator.validate_reference("inc-A", "det-hallucinated-999")
    assert is_valid is False

    # 2. Cross-incident record: belongs to inc-B, cited in inc-A
    is_valid, _, _ = validator.validate_reference("inc-A", "ev-B-01")
    assert is_valid is False


def test_finding_demoted_to_hypothesis_when_evidence_unverified(memory_db):
    """Verify that an ungrounded finding with fabricated evidence is demoted to a hypothesis."""
    now = datetime.now(timezone.utc)
    inc = Incident(id="inc-01", title="Test Incident", first_seen=now, last_seen=now)
    memory_db.add(inc)
    memory_db.commit()

    validator = EvidenceValidator(session=memory_db)

    # Finding asserting factual certainty with fabricated evidence ID
    finding = AgentFinding(
        run_id="run-001",
        finding_type="detection_analysis",
        claim="Malicious executable deployed",
        confidence=0.95,
        evidence_refs=["fabricated-det-12345"],
        is_hypothesis=False,
    )

    validated_finding, is_valid = validator.validate_finding("inc-01", finding)

    # The fabricated reference must be stripped, and finding demoted to hypothesis
    assert len(validated_finding.evidence_refs) == 0
    assert validated_finding.is_hypothesis is True
    assert validated_finding.confidence <= 0.4
    assert is_valid is False
    assert "Demoted to hypothesis" in (validated_finding.limitations or "")
