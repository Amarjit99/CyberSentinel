"""CyberSentinel AI — Unit Tests: Deterministic Explainable Incident Risk Engine (Sprint 14)"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from services.persistence.models import (
    Base,
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
)
from services.risk import (
    DeterministicRiskEngine,
    IncidentRiskBandEnum,
    RiskScoringPolicy,
)


@pytest.fixture
def risk_db_session():
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


def test_scoring_policy_validation():
    """Verify RiskScoringPolicy enforces weight summation to 1.0 and monotonic thresholds."""
    # Valid default policy
    policy = RiskScoringPolicy()
    assert sum(policy.weights.values()) == pytest.approx(1.0)
    assert policy.classify_score(25.0) == IncidentRiskBandEnum.LOW
    assert policy.classify_score(40.0) == IncidentRiskBandEnum.MEDIUM
    assert policy.classify_score(70.0) == IncidentRiskBandEnum.HIGH
    assert policy.classify_score(85.0) == IncidentRiskBandEnum.CRITICAL

    # Invalid weights sum
    with pytest.raises(ValueError, match="weights must sum to 1.0"):
        RiskScoringPolicy(weights={"detection_severity": 0.5})

    # Invalid band thresholds order
    with pytest.raises(ValueError, match="strictly increasing"):
        RiskScoringPolicy(
            band_thresholds={
                "LOW": 0.0,
                "MEDIUM": 80.0,
                "HIGH": 70.0,  # lower than MEDIUM
                "CRITICAL": 90.0,
            }
        )


def test_risk_band_boundaries():
    """Verify all risk band boundaries map to exactly one authoritative band."""
    policy = RiskScoringPolicy()

    assert policy.classify_score(0.0) == IncidentRiskBandEnum.LOW
    assert policy.classify_score(39.99) == IncidentRiskBandEnum.LOW
    assert policy.classify_score(40.0) == IncidentRiskBandEnum.MEDIUM
    assert policy.classify_score(69.99) == IncidentRiskBandEnum.MEDIUM
    assert policy.classify_score(70.0) == IncidentRiskBandEnum.HIGH
    assert policy.classify_score(84.99) == IncidentRiskBandEnum.HIGH
    assert policy.classify_score(85.0) == IncidentRiskBandEnum.CRITICAL
    assert policy.classify_score(100.0) == IncidentRiskBandEnum.CRITICAL
    # Out of bounds clamping
    assert policy.classify_score(-10.0) == IncidentRiskBandEnum.LOW
    assert policy.classify_score(150.0) == IncidentRiskBandEnum.CRITICAL


def test_deterministic_scoring_reproducibility(risk_db_session):
    """Verify identical inputs and policy produce the exact same score and explanation."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Brute Force Credential Access",
        status="NEW",
        severity="high",
        confidence=0.9,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    assessment_1 = engine.assess_incident(incident, risk_db_session, persist=False)
    assessment_2 = engine.assess_incident(incident, risk_db_session, persist=False)

    assert assessment_1.overall_score == assessment_2.overall_score
    assert assessment_1.risk_band == assessment_2.risk_band
    for factor_key in assessment_1.factors:
        assert assessment_1.factors[factor_key].raw_score == assessment_2.factors[factor_key].raw_score
        assert assessment_1.factors[factor_key].weighted_score == assessment_2.factors[factor_key].weighted_score


def test_missing_evidence_and_partial_assessments(risk_db_session):
    """Verify missing data yields neutral baselines and explicit uncertainty flags."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    # Incident with no evidence, no entities, no detections
    incident = Incident(
        id=inc_id,
        title="Sparse Incident",
        status="NEW",
        severity="medium",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    assessment = engine.assess_incident(incident, risk_db_session, persist=False)

    assert 0.0 <= assessment.overall_score <= 100.0
    assert assessment.risk_band in [IncidentRiskBandEnum.LOW, IncidentRiskBandEnum.MEDIUM]

    # Verify uncertainty caveats are populated
    assert any("No formal forensic evidence items" in u for u in assessment.uncertainties)
    assert any("No indicator entities" in d for d in assessment.factors["threat_intel_context"].drivers)
    assert any("No individual detection records linked" in u for u in assessment.uncertainties)


def test_evidence_strength_scaling(risk_db_session):
    """Verify evidence factor increases proportionally with count and integrity checksums."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Evidence Rich Incident",
        status="INVESTIGATING",
        severity="high",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    f_empty = engine._calculate_evidence_strength(incident, risk_db_session)
    assert f_empty.raw_score == 20.0

    # Add 2 evidence items with 64-char SHA-256 checksums
    ev1 = Evidence(
        id=str(uuid4()),
        incident_id=inc_id,
        evidence_type="memory_dump",
        source_ref="/var/log/mem.raw",
        checksum="a" * 64,
        provenance_json={"collector": "agent"},
        created_by="analyst_1",
    )
    ev2 = Evidence(
        id=str(uuid4()),
        incident_id=inc_id,
        evidence_type="pcap",
        source_ref="/var/log/traffic.pcap",
        checksum="b" * 64,
        provenance_json={"collector": "zeek"},
        created_by="analyst_1",
    )
    risk_db_session.add_all([ev1, ev2])
    risk_db_session.commit()

    f_loaded = engine._calculate_evidence_strength(incident, risk_db_session)
    assert f_loaded.raw_score > f_empty.raw_score
    assert len(f_loaded.supporting_evidence) == 2


def test_high_value_asset_scope_elevation(risk_db_session):
    """Verify presence of critical infrastructure or admin accounts elevates scope factor."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Privileged Asset Compromise",
        status="TRIAGE",
        severity="critical",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)

    # Standard entity
    e1 = IncidentEntity(
        incident_id=inc_id,
        entity_type="host",
        entity_key="workstation-42.local",
        relation="target",
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(e1)
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    f_standard = engine._calculate_incident_scope(incident, risk_db_session)

    # Add high-value domain controller entity
    e_dc = IncidentEntity(
        incident_id=inc_id,
        entity_type="host",
        entity_key="dc01-prod.corp.local",
        relation="target",
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(e_dc)
    risk_db_session.commit()

    f_elevated = engine._calculate_incident_scope(incident, risk_db_session)
    assert f_elevated.raw_score > f_standard.raw_score
    assert any("high-value" in d.lower() for d in f_elevated.drivers)


def test_correlation_context_multi_rule_corroboration(risk_db_session):
    """Verify correlation context awards higher score to multi-rule corroborated incidents."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Multi-Alert Corroboration",
        status="TRIAGE",
        severity="high",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)

    d1 = Detection(
        id="det-1",
        rule_id="sigma-powershell-enc",
        rule_version="1.0",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    d2 = Detection(
        id="det-2",
        rule_id="sigma-c2-beacon",
        rule_version="1.0",
        severity="critical",
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add_all([d1, d2])

    inc_d1 = IncidentDetection(
        incident_id=inc_id,
        detection_id=d1.id,
        link_reason="Correlated step 1",
        linked_by="correlation_engine",
    )
    inc_d2 = IncidentDetection(
        incident_id=inc_id,
        detection_id=d2.id,
        link_reason="Correlated step 2",
        linked_by="correlation_engine",
    )
    risk_db_session.add_all([inc_d1, inc_d2])
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    f_corr = engine._calculate_correlation_context(incident, risk_db_session)
    assert f_corr.raw_score == 75.0
    assert len(f_corr.supporting_evidence) == 2


def test_explain_assessment_response_structure(risk_db_session):
    """Verify explain_assessment produces complete, auditable breakdown with weights."""
    inc_id = f"inc-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=inc_id,
        title="Auditable Incident",
        status="NEW",
        severity="medium",
        confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    risk_db_session.add(incident)
    risk_db_session.commit()

    engine = DeterministicRiskEngine()
    assessment = engine.assess_incident(incident, risk_db_session, persist=False)
    explanation = engine.explain_assessment(assessment)

    assert explanation.incident_id == inc_id
    assert explanation.assessment_id == assessment.id
    assert len(explanation.factors) == 7
    assert len(explanation.weights_used) == 7
    assert sum(explanation.weights_used.values()) == pytest.approx(1.0)
    assert "Overall Score = Sum(Factor Raw Score * Factor Weight)" in explanation.formula_description
