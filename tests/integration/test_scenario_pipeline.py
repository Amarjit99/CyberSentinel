"""CyberSentinel AI — Integration Tests: Scenario Pipeline Evaluation (Sprint 22)
Tests end-to-end execution of synthetic lab scenarios across real pipeline components:
Normalization -> Sigma Detection -> Correlation -> Incident Lifecycle -> Risk -> Triage -> Investigation.
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R1.1-LAB-SCENARIOS
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scenarios.catalogue import default_scenario_catalogue
from scenarios.models import ScenarioStatusEnum
from scenarios.runner import default_scenario_runner
from services.persistence.models import Base


@pytest.fixture
def scenario_db():
    """Isolated, transactional in-memory database session for scenario runs."""
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


@pytest.mark.asyncio
async def test_pipeline_executes_auth_bruteforce_scenario(scenario_db):
    """Verify SCN-01: Ingestion -> Sigma auth_root_failed -> corr_brute_force_auth -> Incident -> Triage -> Investigation."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-01-AUTH-BRUTEFORCE")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert record.events_ingested_count == 4
    assert record.events_normalized_count == 4
    assert len(record.normalization_errors) == 0

    # Detections
    assert any("auth_root_failed" in m.lower() for m in record.matched_detection_rules)
    assert len(record.missing_expected_detections) == 0
    assert len(record.unexpected_detections) == 0

    # Correlation & Incident
    assert record.correlated_rule_id == "44444444-4444-4444-4444-444444444444"
    assert record.incident_id is not None
    assert record.incident_severity == "high"

    # Risk & Triage
    assert record.risk_score is not None
    assert record.risk_score >= 40.0
    assert record.risk_band.upper() in ["MEDIUM", "HIGH", "CRITICAL"]
    assert record.triage_summary is not None
    assert record.triage_severity in ["high", "critical"]

    # Investigation & Grounding
    assert record.investigation_run_id is not None
    assert len(record.finding_claims) > 0
    assert len(record.evidence_refs) > 0


@pytest.mark.asyncio
async def test_pipeline_executes_suspicious_powershell_scenario(scenario_db):
    """Verify SCN-02: Ingestion -> Sigma proc_powershell_download -> Incident -> Triage."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-02-SUSPICIOUS-POWERSHELL")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert any("proc_powershell_download" in m.lower() for m in record.matched_detection_rules)
    assert record.incident_id is not None
    assert record.risk_band.upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert record.triage_summary is not None


@pytest.mark.asyncio
async def test_pipeline_executes_suspicious_dns_scenario(scenario_db):
    """Verify SCN-05: Ingestion -> Sigma net_suspicious_dns -> Dynamic DNS alert."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-05-SUSPICIOUS-DNS")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert any("net_suspicious_dns" in m.lower() for m in record.matched_detection_rules)
    assert record.incident_id is not None


@pytest.mark.asyncio
async def test_pipeline_executes_multi_stage_intrusion_scenario(scenario_db):
    """Verify SCN-09: Discovery followed by execution triggers corr_recon_to_execution."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-09-MULTI-STAGE-INTRUSION")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert any("whoami" in m.lower() for m in record.matched_detection_rules)
    assert any("powershell" in m.lower() for m in record.matched_detection_rules)

    # Multi-stage correlation triggered!
    assert record.correlated_rule_id == "55555555-5555-5555-5555-555555555555"
    assert record.incident_id is not None
    assert record.incident_severity == "critical"
    assert record.risk_band.upper() in ["MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_negative_control_benign_auth_below_threshold(scenario_db):
    """Verify SCN-NEG-01: Single login typo matches Sigma rule, but correlation threshold of 3 prevents incident."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-NEG-01-BENIGN-AUTH")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert any("auth_root_failed" in m.lower() for m in record.matched_detection_rules)
    # Correlation must NOT trigger
    assert record.correlated_rule_id is None
    assert record.incident_id is None


@pytest.mark.asyncio
async def test_negative_control_legitimate_admin_whitelisted(scenario_db):
    """Verify SCN-NEG-02: trusted_updater account is filtered out by Sigma rule; zero detections produced."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-NEG-02-LEGITIMATE-ADMIN")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert len(record.matched_detection_rules) == 0
    assert len(record.unexpected_detections) == 0
    assert record.incident_id is None


@pytest.mark.asyncio
async def test_negative_control_benign_dns_traffic(scenario_db):
    """Verify SCN-NEG-03: Internal corporate DNS queries produce zero detections."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-NEG-03-BENIGN-DNS")
    assert scenario is not None

    record = await runner.run_scenario(scenario, scenario_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert len(record.matched_detection_rules) == 0
    assert len(record.unexpected_detections) == 0


@pytest.mark.asyncio
async def test_full_scenario_suite_run_compiles_metrics(scenario_db):
    """Verify run_suite executes multiple scenarios and generates aggregate lab metrics."""
    runner = default_scenario_runner
    catalogue = default_scenario_catalogue
    test_scenarios = [
        catalogue.get_scenario("SCN-01-AUTH-BRUTEFORCE"),
        catalogue.get_scenario("SCN-02-SUSPICIOUS-POWERSHELL"),
        catalogue.get_scenario("SCN-NEG-01-BENIGN-AUTH"),
        catalogue.get_scenario("SCN-NEG-02-LEGITIMATE-ADMIN"),
    ]
    report = await runner.run_suite(test_scenarios, scenario_db)

    assert report.total_scenarios == 4
    assert report.passed_scenarios == 4
    assert report.failed_scenarios == 0
    assert report.lab_detection_rate == 100.0
    assert report.lab_false_positive_count == 0
    assert len(report.scenario_records) == 4
