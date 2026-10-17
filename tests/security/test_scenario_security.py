"""CyberSentinel AI — Security Tests: Scenario Adversarial Defenses & Safety Gates (Sprint 22)
Verifies:
- SCN-10: Prompt injection embedded in incident telemetry is quarantined and defanged.
- SCN-11: Poisoned knowledge base documents cannot escape delimiters.
- SCN-12: Unauthorized tool execution is denied; LIVE_RESPONSE_DISABLED=true blocks live containment.
- SCN-NEG-04: Malformed telemetry is quarantined without corrupting the pipeline.
Governing Decisions: ADR-0005, ADR-0006, CSAI-R1.1-LAB-SCENARIOS
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scenarios.catalogue import default_scenario_catalogue
from scenarios.models import ScenarioStatusEnum
from scenarios.runner import default_scenario_runner
from scenarios.validator import default_scenario_validator
from services.persistence.models import Base


@pytest.fixture
def sec_db():
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
async def test_scenario_prompt_injection_quarantine(sec_db):
    """Verify SCN-10: Prompt injection embedded in command line telemetry is detected and quarantined."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-10-PROMPT-INJECTION")
    assert scenario is not None

    record = await runner.run_scenario(scenario, sec_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert record.prompt_injection_detected is True
    assert record.prompt_injection_quarantined is True
    assert "prompt_injection_defense" in record.stages_exercised


@pytest.mark.asyncio
async def test_scenario_poisoned_knowledge_doc_delimiter_escaped(sec_db):
    """Verify SCN-11: RAG engine defangs retrieved delimiters preventing prompt context escapes."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-11-POISONED-KNOWLEDGE-DOC")
    assert scenario is not None

    record = await runner.run_scenario(scenario, sec_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert "rag_sanitization" in record.stages_exercised
    assert any("delimiter successfully escaped" in note for note in record.notes)


@pytest.mark.asyncio
async def test_scenario_unauthorized_tool_call_and_safety_switch(sec_db):
    """Verify SCN-12: ToolExecutionService denies arbitrary calls; LIVE_RESPONSE_DISABLED=true blocks containment."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-12-UNAUTHORIZED-TOOL-CALL")
    assert scenario is not None

    record = await runner.run_scenario(scenario, sec_db)

    assert record.status == ScenarioStatusEnum.PASS
    assert "governance_abuse_prevention" in record.stages_exercised
    assert record.response_safety_switch_verified is True
    assert any("LIVE_RESPONSE_DISABLED=true safety switch blocked" in note for note in record.notes)


@pytest.mark.asyncio
async def test_negative_control_malformed_telemetry_quarantined(sec_db):
    """Verify SCN-NEG-04: Invalid port numbers are rejected during normalization without pipeline crash."""
    runner = default_scenario_runner
    scenario = default_scenario_catalogue.get_scenario("SCN-NEG-04-MALFORMED-TELEMETRY")
    assert scenario is not None

    record = await runner.run_scenario(scenario, sec_db)

    # Negative case safely handled
    assert record.status == ScenarioStatusEnum.PASS
    assert record.events_normalized_count == 0
    assert len(record.normalization_errors) == 1
    assert "dst_port" in record.normalization_errors[0] or "validation failed" in record.normalization_errors[0]


def test_scenario_validator_rejects_arbitrary_shell_tokens():
    """Verify that dangerous subprocess/shell tokens in scenario definitions are blocked."""
    malicious_scenario = {
        "scenario_id": "SCN-01-EVIL-RUNNER",
        "version": "1.0.0",
        "name": "subprocess.Popen(['rm', '-rf'])",
        "description": "Attempting process invocation via scenario parser.",
        "objective": "Verify static rejection of shell commands.",
        "category": "authentication",
        "synthetic_events": [
            {
                "event_id": "44444444-4444-4444-4444-444444444444",
                "timestamp": "2026-10-17T08:00:00Z",
                "source_type": "linux",
                "source_name": "auditd",
                "event_type": "authentication",
                "username": "root",
            }
        ],
    }
    result = default_scenario_validator.validate_scenario(malicious_scenario)
    assert result.is_valid is False
    assert any("Executable code pattern" in err for err in result.errors)
