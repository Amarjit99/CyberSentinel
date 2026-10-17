"""CyberSentinel AI — Unit Tests: Scenario Framework & Static Validator (Sprint 22)
Tests scenario definition contracts, schema validation, safety token rejection, and catalogue discovery.
Governing Decisions: ADR-0005, CSAI-R1.1-LAB-SCENARIOS
"""


from scenarios.catalogue import default_scenario_catalogue
from scenarios.models import (
    ScenarioCategoryEnum,
)
from scenarios.validator import default_scenario_validator


def test_catalogue_loads_all_fixtures():
    """Verify that all 16 scenario fixture files in scenarios/fixtures load and validate cleanly."""
    catalogue = default_scenario_catalogue
    assert catalogue.scenario_count == 16
    scenarios = catalogue.list_scenarios()
    ids = [s.scenario_id for s in scenarios]

    # Check 12 primary defensive scenarios
    for i in range(1, 13):
        expected_prefix = f"SCN-{i:02d}-"
        assert any(sid.startswith(expected_prefix) for sid in ids), f"Missing primary scenario {expected_prefix}"

    # Check 4 negative controls
    for i in range(1, 5):
        expected_neg = f"SCN-NEG-{i:02d}-"
        assert any(sid.startswith(expected_neg) for sid in ids), f"Missing negative scenario {expected_neg}"


def test_validator_accepts_valid_scenario_definition():
    """Verify that a compliant ScenarioDefinition passes validation without errors."""
    valid_data = {
        "scenario_id": "SCN-01-AUTH-BRUTEFORCE",
        "version": "1.0.0",
        "name": "Brute-Force Authentication Test",
        "description": "Simulates four failed login attempts to verify detection rule.",
        "objective": "Verify auth_root_failed triggers alert.",
        "category": "authentication",
        "is_negative_case": False,
        "required_telemetry_sources": ["linux"],
        "required_canonical_fields": ["username"],
        "attack_technique_ids": ["T1110"],
        "synthetic_events": [
            {
                "event_id": "11111111-1111-1111-1111-111111111111",
                "timestamp": "2026-10-17T08:00:00Z",
                "source_type": "linux",
                "source_name": "auditd",
                "event_type": "authentication",
                "username": "root",
                "severity": "high",
            }
        ],
        "expected_detection_rules": ["auth_root_failed"],
        "cleanup_policy": "session_rollback",
    }
    result = default_scenario_validator.validate_scenario(valid_data)
    assert result.is_valid is True
    assert len(result.errors) == 0
    assert result.event_count == 1


def test_validator_rejects_malformed_scenario_id():
    """Verify that scenario IDs not conforming to standard naming pattern are rejected."""
    bad_data = {
        "scenario_id": "invalid_id_format_123",
        "version": "1.0.0",
        "name": "Bad ID Test",
        "description": "This scenario has an invalid identifier.",
        "objective": "Test schema validation rejection.",
        "category": "authentication",
        "synthetic_events": [{"event_type": "auth"}],
    }
    result = default_scenario_validator.validate_scenario(bad_data)
    assert result.is_valid is False
    assert any("scenario_id" in err for err in result.errors)


def test_validator_rejects_executable_code_in_metadata():
    """Verify that dangerous executable code patterns in scenario metadata are blocked."""
    injected_data = {
        "scenario_id": "SCN-01-MALICIOUS-DEF",
        "version": "1.0.0",
        "name": "eval(os.system('id'))",  # Code execution injection attempt
        "description": "Attempting code injection in scenario definition.",
        "objective": "Verify rejection of executable code tokens.",
        "category": "authentication",
        "synthetic_events": [
            {
                "event_id": "22222222-2222-2222-2222-222222222222",
                "timestamp": "2026-10-17T08:00:00Z",
                "source_type": "linux",
                "source_name": "auditd",
                "event_type": "authentication",
                "username": "root",
            }
        ],
    }
    result = default_scenario_validator.validate_scenario(injected_data)
    assert result.is_valid is False
    assert any("Executable code pattern" in err for err in result.errors)


def test_validator_rejects_oversized_event_count():
    """Verify that scenarios exceeding MAX_EVENTS_PER_SCENARIO are rejected."""
    huge_events = [
        {
            "event_id": f"33333333-3333-3333-3333-{i:012d}",
            "timestamp": "2026-10-17T08:00:00Z",
            "source_type": "linux",
            "source_name": "auditd",
            "event_type": "authentication",
            "username": f"user_{i}",
        }
        for i in range(105)  # Max is 100
    ]
    huge_data = {
        "scenario_id": "SCN-01-HUGE-COUNT",
        "version": "1.0.0",
        "name": "Oversized Event Count Test",
        "description": "Too many events.",
        "objective": "Test event limit enforcement.",
        "category": "authentication",
        "synthetic_events": huge_events,
    }
    result = default_scenario_validator.validate_scenario(huge_data)
    assert result.is_valid is False
    assert any("exceeding the maximum allowed limit" in err for err in result.errors)


def test_catalogue_filter_by_category():
    """Verify scenario catalogue filtering by category."""
    catalogue = default_scenario_catalogue
    auth_scenarios = catalogue.list_scenarios(category="authentication")
    assert len(auth_scenarios) >= 1
    for s in auth_scenarios:
        assert s.category == ScenarioCategoryEnum.AUTHENTICATION

    benign_scenarios = catalogue.list_scenarios(category="benign_baseline")
    assert len(benign_scenarios) == 4
