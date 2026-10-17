"""Unit Tests for Sigma Detection Engine
Traceability: CSAI-P3-DETECTION, ADR-0004, Gate G3
"""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.detection.engine import SigmaDetectionEngine

RULE_1_YAML = """
title: Test Rule 1 - Suspicious PowerShell
id: 11111111-1111-1111-1111-111111111111
status: stable
logsource:
    category: process_creation
detection:
    sel:
        process_name: powershell.exe
    condition: sel
level: high
"""

RULE_2_YAML = """
title: Test Rule 2 - Suspicious Command Line
id: 22222222-2222-2222-2222-222222222222
status: stable
logsource:
    category: process_creation
detection:
    sel:
        command_line|contains: mimikatz
    condition: sel
level: critical
"""

RULE_3_NETWORK_YAML = """
title: Test Rule 3 - Suspicious DNS
id: 33333333-3333-3333-3333-333333333333
status: stable
logsource:
    category: dns
detection:
    sel:
        domain|endswith: .top
    condition: sel
level: medium
"""


def test_engine_load_rules_and_count():
    """Verify loading multiple rules into the engine."""
    engine = SigmaDetectionEngine()
    r1 = engine.load_rule(RULE_1_YAML)
    r2 = engine.load_rule(RULE_2_YAML)

    assert r1.rule_id == "11111111-1111-1111-1111-111111111111"
    assert r2.rule_id == "22222222-2222-2222-2222-222222222222"
    assert engine.rule_count == 2


def test_engine_evaluates_single_match():
    """Verify engine returns 1 DetectionResult when 1 rule matches."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_1_YAML)
    engine.load_rule(RULE_2_YAML)
    engine.load_rule(RULE_3_NETWORK_YAML)

    now = datetime.now(timezone.utc)
    event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -Command Write-Host Hello",
        severity="low",
    )

    results = engine.evaluate(event)
    assert len(results) == 1
    assert results[0].rule_id == "11111111-1111-1111-1111-111111111111"
    assert results[0].severity == EventSeverityEnum.HIGH
    assert results[0].event_id == str(event.event_id)


def test_engine_evaluates_multiple_matches():
    """Verify engine returns multiple DetectionResults when multiple rules match."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_1_YAML)
    engine.load_rule(RULE_2_YAML)

    now = datetime.now(timezone.utc)
    event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc invoke-mimikatz",
        severity="low",
    )

    results = engine.evaluate(event)
    assert len(results) == 2
    rule_ids = {r.rule_id for r in results}
    assert "11111111-1111-1111-1111-111111111111" in rule_ids
    assert "22222222-2222-2222-2222-222222222222" in rule_ids


def test_engine_evaluates_zero_matches():
    """Verify engine returns empty list when no rules match."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_1_YAML)
    engine.load_rule(RULE_2_YAML)

    now = datetime.now(timezone.utc)
    event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="notepad.exe",
        command_line="notepad.exe doc.txt",
        severity="low",
    )

    results = engine.evaluate(event)
    assert len(results) == 0


def test_engine_load_rules_from_directory_with_faulty_rule_isolation():
    """Verify engine loads valid rules and isolates faulty rules without crashing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        dir_path = Path(temp_dir)
        (dir_path / "valid1.yml").write_text(RULE_1_YAML, encoding="utf-8")
        (dir_path / "valid2.yaml").write_text(RULE_3_NETWORK_YAML, encoding="utf-8")
        (dir_path / "corrupt.yml").write_text("invalid: yaml: [unbalanced", encoding="utf-8")

        engine = SigmaDetectionEngine()
        loaded = engine.load_rules_from_directory(temp_dir)

        # 2 valid rules should be loaded despite corrupt.yml
        assert loaded == 2
        assert engine.rule_count == 2
        rules = engine.list_rules()
        assert len(rules) == 2


def test_engine_reload_and_clear():
    """Verify clearing rules removes all active compiled rules."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_1_YAML)
    assert engine.rule_count == 1

    engine.clear_rules()
    assert engine.rule_count == 0


def test_engine_evaluate_dict():
    """Verify evaluating from dictionary representation."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_1_YAML)

    event_dict = {
        "event_id": "ev-custom-12345",
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "windows",
        "source_name": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "severity": "low",
    }

    results = engine.evaluate_dict(event_dict)
    assert len(results) == 1
    assert results[0].event_id == "ev-custom-12345"
