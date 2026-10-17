"""Tests for Phase 4 Correlation Rule Definition, Validation, and Loading."""

import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.enums import EventSeverityEnum
from services.correlation.engine import CorrelationEngine
from services.correlation.models import CorrelationRule, SequenceStep


def test_valid_threshold_correlation_rule():
    rule = CorrelationRule(
        id=str(uuid.uuid4()),
        name="Test Brute Force Rule",
        description="Detects multiple failed logins",
        severity=EventSeverityEnum.HIGH,
        group_by=["username"],
        window_seconds=300,
        threshold=5,
        detection_rule_ids=["sigma-auth-failed-001"],
        enabled=True,
    )
    assert rule.name == "Test Brute Force Rule"
    assert rule.window_seconds == 300
    assert rule.threshold == 5
    assert rule.group_by == ["username"]
    assert rule.sequence is None


def test_valid_sequence_correlation_rule():
    rule = CorrelationRule(
        id=str(uuid.uuid4()),
        name="Test Recon to Execution",
        description="Recon followed by execution",
        severity=EventSeverityEnum.CRITICAL,
        group_by=["hostname"],
        window_seconds=600,
        threshold=2,
        sequence=[
            SequenceStep(step_id="step1", rule_id="sigma-recon-001"),
            SequenceStep(step_id="step2", rule_id="sigma-exec-002"),
        ],
        enabled=True,
    )
    assert len(rule.sequence) == 2
    assert rule.sequence[0].step_id == "step1"
    assert rule.sequence[1].step_id == "step2"


def test_rule_invalid_window_seconds():
    with pytest.raises(ValidationError):
        CorrelationRule(
            id=str(uuid.uuid4()),
            name="Invalid Window",
            description="Window is 0",
            severity=EventSeverityEnum.MEDIUM,
            group_by=["src_ip"],
            window_seconds=0,
            threshold=2,
        )


def test_rule_invalid_threshold():
    with pytest.raises(ValidationError):
        CorrelationRule(
            id=str(uuid.uuid4()),
            name="Invalid Threshold",
            description="Threshold is 0",
            severity=EventSeverityEnum.MEDIUM,
            group_by=["src_ip"],
            window_seconds=60,
            threshold=0,
        )


def test_rule_invalid_sequence_steps():
    with pytest.raises(ValueError, match="at least 2 steps"):
        CorrelationRule(
            id=str(uuid.uuid4()),
            name="Invalid Single Step Sequence",
            description="Sequence has only 1 step",
            severity=EventSeverityEnum.HIGH,
            group_by=["hostname"],
            window_seconds=300,
            threshold=1,
            sequence=[
                SequenceStep(step_id="step1", rule_id="sigma-step-1"),
            ],
        )


def test_rule_invalid_group_by_field():
    with pytest.raises(ValueError, match="Unsupported group_by field"):
        CorrelationRule(
            id=str(uuid.uuid4()),
            name="Invalid Group By",
            description="Invalid group by field",
            severity=EventSeverityEnum.HIGH,
            group_by=["non_existent_field_123"],
            window_seconds=300,
            threshold=2,
        )


def test_engine_load_rules_from_directory(tmp_path: Path):
    rule_yaml = """
id: 550e8400-e29b-41d4-a716-446655440000
name: Directory Loaded Rule
description: Rule loaded from temporary YAML file
severity: high
group_by:
  - username
window_seconds: 120
threshold: 3
detection_rule_ids:
  - sigma-auth-failed-001
enabled: true
"""
    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(rule_yaml, encoding="utf-8")

    engine = CorrelationEngine()
    loaded = engine.load_rules_from_directory(str(tmp_path))
    assert loaded == 1
    assert len(engine.list_rules()) == 1
    loaded_rule = engine.get_rule("550e8400-e29b-41d4-a716-446655440000")
    assert loaded_rule is not None
    assert loaded_rule.name == "Directory Loaded Rule"
