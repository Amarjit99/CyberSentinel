"""Tests for Sliding Event Window, Temporal Ordering, Deduplication, and Threshold/Sequence Evaluation."""

import uuid
from datetime import datetime, timedelta, timezone

from schemas.enums import EventSeverityEnum
from services.correlation.models import CorrelationRule, SequenceStep
from services.correlation.window import SlidingEventWindow, WindowEntry


def create_sample_rule(
    window_seconds: int = 300,
    threshold: int = 3,
    cooldown_seconds: int = 60,
    sequence: list[SequenceStep] | None = None,
) -> CorrelationRule:
    return CorrelationRule(
        id=str(uuid.uuid4()),
        name="Sample Window Rule",
        description="Testing sliding window",
        severity=EventSeverityEnum.HIGH,
        group_by=["hostname"],
        window_seconds=window_seconds,
        threshold=threshold,
        cooldown_seconds=cooldown_seconds,
        sequence=sequence,
        enabled=True,
    )


def test_sliding_window_threshold_firing():
    rule = create_sample_rule(window_seconds=300, threshold=3)
    window = SlidingEventWindow(window_seconds=300)

    base_time = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    # Entry 1
    accepted1 = window.add_entry(
        WindowEntry(
            detection_id="det-1",
            rule_id="sigma-rule-1",
            rule_name="Test Sigma",
            event_id="evt-1",
            timestamp=base_time,
            tags=["attack.t1110"],
            severity=EventSeverityEnum.HIGH,
        )
    )
    assert accepted1 is True
    match1 = window.evaluate_rule(rule, "host", "workstation-01", base_time)
    assert match1 is None

    # Entry 2
    t2 = base_time + timedelta(seconds=30)
    window.add_entry(
        WindowEntry(
            detection_id="det-2",
            rule_id="sigma-rule-1",
            rule_name="Test Sigma",
            event_id="evt-2",
            timestamp=t2,
            tags=["attack.t1110"],
            severity=EventSeverityEnum.HIGH,
        )
    )
    match2 = window.evaluate_rule(rule, "host", "workstation-01", t2)
    assert match2 is None

    # Entry 3 (reaches threshold 3)
    t3 = base_time + timedelta(seconds=60)
    window.add_entry(
        WindowEntry(
            detection_id="det-3",
            rule_id="sigma-rule-1",
            rule_name="Test Sigma",
            event_id="evt-3",
            timestamp=t3,
            tags=["attack.t1110"],
            severity=EventSeverityEnum.HIGH,
        )
    )
    match3 = window.evaluate_rule(rule, "host", "workstation-01", t3)
    assert match3 is not None
    assert match3.entity_key == "workstation-01"
    assert len(match3.detection_ids) == 3
    assert "det-1" in match3.detection_ids
    assert "det-2" in match3.detection_ids
    assert "det-3" in match3.detection_ids


def test_sliding_window_deduplication():
    window = SlidingEventWindow(window_seconds=300)
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    entry1 = WindowEntry(
        detection_id="det-dup-1",
        rule_id="sigma-1",
        rule_name="Sigma 1",
        event_id="evt-1",
        timestamp=t0,
        tags=[],
        severity=EventSeverityEnum.MEDIUM,
    )
    accepted1 = window.add_entry(entry1)
    accepted2 = window.add_entry(entry1)

    assert accepted1 is True
    assert accepted2 is False
    assert window.entry_count == 1


def test_sliding_window_expiration():
    window = SlidingEventWindow(window_seconds=60)
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    # Entry 1 at t0
    window.add_entry(
        WindowEntry(
            detection_id="det-1",
            rule_id="sigma-1",
            rule_name="Sigma 1",
            event_id="evt-1",
            timestamp=t0,
            tags=[],
            severity=EventSeverityEnum.LOW,
        )
    )

    # Entry 2 at t0 + 120s (older entry expires because window is 60s)
    window.add_entry(
        WindowEntry(
            detection_id="det-2",
            rule_id="sigma-1",
            rule_name="Sigma 1",
            event_id="evt-2",
            timestamp=t0 + timedelta(seconds=120),
            tags=[],
            severity=EventSeverityEnum.LOW,
        )
    )
    # det-1 expired, only det-2 is retained
    assert window.entry_count == 1


def test_sliding_window_late_arrival_rejection():
    window = SlidingEventWindow(window_seconds=300)
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    window.add_entry(
        WindowEntry(
            detection_id="det-current",
            rule_id="sigma-1",
            rule_name="Sigma 1",
            event_id="evt-current",
            timestamp=t0,
            tags=[],
            severity=EventSeverityEnum.LOW,
        )
    )

    # Entry arrived more than 3600s + window_seconds before max timestamp
    late_time = t0 - timedelta(seconds=4500)
    accepted = window.add_entry(
        WindowEntry(
            detection_id="det-late",
            rule_id="sigma-1",
            rule_name="Sigma 1",
            event_id="evt-late",
            timestamp=late_time,
            tags=[],
            severity=EventSeverityEnum.LOW,
        )
    )
    assert accepted is False
    assert window.entry_count == 1


def test_sliding_window_cooldown():
    rule = create_sample_rule(window_seconds=300, threshold=2, cooldown_seconds=120)
    window = SlidingEventWindow(window_seconds=300)

    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
    window.add_entry(
        WindowEntry(detection_id="det-1", rule_id="sig-1", rule_name="Sig", event_id="evt-1", timestamp=t0, tags=[], severity=EventSeverityEnum.HIGH)
    )
    t1 = t0 + timedelta(seconds=10)
    window.add_entry(
        WindowEntry(detection_id="det-2", rule_id="sig-1", rule_name="Sig", event_id="evt-2", timestamp=t1, tags=[], severity=EventSeverityEnum.HIGH)
    )
    match1 = window.evaluate_rule(rule, "host", "host-cd", t1)
    assert match1 is not None

    # Entry 3 arrives 30s later (within 120s cooldown) -> should be suppressed
    t2 = t0 + timedelta(seconds=40)
    window.add_entry(
        WindowEntry(detection_id="det-3", rule_id="sig-1", rule_name="Sig", event_id="evt-3", timestamp=t2, tags=[], severity=EventSeverityEnum.HIGH)
    )
    match2 = window.evaluate_rule(rule, "host", "host-cd", t2)
    assert match2 is None


def test_sequence_matching_success():
    seq = [
        SequenceStep(step_id="step1", rule_id="sigma-step-1"),
        SequenceStep(step_id="step2", rule_id="sigma-step-2"),
    ]
    rule = create_sample_rule(window_seconds=600, threshold=2, sequence=seq)
    window = SlidingEventWindow(window_seconds=600)

    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    # Step 1 occurs
    window.add_entry(
        WindowEntry(detection_id="det-s1", rule_id="sigma-step-1", rule_name="S1", event_id="evt-s1", timestamp=t0, tags=[], severity=EventSeverityEnum.MEDIUM)
    )
    # Step 2 occurs 100s later
    t1 = t0 + timedelta(seconds=100)
    window.add_entry(
        WindowEntry(detection_id="det-s2", rule_id="sigma-step-2", rule_name="S2", event_id="evt-s2", timestamp=t1, tags=[], severity=EventSeverityEnum.CRITICAL)
    )
    match = window.evaluate_rule(rule, "host", "host-seq", t1)
    assert match is not None
    assert match.detection_ids == ["det-s1", "det-s2"]
    assert match.event_ids == ["evt-s1", "evt-s2"]


def test_sequence_matching_out_of_order_rejection():
    seq = [
        SequenceStep(step_id="step1", rule_id="sigma-step-1"),
        SequenceStep(step_id="step2", rule_id="sigma-step-2"),
    ]
    rule = create_sample_rule(window_seconds=600, threshold=2, sequence=seq)
    window = SlidingEventWindow(window_seconds=600)

    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    # Step 2 occurs BEFORE Step 1
    window.add_entry(
        WindowEntry(detection_id="det-s2", rule_id="sigma-step-2", rule_name="S2", event_id="evt-s2", timestamp=t0, tags=[], severity=EventSeverityEnum.CRITICAL)
    )
    t1 = t0 + timedelta(seconds=50)
    window.add_entry(
        WindowEntry(detection_id="det-s1", rule_id="sigma-step-1", rule_name="S1", event_id="evt-s1", timestamp=t1, tags=[], severity=EventSeverityEnum.MEDIUM)
    )
    match = window.evaluate_rule(rule, "host", "host-seq-ooo", t1)
    # Out of order sequence does not trigger
    assert match is None
