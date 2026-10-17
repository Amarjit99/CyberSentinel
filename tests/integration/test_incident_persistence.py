"""Integration Tests for Incident Persistence, Correlation Updates, and Timeline.
Tests incident creation from CorrelationMatch, deduplication of open incidents,
detection linking, entity association, note addition, and timeline generation.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from schemas.enums import EventSeverityEnum, IncidentStateEnum
from services.correlation.models import CorrelationMatch
from services.incidents.manager import IncidentManager
from services.persistence.models import (
    Base,
    IncidentDetection,
    IncidentEntity,
)


@pytest.fixture(scope="function")
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_create_and_deduplicate_incident(db_session):
    manager = IncidentManager()
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    # First match
    match1 = CorrelationMatch(
        match_id="match-01",
        rule_id="550e8400-e29b-41d4-a716-446655440001",
        rule_name="Multiple Failed Authentications",
        severity=EventSeverityEnum.HIGH,
        entity_type="user",
        entity_key="target_user",
        detection_ids=["det-01", "det-02"],
        event_ids=["evt-01", "evt-02"],
        window_start=t0,
        window_end=t0 + timedelta(seconds=120),
        title="Multiple Failed Authentications on user 'target_user'",
        description="Multiple failed authentications observed.",
    )

    incident1 = manager.create_or_update_from_correlation(match1, db_session)
    assert incident1 is not None
    assert incident1.severity == "high"
    assert incident1.status == IncidentStateEnum.NEW.value
    assert incident1.version == 1

    # Verify detection and entity links
    det_links = db_session.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == incident1.id)
    ).scalars().all()
    assert len(det_links) == 2

    ent_links = db_session.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == incident1.id)
    ).scalars().all()
    assert len(ent_links) == 1
    assert ent_links[0].entity_key == "target_user"

    # Second match on SAME open incident with a new detection and higher severity
    match2 = CorrelationMatch(
        match_id="match-02",
        rule_id="550e8400-e29b-41d4-a716-446655440002",
        rule_name="Privilege Escalation Detected",
        severity=EventSeverityEnum.CRITICAL,
        entity_type="user",
        entity_key="target_user",
        detection_ids=["det-03"],
        event_ids=["evt-03"],
        window_start=t0 + timedelta(seconds=130),
        window_end=t0 + timedelta(seconds=180),
        title="Privilege Escalation on user 'target_user'",
        description="Privilege escalation follow-up observed.",
    )

    incident2 = manager.create_or_update_from_correlation(match2, db_session)
    # Must update the existing incident, not create a new one
    assert incident2.id == incident1.id
    assert incident2.severity == "critical"
    last_seen_utc = incident2.last_seen if incident2.last_seen.tzinfo else incident2.last_seen.replace(tzinfo=timezone.utc)
    assert last_seen_utc == match2.window_end

    # Verify det-03 was added
    updated_det_links = db_session.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == incident1.id)
    ).scalars().all()
    assert len(updated_det_links) == 3


def test_add_note_with_redaction_and_get_timeline(db_session):
    manager = IncidentManager()
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

    match = CorrelationMatch(
        match_id="match-timeline-01",
        rule_id="550e8400-e29b-41d4-a716-446655440003",
        rule_name="Suspicious Execution",
        severity=EventSeverityEnum.HIGH,
        entity_type="host",
        entity_key="victim-workstation",
        detection_ids=["det-timeline-1"],
        event_ids=["evt-timeline-1"],
        window_start=t0,
        window_end=t0 + timedelta(seconds=60),
        title="Suspicious Execution on victim-workstation",
        description="Suspicious execution pattern detected.",
    )

    incident = manager.create_or_update_from_correlation(match, db_session)

    # Add analyst note with secret credentials
    note = manager.add_note(
        session=db_session,
        incident_id=incident.id,
        author_id="analyst_alice",
        note_text="Investigated host. Found token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 and password=SuperSecretPassword123!",
    )

    assert note is not None
    # Verify sensitive tokens and passwords are redacted
    assert "SuperSecretPassword123!" not in note.note
    assert "[REDACTED_SECRET]" in note.note or "[REDACTED_TOKEN]" in note.note or "[REDACTED" in note.note

    # Get chronological timeline
    timeline = manager.get_incident_timeline(db_session, incident.id)
    assert len(timeline) >= 2
    event_types = [item["type"] for item in timeline]
    assert "incident_created" in event_types
    assert "analyst_note" in event_types
