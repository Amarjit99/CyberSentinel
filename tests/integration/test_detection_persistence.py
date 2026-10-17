"""Integration Tests for Detection Persistence & Idempotency
Traceability: CSAI-P3-DETECTION, ADR-0001, ADR-0003, Gate G3
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.detection import DetectionMatch
from services.detection.persistence import DetectionPersistenceManager
from services.persistence.models import Base, Detection, DetectionEvent

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_detection_persistence_creates_records(test_db):
    """Verify persisting a DetectionMatch creates a Detection and DetectionEvent record."""
    manager = DetectionPersistenceManager()
    now = datetime.now(timezone.utc)

    event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc invoke-mimikatz",
        severity="medium",
    )

    match = DetectionMatch(
        rule_id="5f1186a4-e73c-4297-baab-a2991557cc37",
        rule_name="Suspicious PowerShell Download Cradle",
        severity=EventSeverityEnum.HIGH,
        matched_event_ids=[str(event.event_id)],
        mitre_attack_ids=["T1059.001"],
    )

    det = manager.persist_match(match, event, db_session=test_db)
    assert det is not None

    # Verify Detection record
    detection = test_db.execute(
        select(Detection).where(Detection.rule_id == match.rule_id)
    ).scalar_one_or_none()

    assert detection is not None
    assert detection.rule_id == "5f1186a4-e73c-4297-baab-a2991557cc37"
    assert detection.severity == "high"
    assert detection.status == "open"

    # Verify DetectionEvent junction record
    det_event = test_db.execute(
        select(DetectionEvent).where(DetectionEvent.detection_id == detection.id)
    ).scalar_one_or_none()

    assert det_event is not None
    assert str(det_event.event_id) == str(event.event_id)
    assert det_event.relation_type == "matched"


def test_detection_persistence_is_strictly_idempotent(test_db):
    """Verify replaying the same DetectionMatch updates last_seen without duplicating records."""
    manager = DetectionPersistenceManager()
    now = datetime.now(timezone.utc)

    event = CanonicalEvent(
        timestamp=now,
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        severity="low",
    )

    match = DetectionMatch(
        rule_id="11111111-2222-3333-4444-555555555555",
        rule_name="Idempotency Test Rule",
        severity=EventSeverityEnum.HIGH,
        matched_event_ids=[str(event.event_id)],
        mitre_attack_ids=["T1033"],
    )

    # First write
    d1 = manager.persist_match(match, event, db_session=test_db)
    assert d1 is not None

    # Second write with same event_id and rule_id
    d2 = manager.persist_match(match, event, db_session=test_db)
    assert d2 is not None

    # Total detections count in DB must still be 1
    total_detections = test_db.execute(select(Detection)).scalars().all()
    assert len(total_detections) == 1

    total_det_events = test_db.execute(select(DetectionEvent)).scalars().all()
    assert len(total_det_events) == 1
