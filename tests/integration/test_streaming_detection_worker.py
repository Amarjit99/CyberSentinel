"""Integration Tests for Streaming Detection Worker with Live Redis Streams
Traceability: CSAI-P3-DETECTION, ADR-0002, ADR-0003, Gate G3
"""

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from schemas.canonical_event import CanonicalEvent
from services.detection.engine import SigmaDetectionEngine
from services.detection.persistence import DetectionPersistenceManager
from services.detection.worker import StreamingDetectionWorker
from services.ingestion.queue import DurableEventQueue
from services.persistence.models import Base, Detection

RULE_POWERSHELL_YAML = """
title: Test Worker Rule - PowerShell Execution
id: c1111111-2222-3333-4444-555555555555
status: stable
logsource:
    category: process_creation
detection:
    sel:
        process_name: powershell.exe
    condition: sel
level: high
"""


@pytest.fixture
def redis_queue():
    """Create a test DurableEventQueue with isolated stream key."""
    redis_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    stream_key = "cybersentinel:test:detection_stream"
    q = DurableEventQueue(stream_key=stream_key, redis_url=redis_url)
    if not q.is_durable:
        pytest.skip("Live Redis broker is not reachable at 127.0.0.1:6379")
    q.clear()
    yield q
    q.clear()


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_worker_processes_stream_and_persists_detections(redis_queue, test_db):
    """Verify worker consumes from Redis Streams, detects threat, and persists to DB."""
    # 1. Setup detection engine with rule
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_POWERSHELL_YAML)

    # 2. Setup persistence manager pointing to test_db
    persistence = DetectionPersistenceManager()

    # 3. Setup worker
    worker = StreamingDetectionWorker(
        queue=redis_queue,
        engine=engine,
        persistence=persistence,
        group_name="test_det_group",
        consumer_name="test_worker_1",
    )

    # 4. Enqueue matching event
    matching_event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc evil",
        severity="medium",
    )
    redis_queue.enqueue(matching_event, require_durability=True)

    # 5. Process batch
    processed_count = worker.process_batch(count=10, db_session=test_db)
    assert processed_count == 1

    # 6. Verify detection was written to test_db
    detection = test_db.execute(
        select(Detection).where(Detection.rule_id == "c1111111-2222-3333-4444-555555555555")
    ).scalar_one_or_none()

    assert detection is not None
    assert detection.severity == "high"


def test_worker_handles_non_matching_event(redis_queue, test_db):
    """Verify worker consumes non-matching event and acknowledges without writing detection."""
    engine = SigmaDetectionEngine()
    engine.load_rule(RULE_POWERSHELL_YAML)

    persistence = DetectionPersistenceManager()
    worker = StreamingDetectionWorker(
        queue=redis_queue,
        engine=engine,
        persistence=persistence,
        group_name="test_det_group_nomatch",
        consumer_name="test_worker_nomatch",
    )

    benign_event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="calc.exe",
        severity="low",
    )
    redis_queue.enqueue(benign_event, require_durability=True)

    processed = worker.process_batch(count=10, db_session=test_db)
    assert processed == 1

    # No detection should be written
    detections = test_db.execute(select(Detection)).scalars().all()
    assert len(detections) == 0
