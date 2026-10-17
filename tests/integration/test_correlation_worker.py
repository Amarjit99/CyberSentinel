"""Integration Tests for Streaming Correlation Worker.
Tests Redis Streams consumer group processing, commit-before-ack semantics,
Sigma detection to correlation pipeline, and incident creation.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.correlation.engine import CorrelationEngine
from services.correlation.models import CorrelationRule
from services.correlation.worker import StreamingCorrelationWorker
from services.detection.engine import SigmaDetectionEngine
from services.detection.persistence import DetectionPersistenceManager
from services.incidents.manager import IncidentManager
from services.ingestion.queue import DurableEventQueue
from services.persistence.models import (
    Base,
    CorrelationWindowState,
    Detection,
    Incident,
    IncidentDetection,
    IncidentEntity,
)


@pytest.fixture(scope="function")
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def queue():
    # Use unique stream key for clean test isolation
    stream_key = f"test_stream_{uuid.uuid4().hex[:8]}"
    q = DurableEventQueue(stream_key=stream_key)
    yield q
    # Cleanup
    if q.is_durable and q.redis_client:
        try:
            q.redis_client.delete(stream_key)
        except Exception:
            pass


def test_streaming_correlation_worker_pipeline(test_db, queue):
    # 1. Setup detection engine with a mock sigma rule
    det_engine = SigmaDetectionEngine()
    rule_yaml = """
title: Suspicious PowerShell Download
id: 550e8400-e29b-41d4-a716-446655440010
status: test
description: Detects powershell web download
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process_name: powershell.exe
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    sigma_rule = det_engine.load_rule(rule_yaml)
    assert sigma_rule is not None

    # 2. Setup correlation engine with a rule that fires on 2 powershell executions on same host
    corr_engine = CorrelationEngine()
    corr_rule = CorrelationRule(
        id=str(uuid.uuid4()),
        name="Repeated PowerShell Invocations",
        description="Two or more powershell executions on the same host within 300s",
        severity=EventSeverityEnum.HIGH,
        group_by=["hostname"],
        window_seconds=300,
        threshold=2,
        cooldown_seconds=0,
        enabled=True,
    )
    corr_engine.load_rule(corr_rule.model_dump())

    # 3. Setup worker
    worker = StreamingCorrelationWorker(
        queue=queue,
        det_engine=det_engine,
        det_persistence=DetectionPersistenceManager(),
        corr_engine=corr_engine,
        inc_mgr=IncidentManager(),
        group_name=f"grp_{uuid.uuid4().hex[:8]}",
        consumer_name="test-worker",
    )

    # 4. Enqueue 2 events on same host "victim-srv"
    t0 = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
    evt1 = CanonicalEvent(
        event_id=uuid.uuid4(),
        timestamp=t0,
        source_type="windows",
        source_name="Microsoft-Windows-Sysmon",
        event_type="process_creation",
        severity=EventSeverityEnum.MEDIUM,
        hostname="victim-srv",
        username="admin",
        process_name="powershell.exe",
    )
    evt2 = CanonicalEvent(
        event_id=uuid.uuid4(),
        timestamp=t0,
        source_type="windows",
        source_name="Microsoft-Windows-Sysmon",
        event_type="process_creation",
        severity=EventSeverityEnum.MEDIUM,
        hostname="victim-srv",
        username="admin",
        process_name="powershell.exe",
    )

    queue.enqueue(evt1)
    queue.enqueue(evt2)

    # 5. Worker processes batch
    processed = worker.process_batch(count=10, db_session=test_db)
    assert processed == 2

    # 6. Verify Detection records created in DB
    detections = test_db.execute(select(Detection)).scalars().all()
    assert len(detections) >= 1

    # 7. Verify Incident created from correlation match
    incidents = test_db.execute(select(Incident)).scalars().all()
    assert len(incidents) == 1
    inc = incidents[0]
    assert "Repeated PowerShell Invocations" in inc.title
    assert inc.severity == "high"
    assert inc.status == "NEW"

    # Verify entities and detections linked to incident
    entities = test_db.execute(
        select(IncidentEntity).where(IncidentEntity.incident_id == inc.id)
    ).scalars().all()
    assert any(e.entity_key == "victim-srv" for e in entities)

    links = test_db.execute(
        select(IncidentDetection).where(IncidentDetection.incident_id == inc.id)
    ).scalars().all()
    assert len(links) >= 1


def test_correlation_window_state_survives_engine_restart(test_db):
    engine = CorrelationEngine()
    rule = CorrelationRule(
        id=str(uuid.uuid4()),
        name="Restart Recovery",
        description="state",
        group_by=["hostname"],
        threshold=2,
    )
    engine.load_rule(rule.model_dump())
    event = CanonicalEvent(
        event_id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="test",
        event_type="process_creation",
        severity=EventSeverityEnum.MEDIUM,
        hostname="restart-host",
        process_name="powershell.exe",
    )
    from services.detection import DetectionMatch

    detection = DetectionMatch(
        rule_id="rule-1",
        rule_name="rule",
        severity=EventSeverityEnum.HIGH,
        matched_event_ids=[str(event.event_id)],
        mitre_attack_ids=[],
    )
    engine.process_detection(detection, event)
    state = engine.export_state()
    for item in state:
        test_db.add(
            CorrelationWindowState(
                key=item["key"],
                rule_id=item["rule_id"],
                entity_type=item["entity_type"],
                entity_key=item["entity_key"],
                state_json=item["state"],
            )
        )
    test_db.commit()

    restarted = CorrelationEngine()
    restarted.load_rule(rule.model_dump())
    restarted.import_state(
        [
            {
                "rule_id": row.rule_id,
                "entity_type": row.entity_type,
                "entity_key": row.entity_key,
                "state": row.state_json,
            }
            for row in test_db.query(CorrelationWindowState).all()
        ]
    )
    assert len(restarted.export_state()) == 1
    assert restarted.export_state()[0]["state"]["entries"][0]["event_id"] == str(event.event_id)
