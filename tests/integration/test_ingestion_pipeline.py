"""CyberSentinel AI — Ingestion Pipeline End-to-End Integration Tests"""

import os

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from services.ingestion.pipeline import IngestionPipeline
from services.ingestion.queue import DurableEventQueue, QuarantineManager
from services.normalization.deduplication import DeduplicationCache
from services.normalization.engine import NormalizationEngine
from services.persistence.models import Base, EventMetadata


@pytest.fixture
def test_pipeline_and_db():
    """Create isolated pipeline and database session for integration testing."""
    # Use live PostgreSQL if DATABASE_URL is set, otherwise in-memory SQLite
    db_url = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    engine = create_engine(
        db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    norm = NormalizationEngine()
    dedup = DeduplicationCache(max_capacity=1000, ttl_seconds=60)
    queue = DurableEventQueue(max_buffer_size=1000)
    quarantine = QuarantineManager(max_quarantine_size=100)

    pipe = IngestionPipeline(
        normalizer=norm,
        dedup_cache=dedup,
        queue=queue,
        quarantine=quarantine,
    )

    yield pipe, session

    session.close()
    Base.metadata.drop_all(bind=engine)


def test_pipeline_ingest_valid_event_end_to_end(test_pipeline_and_db):
    """Verify full workflow: Ingest -> Normalization -> Queue -> DB Persistence."""
    pipe, session = test_pipeline_and_db

    record = {
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "network",
        "source_name": "zeek_conn",
        "event_type": "network_connection",
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.2",
        "src_port": 50123,
        "dst_port": 443,
        "severity": "medium",
        "raw_record": {"original": "data"},
    }

    result = pipe.ingest_event(record, connector_id="zeek-01", db_session=session)
    assert result.status == "ingested"
    assert result.persisted is True
    assert result.event_id is not None
    assert pipe.queue.qsize() == 1

    # Verify database persistence
    saved = session.execute(
        select(EventMetadata).where(EventMetadata.id == result.event_id)
    ).scalar_one_or_none()
    assert saved is not None
    assert saved.source_id == "zeek-01"
    assert saved.checksum == result.raw_hash


def test_pipeline_deduplication_suppression(test_pipeline_and_db):
    """Verify duplicate event submission is identified and suppressed."""
    pipe, session = test_pipeline_and_db

    record = {
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "cloud",
        "source_name": "aws_cloudtrail",
        "event_type": "aws:iam:CreateUser",
        "username": "admin",
        "severity": "high",
    }

    res1 = pipe.ingest_event(record, connector_id="aws-01", db_session=session)
    assert res1.status == "ingested"
    assert res1.persisted is True

    # Submitting identical event with same connector ID
    res2 = pipe.ingest_event(record, connector_id="aws-01", db_session=session)
    assert res2.status == "duplicate"
    assert res2.persisted is False

    # Event count in database should remain 1
    events = session.execute(select(EventMetadata)).scalars().all()
    assert len(events) == 1


def test_pipeline_quarantine_and_replay_workflow(test_pipeline_and_db):
    """Verify malformed event is quarantined and can be successfully replayed."""
    pipe, session = test_pipeline_and_db

    # Malformed event missing required source_name and event_type
    bad_record = {"timestamp": "2026-10-16T12:00:00Z", "source_type": "syslog"}
    res = pipe.ingest_event(bad_record, connector_id="syslog-01", db_session=session)
    assert res.status == "quarantined"
    assert res.quarantine_id is not None

    # Verify in quarantine storage
    q_records = pipe.quarantine.get_quarantine_records()
    assert len(q_records) == 1
    assert q_records[0]["quarantine_id"] == res.quarantine_id

    # Simulate repairing the payload in quarantine record
    pipe.quarantine._quarantine[res.quarantine_id].raw_payload.update(
        {"source_name": "sysmon", "event_type": "process_creation"}
    )

    # Replay
    replay_res = pipe.replay_quarantined_event(res.quarantine_id, db_session=session)
    assert replay_res.status == "ingested"
    assert replay_res.persisted is True

    # Quarantined list should now be empty (resolved)
    assert len(pipe.quarantine.get_quarantine_records()) == 0


def test_pipeline_live_postgresql_persistence():
    """Verify end-to-end ingestion and persistence against live PostgreSQL when available."""
    pg_url = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://cybersentinel_dev:local_dev_password_change_in_production@127.0.0.1:5432/cybersentinel_db",
    )
    try:
        pg_engine = create_engine(pg_url, connect_args={"connect_timeout": 2})
        with pg_engine.connect():
            pass
    except Exception:
        pytest.skip("Live PostgreSQL database is not reachable at configured URL")

    PgSession = sessionmaker(bind=pg_engine)
    session = PgSession()

    try:
        pipe = IngestionPipeline()
        record = {
            "timestamp": "2026-10-16T12:30:00Z",
            "source_type": "endpoint",
            "source_name": "edr_sensor",
            "event_type": "process_creation",
            "hostname": "PROD-WS-99",
            "process_name": "cmd.exe",
            "severity": "low",
            "raw_record": {"sensor_id": 42},
        }

        res = pipe.ingest_event(record, connector_id="live-pg-test-01", db_session=session)
        assert res.status == "ingested"
        assert res.persisted is True
        assert res.event_id is not None

        # Verify record exists in real PostgreSQL database
        saved = session.execute(select(EventMetadata).where(EventMetadata.id == res.event_id)).scalar_one_or_none()
        assert saved is not None
        assert saved.source_id == "live-pg-test-01"
        assert saved.classification == "low"

        # Clean up test record from live DB
        session.delete(saved)
        session.commit()
    finally:
        session.close()

