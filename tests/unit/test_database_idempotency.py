"""CyberSentinel AI — Database-Level Idempotency & Duplicate Suppression Tests
Traceability: Requirement 2.D, ADR-0003
"""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from services.ingestion.pipeline import IngestionPipeline
from services.ingestion.queue import DurableEventQueue, QuarantineManager
from services.normalization.deduplication import DeduplicationCache
from services.normalization.engine import NormalizationEngine
from services.persistence.models import Base, EventMetadata


@pytest.fixture
def isolated_db_and_pipeline():
    """Create in-memory database session and pipeline with flushable cache."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    norm = NormalizationEngine()
    dedup = DeduplicationCache(max_capacity=100, ttl_seconds=60)
    queue = DurableEventQueue(max_buffer_size=100)
    quarantine = QuarantineManager(max_quarantine_size=10)

    pipe = IngestionPipeline(
        normalizer=norm,
        dedup_cache=dedup,
        queue=queue,
        quarantine=quarantine,
    )

    yield pipe, session, dedup

    session.close()
    Base.metadata.drop_all(bind=engine)


def test_database_level_idempotency_after_cache_flush(isolated_db_and_pipeline):
    """Verify that if in-memory deduplication cache is evicted/rebooted, database prevents duplicate records."""
    pipe, session, dedup = isolated_db_and_pipeline

    record = {
        "event_id": "11111111-2222-3333-4444-555555555555",
        "timestamp": "2026-10-16T12:00:00Z",
        "source_type": "windows",
        "source_name": "sysmon",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c dir",
    }

    # 1. First ingestion (clean insert)
    res1 = pipe.ingest_event(record, connector_id="agent-01", db_session=session)
    assert res1.status == "ingested"
    assert res1.persisted is True

    # 2. Simulate complete cache flush / process restart
    dedup.clear()
    assert len(dedup._cache) == 0

    # 3. Second ingestion of identical record after cache eviction
    res2 = pipe.ingest_event(record, connector_id="agent-01", db_session=session)
    assert res2.status == "duplicate"
    assert res2.persisted is False
    assert "primary key uniqueness" in (res2.error or "")

    # 4. Verify exactly 1 record exists in the database
    db_events = session.execute(select(EventMetadata)).scalars().all()
    assert len(db_events) == 1
    assert db_events[0].id == "11111111-2222-3333-4444-555555555555"
