"""CyberSentinel AI — Quarantine, DLQ and Replay Unit Tests"""

from datetime import datetime, timezone

from schemas.canonical_event import CanonicalEvent
from services.ingestion.queue import DurableEventQueue, QuarantineManager


def test_durable_event_queue_in_memory():
    """Verify in-memory durable queue enqueue, batch dequeue, and qsize."""
    q = DurableEventQueue(max_buffer_size=5)
    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="network",
        source_name="zeek",
        event_type="conn",
    )
    assert q.enqueue(event) is True
    assert q.qsize() == 1

    batch = q.dequeue_batch(batch_size=10)
    assert len(batch) == 1
    assert batch[0]["source_type"] == "network"
    assert q.qsize() == 0


def test_quarantine_and_dlq_loop_protection():
    """Verify quarantine stores invalid events and moves to DLQ when replay limit is reached."""
    qm = QuarantineManager(max_quarantine_size=10, max_replay_attempts=2)

    rec = qm.quarantine_event(
        source_type="syslog",
        error_reason="Invalid syslog header format",
        raw_payload={"raw": "corrupt data"},
        raw_hash="hash123",
    )
    assert rec.quarantine_id is not None
    assert len(qm.get_quarantine_records()) == 1

    # First replay attempt: count=1
    r1 = qm.replay_quarantined(rec.quarantine_id)
    assert r1 is not None
    assert r1.replay_count == 1

    # Second replay attempt: count=2
    r2 = qm.replay_quarantined(rec.quarantine_id)
    assert r2 is not None
    assert r2.replay_count == 2

    # Third replay attempt: exceeds max_replay_attempts=2, must move to DLQ
    r3 = qm.replay_quarantined(rec.quarantine_id)
    assert r3 is None  # Exceeded, promoted to DLQ

    # Verify moved from quarantine to dead letter queue
    assert len(qm.get_quarantine_records()) == 0
    assert len(qm.get_dlq_records()) == 1
    dlq_item = qm.get_dlq_records()[0]
    assert dlq_item["quarantine_id"] == rec.quarantine_id
