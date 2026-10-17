"""CyberSentinel AI — Redis Streams Live Durability & Consumer Groups Integration Tests
Traceability: ADR-0002, ADR-0003, Requirement 2.C
"""

import os
from datetime import datetime, timezone

import pytest

from schemas.canonical_event import CanonicalEvent
from services.ingestion.queue import BrokerUnavailableError, DurableEventQueue


@pytest.fixture
def redis_queue():
    """Create a DurableEventQueue connected to the local Redis instance."""
    redis_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    q = DurableEventQueue(stream_key="cybersentinel:test:stream", redis_url=redis_url)
    if not q.is_durable:
        pytest.skip("Live Redis broker is not reachable at 127.0.0.1:6379")
    q.clear()
    yield q
    q.clear()


def test_redis_connection_and_durability_mode(redis_queue):
    """Verify DurableEventQueue detects live Redis and reports durable mode."""
    assert redis_queue.is_durable is True
    assert redis_queue.storage_mode == "redis_streams"


def test_redis_stream_publish_and_size(redis_queue):
    """Verify events are published to Redis Streams (XADD) and tracked via XLEN."""
    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="windows",
        source_name="sysmon",
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -NoProfile",
        severity="medium",
    )

    enqueued = redis_queue.enqueue(event, require_durability=True)
    assert enqueued is True
    assert redis_queue.qsize() == 1


def test_redis_consumer_groups_lifecycle(redis_queue):
    """Verify consumer groups (XGROUP, XREADGROUP, XACK) for downstream detection workers."""
    group_name = "test_detection_workers"
    consumer_name = "worker_node_01"

    # 1. Create consumer group
    group_created = redis_queue.create_consumer_group(group_name=group_name)
    assert group_created is True

    # 2. Publish two events
    for i in range(2):
        ev = CanonicalEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network",
            source_name="zeek",
            event_type="dns_query",
            domain=f"test{i}.internal",
        )
        redis_queue.enqueue(ev, require_durability=True)

    # 3. Read via consumer group
    entries = redis_queue.read_consumer_group(group_name=group_name, consumer_name=consumer_name, count=10)
    assert len(entries) == 2
    assert "_stream_entry_id" in entries[0]
    entry_id_1 = entries[0]["_stream_entry_id"]
    entry_id_2 = entries[1]["_stream_entry_id"]

    # 4. Check pending messages
    pending = redis_queue.get_pending_count(group_name=group_name)
    assert pending == 2

    # 5. Acknowledge one message
    acked = redis_queue.ack_consumer_group(group_name, entry_id_1)
    assert acked == 1

    # Pending count should now be 1
    assert redis_queue.get_pending_count(group_name=group_name) == 1

    # Acknowledge second message
    acked_2 = redis_queue.ack_consumer_group(group_name, entry_id_2)
    assert acked_2 == 1
    assert redis_queue.get_pending_count(group_name=group_name) == 0


def test_require_durability_fails_safely_when_broker_unavailable():
    """Verify require_durability=True raises BrokerUnavailableError rather than silent volatile fallback."""
    # Connect to invalid port
    bad_queue = DurableEventQueue(
        stream_key="cybersentinel:bad:stream",
        redis_url="redis://127.0.0.1:59999/0",
    )
    assert bad_queue.is_durable is False
    assert bad_queue.storage_mode == "in_memory_volatile_fallback"

    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="linux",
        source_name="auditd",
        event_type="user_login",
    )

    with pytest.raises(BrokerUnavailableError) as exc_info:
        bad_queue.enqueue(event, require_durability=True)

    assert "Durable delivery required" in str(exc_info.value)
