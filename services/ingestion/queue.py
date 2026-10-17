"""CyberSentinel AI — Durable Delivery, Quarantine, DLQ & Replay Engine

Implements stream buffering via Redis Streams with thread-safe in-memory fallback,
structured quarantine for malformed events, dead-letter storage, and controlled replay.
"""

import json
import os
import threading
from collections import deque
from typing import Any, Dict, List, Optional
from uuid import uuid4

from packages.common import sanitize_raw_payload, utc_now
from packages.observability import metrics
from schemas.canonical_event import CanonicalEvent


class QuarantineRecord:
    """Record of an event rejected during ingestion/normalization."""

    def __init__(
        self,
        quarantine_id: str,
        timestamp: str,
        source_type: str,
        error_reason: str,
        raw_payload: Dict[str, Any],
        raw_hash: str,
        replay_count: int = 0,
    ) -> None:
        self.quarantine_id = quarantine_id
        self.timestamp = timestamp
        self.source_type = source_type
        self.error_reason = error_reason
        self.raw_payload = raw_payload
        self.raw_hash = raw_hash
        self.replay_count = replay_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "quarantine_id": self.quarantine_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "error_reason": self.error_reason,
            "raw_payload": self.raw_payload,
            "raw_hash": self.raw_hash,
            "replay_count": self.replay_count,
        }


class BrokerUnavailableError(Exception):
    """Raised when durable ingestion is required but message broker is unavailable."""

    pass


class DurableEventQueue:
    """Stream buffering queue connecting to Redis Streams with observable in-memory fallback."""

    def __init__(
        self,
        stream_key: str = "cybersentinel:events:stream",
        max_buffer_size: int = 20000,
        redis_url: Optional[str] = None,
    ) -> None:
        self.stream_key = stream_key
        self.max_buffer_size = max_buffer_size
        self._memory_queue: deque[Dict[str, Any]] = deque(maxlen=max_buffer_size)
        self._lock = threading.Lock()
        self._redis_client = None
        self._use_redis = False

        # Attempt Redis connection if configured
        redis_target = redis_url or os.getenv("REDIS_URL")
        if redis_target:
            try:
                import redis

                client = redis.from_url(redis_target, socket_timeout=1.0)
                client.ping()
                self._redis_client = client
                self._use_redis = True
            except Exception:
                self._use_redis = False

    @property
    def is_durable(self) -> bool:
        """True only if backed by an active, verified Redis Streams broker."""
        return self._use_redis and self._redis_client is not None

    @property
    def storage_mode(self) -> str:
        """Observable description of active queue storage tier."""
        return "redis_streams" if self.is_durable else "in_memory_volatile_fallback"

    def check_health(self) -> Dict[str, Any]:
        """Bounded health probe for durable queue dependency without leaking connection strings."""
        if self._redis_client is not None and self._use_redis:
            try:
                self._redis_client.ping()
                return {
                    "status": "connected",
                    "storage_mode": "redis_streams",
                    "is_durable": True,
                }
            except Exception:
                return {
                    "status": "degraded",
                    "storage_mode": "in_memory_volatile_fallback",
                    "is_durable": False,
                }
        return {
            "status": "active",
            "storage_mode": "in_memory_volatile_fallback",
            "is_durable": False,
        }


    def enqueue(self, event: CanonicalEvent, require_durability: bool = False) -> bool:
        """Publish canonical event to Redis Stream or in-memory queue.

        If require_durability=True, raises BrokerUnavailableError if Redis broker is inactive.
        """
        event_dict = event.model_dump(mode="json")
        payload_str = json.dumps(event_dict)

        if self.is_durable and self._redis_client:
            try:
                self._redis_client.xadd(
                    self.stream_key, {"payload": payload_str}, maxlen=self.max_buffer_size
                )
                return True
            except Exception as ex:
                if require_durability:
                    raise BrokerUnavailableError(f"Failed to publish to Redis stream: {ex}") from ex
                # Fall back to in-memory queue on Redis runtime failure
                self._use_redis = False

        if require_durability:
            raise BrokerUnavailableError(
                "Durable delivery required, but active Redis Streams broker is unavailable."
            )

        with self._lock:
            if len(self._memory_queue) >= self.max_buffer_size:
                return False  # Backpressure overflow
            self._memory_queue.append(event_dict)
            return True

    def create_consumer_group(
        self, group_name: str = "cybersentinel_detection_workers", start_id: str = "0"
    ) -> bool:
        """Initialize a Redis consumer group for downstream detection workers."""
        if not self.is_durable or not self._redis_client:
            return False
        try:
            self._redis_client.xgroup_create(
                self.stream_key, group_name, id=start_id, mkstream=True
            )
            return True
        except Exception as ex:
            # Group may already exist (BUSYGROUP)
            if "BUSYGROUP" in str(ex):
                return True
            return False

    def read_consumer_group(
        self,
        group_name: str,
        consumer_name: str,
        count: int = 100,
        block_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch unacknowledged messages via Redis Consumer Groups for downstream workers."""
        if not self.is_durable or not self._redis_client:
            return self.dequeue_batch(batch_size=count)

        try:
            entries: Any = self._redis_client.xreadgroup(
                group_name,
                consumer_name,
                {self.stream_key: ">"},
                count=count,
                block=block_ms,
            )
            results = []
            if isinstance(entries, (list, tuple)):
                for stream_item in entries:
                    stream_entries = (
                        stream_item[1]
                        if isinstance(stream_item, (list, tuple)) and len(stream_item) > 1
                        else []
                    )
                    if isinstance(stream_entries, (list, tuple)):
                        for entry in stream_entries:
                            entry_id = (
                                entry[0].decode()
                                if isinstance(entry[0], bytes)
                                else str(entry[0])
                            )
                            fields = entry[1] if len(entry) > 1 and isinstance(entry[1], dict) else {}
                            raw_payload = fields.get(b"payload") or fields.get("payload")
                            if raw_payload:
                                if isinstance(raw_payload, bytes):
                                    raw_payload = raw_payload.decode("utf-8")
                                parsed = json.loads(raw_payload)
                                parsed["_stream_entry_id"] = entry_id
                                results.append(parsed)
            return results
        except Exception:
            return []

    def ack_consumer_group(self, group_name: str, *entry_ids: str) -> int:
        """Acknowledge processed entries in consumer group."""
        if not self.is_durable or not self._redis_client or not entry_ids:
            return 0
        try:
            return int(self._redis_client.xack(self.stream_key, group_name, *entry_ids))
        except Exception:
            return 0

    def get_pending_count(self, group_name: str) -> int:
        """Retrieve count of pending unacknowledged messages in consumer group."""
        if not self.is_durable or not self._redis_client:
            return 0
        try:
            pending_info = self._redis_client.xpending(self.stream_key, group_name)
            if isinstance(pending_info, dict):
                return int(pending_info.get("pending", 0))
            return 0
        except Exception:
            return 0

    def dequeue_batch(self, batch_size: int = 100) -> List[Dict[str, Any]]:
        """Fetch up to batch_size items from stream or memory queue."""
        if self._use_redis and self._redis_client:
            try:
                items: Any = self._redis_client.xread({self.stream_key: "0-0"}, count=batch_size)
                results = []
                for item in items:
                    stream_entries = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else []
                    for entry in stream_entries:
                        entry_id = entry[0]
                        fields = entry[1] if isinstance(entry, (list, tuple)) and len(entry) > 1 else {}
                        if isinstance(fields, dict):
                            payload = fields.get(b"payload") or fields.get("payload")
                            if payload:
                                if isinstance(payload, bytes):
                                    payload = payload.decode("utf-8")
                                results.append(json.loads(payload))
                            self._redis_client.xdel(self.stream_key, entry_id)
                return results
            except Exception:
                pass

        with self._lock:
            count = min(len(self._memory_queue), batch_size)
            batch = [self._memory_queue.popleft() for _ in range(count)]
            return batch

    def qsize(self) -> int:
        if self._use_redis and self._redis_client:
            try:
                return int(self._redis_client.xlen(self.stream_key))
            except Exception:
                pass
        with self._lock:
            return len(self._memory_queue)

    def clear(self) -> None:
        if self._use_redis and self._redis_client:
            try:
                self._redis_client.delete(self.stream_key)
            except Exception:
                pass
        with self._lock:
            self._memory_queue.clear()


class QuarantineManager:
    """Manages rejected events and dead-letter records with controlled replay."""

    def __init__(self, max_quarantine_size: int = 5000, max_replay_attempts: int = 3) -> None:
        self.max_quarantine_size = max_quarantine_size
        self.max_replay_attempts = max_replay_attempts
        self._quarantine: Dict[str, QuarantineRecord] = {}
        self._dead_letter: Dict[str, QuarantineRecord] = {}
        self._lock = threading.Lock()

    def quarantine_event(
        self,
        source_type: str,
        error_reason: str,
        raw_payload: Dict[str, Any],
        raw_hash: str,
    ) -> QuarantineRecord:
        """Store invalid event into quarantine."""
        q_id = str(uuid4())
        sanitized_payload = sanitize_raw_payload(raw_payload) if isinstance(raw_payload, dict) else raw_payload
        rec = QuarantineRecord(
            quarantine_id=q_id,
            timestamp=utc_now().isoformat(),
            source_type=source_type,
            error_reason=error_reason,
            raw_payload=sanitized_payload,
            raw_hash=raw_hash,
            replay_count=0,
        )
        with self._lock:
            if len(self._quarantine) >= self.max_quarantine_size:
                # Evict oldest entry
                oldest_key = next(iter(self._quarantine))
                del self._quarantine[oldest_key]
            self._quarantine[q_id] = rec

        metrics.inc_quarantined()
        return rec

    def send_to_dlq(self, record: QuarantineRecord, terminal_reason: str) -> None:
        """Move permanently unreplayable or retry-exhausted record to dead-letter queue."""
        record.error_reason = terminal_reason
        with self._lock:
            self._quarantine.pop(record.quarantine_id, None)
            self._dead_letter[record.quarantine_id] = record
        metrics.inc_dlq()

    def get_quarantine_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in list(self._quarantine.values())[:limit]]

    def get_dlq_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in list(self._dead_letter.values())[:limit]]

    def replay_quarantined(self, quarantine_id: str) -> Optional[QuarantineRecord]:
        """Fetch and increment replay count on a quarantined record.

        Protects against infinite replay loops by moving to DLQ if max attempts exceeded.
        """
        with self._lock:
            rec = self._quarantine.get(quarantine_id)
            if not rec:
                return None

            rec.replay_count += 1
            if rec.replay_count > self.max_replay_attempts:
                # Exceeded max replays, move to DLQ
                self._quarantine.pop(quarantine_id, None)
                self._dead_letter[quarantine_id] = rec
                metrics.inc_dlq()
                return None

            metrics.inc_replayed()
            return rec

    def remove_quarantined(self, quarantine_id: str) -> bool:
        """Remove record from quarantine once successfully resolved or replayed."""
        with self._lock:
            return self._quarantine.pop(quarantine_id, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._quarantine.clear()
            self._dead_letter.clear()


# Global queue and quarantine singletons
durable_queue = DurableEventQueue()
quarantine_manager = QuarantineManager()
