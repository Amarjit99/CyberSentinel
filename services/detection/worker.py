"""CyberSentinel AI — Streaming Detection Worker
Consumes normalized events from Redis Streams consumer groups, evaluates Sigma rules,
and persists detections to PostgreSQL.
"""

import logging
import time
from typing import Callable, List, Optional

from sqlalchemy.orm import Session

from packages.observability.metrics import metrics
from schemas.canonical_event import CanonicalEvent
from services.detection.engine import SigmaDetectionEngine, detection_engine
from services.detection.persistence import DetectionPersistenceManager, persistence_manager
from services.ingestion.queue import DurableEventQueue, durable_queue
from services.persistence.database import SessionLocal

logger = logging.getLogger("cybersentinel.detection.worker")


class StreamingDetectionWorker:
    """Streaming detection worker processing CanonicalEvents from Redis Streams."""

    def __init__(
        self,
        queue: Optional[DurableEventQueue] = None,
        engine: Optional[SigmaDetectionEngine] = None,
        persistence: Optional[DetectionPersistenceManager] = None,
        group_name: str = "cybersentinel_detection_workers",
        consumer_name: str = "worker-01",
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        self.queue = queue or durable_queue
        self.engine = engine or detection_engine
        self.persistence = persistence or persistence_manager
        self.group_name = group_name
        self.consumer_name = consumer_name
        self.session_factory = session_factory or SessionLocal
        self._running = False

        # Ensure Redis consumer group is initialized if durable
        if self.queue.is_durable:
            self.queue.create_consumer_group(self.group_name)

    def process_batch(self, count: int = 50, db_session: Optional[Session] = None) -> int:
        """Fetch, evaluate, persist, and acknowledge a batch of events."""
        # 1. Fetch entries from Redis Consumer Group (or in-memory fallback)
        if self.queue.is_durable:
            entries = self.queue.read_consumer_group(
                group_name=self.group_name,
                consumer_name=self.consumer_name,
                count=count,
            )
        else:
            entries = self.queue.dequeue_batch(batch_size=count)

        if not entries:
            return 0

        owns_session = db_session is None
        session = db_session or self.session_factory()
        processed_count = 0
        ack_entry_ids: List[str] = []

        try:
            for item in entries:
                stream_entry_id = item.get("_stream_entry_id")
                clean_item = {k: v for k, v in item.items() if not k.startswith("_")}

                try:
                    # Validate canonical event
                    canonical_event = CanonicalEvent.model_validate(clean_item)

                    # Evaluate against active Sigma detection rules
                    matches = self.engine.evaluate(canonical_event)

                    # Persist detections if matches occurred
                    if matches:
                        self.persistence.persist_matches(matches, canonical_event, session)

                    processed_count += 1
                    if stream_entry_id:
                        ack_entry_ids.append(stream_entry_id)

                except Exception as ev_err:
                    metrics.inc_evaluation_error()
                    logger.error(
                        "Error processing event '%s' in detection worker: %s",
                        clean_item.get("event_id"),
                        ev_err,
                    )
                    # Note: We do NOT ack failed entries to allow recovery/DLQ processing

            # 2. Acknowledge successfully processed and persisted entries in Redis
            if ack_entry_ids and self.queue.is_durable:
                self.queue.ack_consumer_group(self.group_name, *ack_entry_ids)

            return processed_count

        finally:
            if owns_session:
                session.close()

    def run_worker_loop(self, poll_interval_sec: float = 0.1, max_batches: Optional[int] = None) -> None:
        """Run continuous stream worker loop with graceful stop support."""
        self._running = True
        batch_counter = 0

        logger.info("Detection worker '%s' started on group '%s'", self.consumer_name, self.group_name)

        while self._running:
            processed = self.process_batch()
            if processed == 0:
                time.sleep(poll_interval_sec)
            batch_counter += 1
            if max_batches is not None and batch_counter >= max_batches:
                break

        logger.info("Detection worker '%s' stopped cleanly", self.consumer_name)

    def stop(self) -> None:
        """Signal worker to stop gracefully."""
        self._running = False
