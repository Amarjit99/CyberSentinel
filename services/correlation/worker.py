"""CyberSentinel AI — Streaming Correlation Worker
Consumes normalized events from Redis Streams, coordinates detection and stateful correlation,
and persists security incidents in PostgreSQL.
Governing Decisions: ADR-0001, ADR-0002, ADR-0003, CSAI-P4-CORRELATION
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Callable, List, Optional

from sqlalchemy.orm import Session

from packages.observability.metrics import metrics
from schemas.canonical_event import CanonicalEvent
from services.correlation.engine import CorrelationEngine, correlation_engine
from services.detection.engine import SigmaDetectionEngine, detection_engine
from services.detection.persistence import DetectionPersistenceManager, persistence_manager
from services.ingestion.queue import DurableEventQueue, durable_queue
from services.persistence.database import SessionLocal
from services.persistence.models import CorrelationWindowState

if TYPE_CHECKING:
    from services.incidents.manager import IncidentManager

logger = logging.getLogger("cybersentinel.correlation.worker")


class StreamingCorrelationWorker:
    """Consumes normalized events, evaluates Sigma detections, feeds temporal windows, and manages incidents."""

    def __init__(
        self,
        queue: Optional[DurableEventQueue] = None,
        det_engine: Optional[SigmaDetectionEngine] = None,
        det_persistence: Optional[DetectionPersistenceManager] = None,
        corr_engine: Optional[CorrelationEngine] = None,
        inc_mgr: Optional[IncidentManager] = None,
        group_name: str = "cybersentinel_correlation_workers",
        consumer_name: str = "corr-worker-01",
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        self.queue = queue or durable_queue
        self.det_engine = det_engine or detection_engine
        self.det_persistence = det_persistence or persistence_manager
        self.corr_engine = corr_engine or correlation_engine
        if inc_mgr is not None:
            self.inc_mgr = inc_mgr
        else:
            from services.incidents.manager import incident_manager

            self.inc_mgr = incident_manager
        self.group_name = group_name
        self.consumer_name = consumer_name
        self.session_factory = session_factory or SessionLocal
        self._running = False

        if self.queue.is_durable:
            self.queue.create_consumer_group(self.group_name)
        self._state_loaded = False

    def _load_state(self, session: Session) -> None:
        if self._state_loaded:
            return
        rows = session.query(CorrelationWindowState).all()
        self.corr_engine.import_state(
            [{"rule_id": row.rule_id, "entity_type": row.entity_type,
              "entity_key": row.entity_key, "state": row.state_json} for row in rows]
        )
        self._state_loaded = True

    def _persist_state(self, session: Session) -> None:
        for item in self.corr_engine.export_state():
            row = session.get(CorrelationWindowState, item["key"])
            if row is None:
                row = CorrelationWindowState(
                    key=item["key"],
                    rule_id=item["rule_id"],
                    entity_type=item["entity_type"],
                    entity_key=item["entity_key"],
                )
                session.add(row)
            row.state_json = item["state"]
        session.commit()

    def process_batch(self, count: int = 50, db_session: Optional[Session] = None) -> int:
        """Fetch a batch of normalized events, evaluate detections and correlations, and persist incidents."""
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
            self._load_state(session)
            for item in entries:
                stream_entry_id = item.get("_stream_entry_id")
                clean_item = {k: v for k, v in item.items() if not k.startswith("_")}

                try:
                    # 1. Parse and validate CanonicalEvent
                    canonical_event = CanonicalEvent.model_validate(clean_item)

                    # 2. Evaluate against Sigma detection rules
                    detection_matches = self.det_engine.evaluate(canonical_event)

                    if detection_matches:
                        # 3. Persist individual Sigma detections idempotently
                        self.det_persistence.persist_matches(detection_matches, canonical_event, session)

                        # 4. Feed each detection into the temporal correlation engine
                        for det_match in detection_matches:
                            corr_matches = self.corr_engine.process_detection(det_match, canonical_event)

                            # 5. Create or update Security Incidents for correlation matches
                            for c_match in corr_matches:
                                self.inc_mgr.create_or_update_from_correlation(c_match, session)

                    processed_count += 1
                    if stream_entry_id:
                        ack_entry_ids.append(stream_entry_id)

                except Exception as ev_err:
                    metrics.inc_counter("correlation_evaluation_errors_total")
                    logger.error(
                        "Error in correlation worker for event '%s': %s",
                        clean_item.get("event_id"),
                        ev_err,
                    )

            # 6. Acknowledge messages in Redis only after DB commits
            if ack_entry_ids and self.queue.is_durable:
                self.queue.ack_consumer_group(self.group_name, *ack_entry_ids)
            self._persist_state(session)

            return processed_count

        finally:
            if owns_session:
                session.close()

    def run_worker_loop(self, poll_interval_sec: float = 0.1, max_batches: Optional[int] = None) -> None:
        """Run continuous stream worker loop with graceful stop support."""
        self._running = True
        batch_counter = 0

        logger.info("Correlation worker '%s' started on group '%s'", self.consumer_name, self.group_name)

        while self._running:
            processed = self.process_batch()
            if processed == 0:
                time.sleep(poll_interval_sec)
            batch_counter += 1
            if max_batches is not None and batch_counter >= max_batches:
                break

        logger.info("Correlation worker '%s' stopped cleanly", self.consumer_name)

    def stop(self) -> None:
        """Signal worker to stop gracefully."""
        self._running = False
