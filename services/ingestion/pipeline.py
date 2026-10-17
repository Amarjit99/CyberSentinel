"""CyberSentinel AI — Production Log Ingestion Pipeline Orchestrator

Integrates: Adapter parsing -> Normalization -> Deduplication -> Durable queueing -> Persistence.
"""

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from packages.common import utc_now
from packages.observability import metrics
from services.ingestion.queue import (
    BrokerUnavailableError,
    DurableEventQueue,
    QuarantineManager,
    durable_queue,
    quarantine_manager,
)
from services.normalization.deduplication import DeduplicationCache, deduplicator
from services.normalization.engine import NormalizationEngine
from services.persistence.models import EventMetadata


class IngestionPipelineResult(BaseModel):
    """Result of processing an individual event through the ingestion pipeline."""

    event_id: Optional[str] = Field(default=None, description="Assigned canonical event ID")
    status: str = Field(..., description="Outcome status: ingested, duplicate, quarantined, error")
    source_type: str = Field(default="unknown", description="Normalized source classification")
    raw_hash: str = Field(..., description="Cryptographic SHA-256 digest of incoming payload")
    quarantine_id: Optional[str] = Field(
        default=None, description="Quarantine ID if event was rejected"
    )
    error: Optional[str] = Field(default=None, description="Sanitized diagnostic explanation")
    persisted: bool = Field(
        default=False, description="Whether event metadata was committed to SQL"
    )
    delivery_mode: str = Field(
        default="in_memory_fallback",
        description="Delivery mode: redis_streams or in_memory_volatile_fallback",
    )
    is_durable: bool = Field(
        default=False, description="Whether event was delivered to an active durable broker"
    )


class IngestionPipeline:
    """Production ingestion pipeline coordinator."""

    def __init__(
        self,
        normalizer: Optional[NormalizationEngine] = None,
        dedup_cache: Optional[DeduplicationCache] = None,
        queue: Optional[DurableEventQueue] = None,
        quarantine: Optional[QuarantineManager] = None,
    ) -> None:
        self.normalizer = normalizer or NormalizationEngine()
        self.dedup_cache = dedup_cache or deduplicator
        self.queue = queue or durable_queue
        self.quarantine = quarantine or quarantine_manager

    def ingest_event(
        self,
        record: Dict[str, Any],
        connector_id: Optional[str] = None,
        source_hint: Optional[str] = None,
        db_session: Optional[Session] = None,
        require_durability: bool = False,
    ) -> IngestionPipelineResult:
        """Process a single telemetry dictionary end-to-end."""
        start_time = time.perf_counter()
        src_id = connector_id or record.get("source_id") or "direct-api"
        source_type = source_hint or record.get("source_type") or "telemetry"

        # 1. Normalization
        norm_result = self.normalizer.normalize(record, connector_id=src_id)
        if not norm_result.success or norm_result.is_quarantined or not norm_result.event:
            # Route to Quarantine
            q_rec = self.quarantine.quarantine_event(
                source_type=source_type,
                error_reason=norm_result.error or "Unknown normalization failure",
                raw_payload=record,
                raw_hash=norm_result.raw_hash,
            )
            elapsed = time.perf_counter() - start_time
            metrics.record_latency(elapsed)
            return IngestionPipelineResult(
                status="quarantined",
                source_type=source_type,
                raw_hash=norm_result.raw_hash,
                quarantine_id=q_rec.quarantine_id,
                error=norm_result.error,
                persisted=False,
                delivery_mode=self.queue.storage_mode,
                is_durable=self.queue.is_durable,
            )

        event = norm_result.event
        event_id_str = str(event.event_id)

        # 2. In-memory Deduplication check
        dedup_key = f"{src_id}:{norm_result.raw_hash}"
        if self.dedup_cache.is_duplicate(dedup_key):
            elapsed = time.perf_counter() - start_time
            metrics.record_latency(elapsed)
            return IngestionPipelineResult(
                event_id=event_id_str,
                status="duplicate",
                source_type=event.source_type,
                raw_hash=norm_result.raw_hash,
                error="Duplicate event suppressed within active deduplication window",
                persisted=False,
                delivery_mode=self.queue.storage_mode,
                is_durable=self.queue.is_durable,
            )

        # 3. Publish to stream queue (Redis Streams or observable bounded memory queue)
        try:
            enqueued = self.queue.enqueue(event, require_durability=require_durability)
            if not enqueued:
                elapsed = time.perf_counter() - start_time
                metrics.record_latency(elapsed)
                return IngestionPipelineResult(
                    event_id=event_id_str,
                    status="error",
                    source_type=event.source_type,
                    raw_hash=norm_result.raw_hash,
                    error="Queue backpressure capacity exceeded; event rejected",
                    persisted=False,
                    delivery_mode=self.queue.storage_mode,
                    is_durable=self.queue.is_durable,
                )
        except BrokerUnavailableError as b_err:
            elapsed = time.perf_counter() - start_time
            metrics.record_latency(elapsed)
            return IngestionPipelineResult(
                event_id=event_id_str,
                status="error",
                source_type=event.source_type,
                raw_hash=norm_result.raw_hash,
                error=str(b_err),
                persisted=False,
                delivery_mode=self.queue.storage_mode,
                is_durable=False,
            )

        # 4. Transactional persistence in PostgreSQL `events` table (if db_session provided)
        persisted = False
        if db_session is not None:
            # Check for existing primary key to ensure database-level idempotency
            existing = db_session.get(EventMetadata, event_id_str)
            if existing:
                metrics.inc_duplicate()
                elapsed = time.perf_counter() - start_time
                metrics.record_latency(elapsed)
                return IngestionPipelineResult(
                    event_id=event_id_str,
                    status="duplicate",
                    source_type=event.source_type,
                    raw_hash=norm_result.raw_hash,
                    error="Duplicate event suppressed by database primary key uniqueness",
                    persisted=False,
                    delivery_mode=self.queue.storage_mode,
                    is_durable=self.queue.is_durable,
                )

            try:
                db_event = EventMetadata(
                    id=event_id_str,
                    source_id=src_id,
                    event_time=event.timestamp,
                    received_at=event.ingest_timestamp,
                    schema_version="1.0.0",
                    raw_ref=event.raw_ref,
                    checksum=norm_result.raw_hash,
                    classification=event.severity.value
                    if hasattr(event.severity, "value")
                    else str(event.severity),
                    event_type=event.event_type,
                    hostname=event.hostname,
                    username=event.username,
                    src_ip=str(event.src_ip) if event.src_ip else None,
                    dst_ip=str(event.dst_ip) if event.dst_ip else None,
                    severity=event.severity.value
                    if hasattr(event.severity, "value")
                    else str(event.severity),
                    created_at=utc_now(),
                )
                db_session.add(db_event)
                db_session.commit()
                persisted = True
                metrics.inc_persisted()
            except IntegrityError:
                db_session.rollback()
                metrics.inc_duplicate()
                elapsed = time.perf_counter() - start_time
                metrics.record_latency(elapsed)
                return IngestionPipelineResult(
                    event_id=event_id_str,
                    status="duplicate",
                    source_type=event.source_type,
                    raw_hash=norm_result.raw_hash,
                    error="Duplicate event suppressed by database integrity constraint",
                    persisted=False,
                    delivery_mode=self.queue.storage_mode,
                    is_durable=self.queue.is_durable,
                )
            except Exception as ex:
                db_session.rollback()
                elapsed = time.perf_counter() - start_time
                metrics.record_latency(elapsed)
                return IngestionPipelineResult(
                    event_id=event_id_str,
                    status="error",
                    source_type=event.source_type,
                    raw_hash=norm_result.raw_hash,
                    error=f"SQL persistence failed: {ex}",
                    persisted=False,
                    delivery_mode=self.queue.storage_mode,
                    is_durable=self.queue.is_durable,
                )

        elapsed = time.perf_counter() - start_time
        metrics.record_latency(elapsed)

        return IngestionPipelineResult(
            event_id=event_id_str,
            status="ingested",
            source_type=event.source_type,
            raw_hash=norm_result.raw_hash,
            persisted=persisted,
            delivery_mode=self.queue.storage_mode,
            is_durable=self.queue.is_durable,
        )

    def ingest_batch(
        self,
        records: List[Dict[str, Any]],
        connector_id: Optional[str] = None,
        source_hint: Optional[str] = None,
        db_session: Optional[Session] = None,
    ) -> List[IngestionPipelineResult]:
        """Ingest a collection of events."""
        return [
            self.ingest_event(
                r,
                connector_id=connector_id,
                source_hint=source_hint,
                db_session=db_session,
            )
            for r in records
        ]

    def replay_quarantined_event(
        self, quarantine_id: str, db_session: Optional[Session] = None
    ) -> IngestionPipelineResult:
        """Attempt to re-normalize and process a previously quarantined record."""
        q_rec = self.quarantine.replay_quarantined(quarantine_id)
        if not q_rec:
            return IngestionPipelineResult(
                status="error",
                raw_hash="",
                error="Quarantine record not found or maximum replay attempts exceeded (sent to DLQ)",
            )

        # Retry ingestion with the raw payload
        result = self.ingest_event(
            record=q_rec.raw_payload,
            connector_id=f"replay-{q_rec.source_type}",
            source_hint=q_rec.source_type,
            db_session=db_session,
        )

        if result.status == "ingested":
            # Remove from quarantine on successful resolution
            self.quarantine.remove_quarantined(quarantine_id)

        return result


# Global default pipeline singleton
pipeline = IngestionPipeline()
