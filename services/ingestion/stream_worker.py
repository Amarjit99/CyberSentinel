"""CyberSentinel AI — Continuous Streaming Telemetry Ingestion Worker.

Coordinates live event streams: Ingestion -> Normalization -> Real-time Detection -> Correlation.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from services.detection.engine import SigmaDetectionEngine
from services.ingestion.pipeline import IngestionPipeline, IngestionPipelineResult
from services.ingestion.pipeline import pipeline as global_pipeline
from services.notifications.dispatcher import NotificationPayload, get_notification_dispatcher
from services.persistence.models import Detection

logger = logging.getLogger("cybersentinel.ingestion.stream")


class StreamBatchResult(BaseModel):
    batch_id: str
    events_received: int
    events_ingested: int
    events_quarantined: int
    detections_matched: int
    detection_ids: List[str] = Field(default_factory=list)
    processing_time_ms: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StreamIngestionWorker:
    """Continuous stream processor bridging telemetry normalization, detection, and correlation."""

    def __init__(
        self,
        ingest_pipeline: Optional[IngestionPipeline] = None,
        detection_engine: Optional[SigmaDetectionEngine] = None,
        correlation_engine: Optional[Any] = None,
    ) -> None:
        self.pipeline = ingest_pipeline or global_pipeline
        self.detection_engine = detection_engine
        self.correlation_engine = correlation_engine
        self.dispatcher = get_notification_dispatcher()

    def process_stream_batch(
        self,
        raw_events: List[Dict[str, Any]],
        connector_id: str = "stream-worker",
        db_session: Optional[Session] = None,
        auto_correlate: bool = True,
    ) -> StreamBatchResult:
        """Process a stream batch through normalization, real-time detection, and correlation."""
        start_time = time.perf_counter()
        batch_id = f"stream-{uuid4().hex[:12]}"
        ingested = 0
        quarantined = 0
        matched_detections: List[str] = []

        for raw in raw_events:
            # 1. Pipeline ingestion and deduplication
            res: IngestionPipelineResult = self.pipeline.ingest_event(
                record=raw,
                connector_id=connector_id,
                db_session=db_session,
            )

            if res.status in ("ingested", "duplicate"):
                ingested += 1
            else:
                quarantined += 1
                continue

            # 2. Evaluate against real-time detection engine if configured
            if self.detection_engine and self.detection_engine.rule_count > 0:
                try:
                    norm_result = self.pipeline.normalizer.normalize(raw, connector_id=connector_id)
                    if norm_result.success and norm_result.event:
                        matches = self.detection_engine.evaluate(norm_result.event)
                        for match in matches:
                            det_id = f"det-{uuid4().hex[:12]}"
                            matched_detections.append(det_id)

                        entity_type = "host" if norm_result.event.hostname else "user"
                        entity_id = norm_result.event.hostname or norm_result.event.username or "unknown"
                        severity_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)

                        # If db_session provided, persist Detection
                        if db_session:
                            detection_record = Detection(
                                id=det_id,
                                rule_id=match.rule_id,
                                rule_name=match.rule_title,
                                severity=severity_str,
                                status="open",
                                entity_type=entity_type,
                                entity_id=entity_id,
                                event_ids=[res.event_id or str(norm_result.event.event_id)],
                                confidence=0.85,
                                mitre_tactics=match.mitre_attack_ids,
                                mitre_techniques=match.mitre_attack_ids,
                                detected_at=datetime.now(timezone.utc),
                            )
                            db_session.add(detection_record)

                        # 3. Slide window correlation if configured
                        if auto_correlate and self.correlation_engine:
                            try:
                                self.correlation_engine.process_detection(
                                    detection_id=det_id,
                                    entity_type=entity_type,
                                    entity_id=entity_id,
                                    rule_id=match.rule_id,
                                    severity=severity_str,
                                    tactics=match.mitre_attack_ids,
                                    timestamp=datetime.now(timezone.utc),
                                    db_session=db_session,
                                )
                            except Exception as ce:
                                logger.debug("Correlation skipped or completed: %s", ce)

                        # 4. High / Critical notification dispatch
                        if severity_str.lower() in ("high", "critical"):
                            try:
                                self.dispatcher.dispatch_sync(
                                    NotificationPayload(
                                        event_type="alert_created",
                                        title=f"Detection: {match.rule_title}",
                                        message=f"Rule {match.rule_id} triggered on entity {entity_id} with severity {severity_str}",
                                        severity=severity_str,
                                        detection_id=det_id,
                                    )
                                )
                            except Exception as de:
                                logger.warning("Outbound notification dispatch failed: %s", de)
                except Exception as ex:
                    logger.warning("Stream detection evaluation failed for event: %s", ex)

        if db_session:
            try:
                db_session.commit()
            except Exception as dbe:
                db_session.rollback()
                logger.error("Failed to commit stream batch to DB: %s", dbe)

        duration_ms = (time.perf_counter() - start_time) * 1000
        return StreamBatchResult(
            batch_id=batch_id,
            events_received=len(raw_events),
            events_ingested=ingested,
            events_quarantined=quarantined,
            detections_matched=len(matched_detections),
            detection_ids=matched_detections,
            processing_time_ms=round(duration_ms, 2),
        )
