"""CyberSentinel AI — Detection Persistence & Idempotency Manager
Persists matched detection records and linked events to PostgreSQL (ADR-0003).
"""

import logging
from datetime import timezone
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from packages.common import compute_sha256, utc_now
from packages.observability.metrics import metrics
from schemas.canonical_event import CanonicalEvent
from services.detection import DetectionMatch
from services.persistence.models import Detection, DetectionEvent

logger = logging.getLogger("cybersentinel.detection.persistence")


class DetectionPersistenceManager:
    """Manages transactional and idempotent persistence of rule detection alerts in PostgreSQL."""

    @staticmethod
    def derive_detection_id(rule_id: str, event_id: str) -> str:
        """Derive deterministic detection identifier ensuring idempotency across re-evaluations."""
        digest = compute_sha256(f"detection:{rule_id}:{event_id}")
        return f"det-{digest[:28]}"

    def persist_match(
        self,
        match: DetectionMatch,
        event: CanonicalEvent,
        db_session: Session,
    ) -> Optional[Detection]:
        """Persist a single DetectionMatch and its linked DetectionEvent idempotently."""
        event_id = str(event.event_id)
        det_id = self.derive_detection_id(match.rule_id, event_id)
        event_time = event.timestamp

        # 1. Idempotency Check: verify if detection already exists
        existing = db_session.get(Detection, det_id)
        if existing:
            metrics.inc_duplicate_detections_suppressed()
            last_seen = existing.last_seen
            if last_seen and last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            cmp_event_time = event_time
            if cmp_event_time and cmp_event_time.tzinfo is None:
                cmp_event_time = cmp_event_time.replace(tzinfo=timezone.utc)

            # Update last_seen if this is a later occurrence
            if cmp_event_time and last_seen and cmp_event_time > last_seen:
                existing.last_seen = event_time
                try:
                    db_session.commit()
                except Exception:
                    db_session.rollback()
            return existing

        # 2. Build Detection and DetectionEvent records
        severity_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)
        detection = Detection(
            id=det_id,
            rule_id=match.rule_id,
            rule_version="1.0.0",
            severity=severity_str,
            first_seen=event_time,
            last_seen=event_time,
            status="open",
            created_at=utc_now(),
        )

        det_event = DetectionEvent(
            detection_id=det_id,
            event_id=event_id,
            relation_type="matched",
        )

        try:
            db_session.add(detection)
            db_session.add(det_event)
            db_session.commit()
            metrics.inc_detections_persisted()
            logger.info("Persisted detection '%s' for rule '%s'", det_id, match.rule_name)
            return detection
        except IntegrityError:
            # Race condition: another concurrent worker already inserted this detection
            db_session.rollback()
            metrics.inc_duplicate_detections_suppressed()
            return db_session.get(Detection, det_id)
        except Exception as ex:
            db_session.rollback()
            logger.error("Failed to persist detection for rule '%s': %s", match.rule_id, ex)
            raise

    def persist_matches(
        self,
        matches: List[DetectionMatch],
        event: CanonicalEvent,
        db_session: Session,
    ) -> List[Detection]:
        """Persist all matches triggered by a single CanonicalEvent."""
        persisted: List[Detection] = []
        for m in matches:
            det = self.persist_match(m, event, db_session)
            if det:
                persisted.append(det)
        return persisted

    def persist_detection(
        self,
        match: DetectionMatch,
        event: Optional[CanonicalEvent] = None,
        session: Optional[Session] = None,
    ) -> bool:
        """Convenience method to persist a detection alert into PostgreSQL."""
        from services.persistence.database import SessionLocal
        close_session = False
        db = session
        if db is None:
            db = SessionLocal()
            close_session = True
        try:
            target_event = event
            if target_event is None:
                raw_eid = match.matched_event_ids[0] if match.matched_event_ids else str(uuid4())
                try:
                    event_id = UUID(raw_eid)
                except ValueError:
                    event_id = uuid4()
                target_event = CanonicalEvent(
                    event_id=event_id,
                    timestamp=utc_now(),
                    source_type="detection",
                    source_name="sigma_engine",
                    event_type="alert",
                    severity=match.severity,
                )
            res = self.persist_match(match, target_event, db)
            return res is not None
        finally:
            if close_session and db:
                db.close()


# Default singleton instance
persistence_manager = DetectionPersistenceManager()
detection_persistence = persistence_manager
