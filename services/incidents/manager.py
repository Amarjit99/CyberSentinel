"""CyberSentinel AI — Incident Management & Case Persistence
Manages incident deduplication, detection clustering, entity associations, notes, and timeline.
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, CSAI-P4-CORRELATION
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.common import compute_sha256, utc_now
from packages.observability.metrics import metrics
from schemas.enums import IncidentStateEnum
from services.correlation.models import CorrelationMatch
from services.persistence.models import (
    AuditEvent,
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
    IncidentNote,
)

logger = logging.getLogger("cybersentinel.incidents.manager")

# Severity order for automatic escalation
SEVERITY_ORDER = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


class IncidentManager:
    """Manages the operational lifecycle, persistence, and evidence tracking of security incidents."""

    @staticmethod
    def derive_incident_id(rule_id: str, entity_type: str, entity_key: str, window_start: datetime) -> str:
        """Derive deterministic incident ID preventing duplicate creation on redelivery."""
        raw = f"incident:{rule_id}:{entity_type}:{entity_key}:{window_start.isoformat()}"
        digest = compute_sha256(raw)
        return f"inc-{digest[:28]}"

    def create_or_update_from_correlation(
        self,
        match: CorrelationMatch,
        db_session: Session,
    ) -> Incident:
        """Create a new incident or update an existing active incident based on correlation match."""
        # 1. Search for existing active (non-closed) incident matching this entity
        active_query = (
            select(Incident)
            .join(IncidentEntity, Incident.id == IncidentEntity.incident_id)
            .where(
                IncidentEntity.entity_type == match.entity_type,
                IncidentEntity.entity_key == match.entity_key,
                Incident.status.notin_([IncidentStateEnum.CLOSED.value, IncidentStateEnum.BENIGN.value]),
            )
            .order_by(Incident.created_at.desc())
        )
        existing_incident = db_session.execute(active_query).scalars().first()

        match_sev_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)

        if existing_incident:
            # --- UPDATE EXISTING INCIDENT ---
            # Update temporal boundaries with timezone safety
            existing_last = existing_incident.last_seen
            if existing_last.tzinfo is None:
                existing_last = existing_last.replace(tzinfo=timezone.utc)
            match_last = match.window_end
            if match_last.tzinfo is None:
                match_last = match_last.replace(tzinfo=timezone.utc)

            if match_last > existing_last:
                existing_incident.last_seen = match_last

            # Check severity escalation
            curr_rank = SEVERITY_ORDER.get(existing_incident.severity.lower(), 1)
            new_rank = SEVERITY_ORDER.get(match_sev_str.lower(), 1)
            if new_rank > curr_rank:
                existing_incident.severity = match_sev_str
                logger.info(
                    "Escalated incident '%s' severity to '%s'", existing_incident.id, match_sev_str
                )


            # Link new detections idempotently
            existing_det_ids = set(
                db_session.execute(
                    select(IncidentDetection.detection_id).where(
                        IncidentDetection.incident_id == existing_incident.id
                    )
                ).scalars().all()
            )

            for did in match.detection_ids:
                if did not in existing_det_ids:
                    inc_det = IncidentDetection(
                        incident_id=existing_incident.id,
                        detection_id=did,
                        link_reason=f"Correlated by rule: {match.rule_name}",
                        linked_by="correlation_engine",
                        linked_at=utc_now(),
                    )
                    db_session.add(inc_det)

            # Ensure entity is linked
            existing_entities = set(
                db_session.execute(
                    select(IncidentEntity.entity_type, IncidentEntity.entity_key).where(
                        IncidentEntity.incident_id == existing_incident.id
                    )
                ).all()
            )

            if (match.entity_type, match.entity_key) not in existing_entities:
                inc_entity = IncidentEntity(
                    incident_id=existing_incident.id,
                    entity_type=match.entity_type,
                    entity_key=match.entity_key,
                    relation="correlated_entity",
                    first_seen=match.window_start,
                    last_seen=match.window_end,
                )
                db_session.add(inc_entity)

            existing_incident.updated_at = utc_now()
            db_session.commit()
            metrics.inc_counter("incidents_updated_total")
            return existing_incident

        else:
            # --- CREATE NEW INCIDENT ---
            inc_id = self.derive_incident_id(
                match.rule_id, match.entity_type, match.entity_key, match.window_start
            )

            # Double check PK collision
            collision = db_session.get(Incident, inc_id)
            if collision:
                metrics.inc_counter("duplicate_incidents_suppressed_total")
                return collision

            incident = Incident(
                id=inc_id,
                title=match.title,
                status=IncidentStateEnum.NEW.value,
                severity=match_sev_str,
                confidence=match.confidence,
                first_seen=match.window_start,
                last_seen=match.window_end,
                version=1,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            db_session.add(incident)
            db_session.flush()

            # Link detection records
            for did in match.detection_ids:
                inc_det = IncidentDetection(
                    incident_id=incident.id,
                    detection_id=did,
                    link_reason=f"Initial correlation: {match.rule_name}",
                    linked_by="correlation_engine",
                    linked_at=utc_now(),
                )
                db_session.add(inc_det)

            # Link primary entity
            inc_entity = IncidentEntity(
                incident_id=incident.id,
                entity_type=match.entity_type,
                entity_key=match.entity_key,
                relation="primary_affected_entity",
                first_seen=match.window_start,
                last_seen=match.window_end,
            )
            db_session.add(inc_entity)

            # Record audit event for creation
            audit = AuditEvent(
                id=str(uuid4()),
                actor_type="AGENT",
                actor_id="correlation_engine",
                action="incident:created",
                object_type="incident",
                object_id=incident.id,
                outcome="SUCCESS",
                reason_code="CORRELATION_MATCH",
                occurred_at=utc_now(),
                metadata_redacted={
                    "rule_id": match.rule_id,
                    "rule_name": match.rule_name,
                    "entity_type": match.entity_type,
                    "entity_key": match.entity_key,
                    "severity": match_sev_str,
                },
            )
            db_session.add(audit)

            db_session.commit()
            metrics.inc_counter("incidents_created_total")
            logger.info("Created new incident '%s' (Title: %s)", incident.id, incident.title)
            return incident

    def add_note(
        self,
        incident_id: str,
        author_id: str,
        body: Optional[str] = None,
        note_text: Optional[str] = None,
        db_session: Optional[Session] = None,
        session: Optional[Session] = None,
    ) -> IncidentNote:
        """Add an analyst investigation note with credential redaction."""
        db = db_session if db_session is not None else session
        if db is None:
            raise ValueError("Database session required for add_note")

        raw_text = note_text if note_text is not None else (body or "")
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        # Sanitize sensitive patterns (e.g. passwords, bearer tokens, api keys)
        import re
        sanitized_body = raw_text
        sanitized_body = re.sub(
            r"(?i)(bearer\s+)([A-Za-z0-9\-_\.=]+)",
            r"\1[REDACTED_SECRET]",
            sanitized_body,
        )
        sanitized_body = re.sub(
            r"(?i)(password|passwd|secret|api[_-]?key)[:=\s]+([^\s]+)",
            r"\1: [REDACTED_SECRET]",
            sanitized_body,
        )

        note = IncidentNote(
            id=str(uuid4()),
            incident_id=incident_id,
            author_id=author_id,
            body_redacted=sanitized_body,
            created_at=utc_now(),
        )
        # Expose convenient note property
        note.note = sanitized_body  # type: ignore[attr-defined]
        db.add(note)

        # Audit entry
        audit = AuditEvent(
            id=str(uuid4()),
            actor_type="USER",
            actor_id=author_id,
            action="incident:note_added",
            object_type="incident",
            object_id=incident_id,
            outcome="SUCCESS",
            occurred_at=utc_now(),
            metadata_redacted={"note_id": note.id},
        )
        db.add(audit)
        db.commit()
        return note

    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        source_ref: str,
        checksum: str,
        provenance: dict,
        created_by: str,
        db_session: Optional[Session] = None,
        session: Optional[Session] = None,
    ) -> Evidence:
        """Attach formal forensic evidence reference to an incident."""
        db = db_session if db_session is not None else session
        if db is None:
            raise ValueError("Database session required for add_evidence")

        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        evidence = Evidence(
            id=str(uuid4()),
            incident_id=incident_id,
            evidence_type=evidence_type,
            source_ref=source_ref,
            checksum=checksum,
            provenance_json=provenance,
            classification="internal",
            collected_at=utc_now(),
            created_by=created_by,
        )
        db.add(evidence)
        db.commit()
        return evidence

    def get_timeline(
        self,
        incident_id: Any,
        db_session: Optional[Any] = None,
        session: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        """Construct an ordered, unified investigation timeline for an incident."""
        if isinstance(incident_id, Session):
            db: Optional[Session] = incident_id
            real_incident_id = str(db_session)
        else:
            db = db_session if isinstance(db_session, Session) else session
            real_incident_id = str(incident_id)

        if db is None:
            raise ValueError("Database session required for get_timeline")
        active_db: Session = db

        incident = active_db.get(Incident, real_incident_id)
        if not incident:
            raise ValueError(f"Incident '{real_incident_id}' not found")

        timeline: List[Dict[str, Any]] = []

        # 1. Incident Creation Event
        timeline.append({
            "timestamp": incident.created_at.isoformat(),
            "type": "incident_created",
            "event_type": "incident_created",
            "title": f"Incident Created: {incident.title}",
            "actor": "correlation_engine",
            "details": {
                "initial_severity": incident.severity,
                "status": incident.status,
            },
        })

        # 2. Correlated Detections
        det_links = active_db.execute(
            select(IncidentDetection, Detection)
            .join(Detection, IncidentDetection.detection_id == Detection.id)
            .where(IncidentDetection.incident_id == real_incident_id)
        ).all()

        for link, det in det_links:
            timeline.append({
                "timestamp": link.linked_at.isoformat(),
                "type": "detection_correlated",
                "event_type": "detection_correlated",
                "title": f"Detection Linked: {det.rule_id}",
                "actor": link.linked_by,
                "details": {
                    "detection_id": det.id,
                    "rule_id": det.rule_id,
                    "severity": det.severity,
                    "link_reason": link.link_reason,
                },
            })

        # 3. Associated Entities
        entities = active_db.execute(
            select(IncidentEntity).where(IncidentEntity.incident_id == real_incident_id)
        ).scalars().all()

        for ent in entities:
            timeline.append({
                "timestamp": ent.first_seen.isoformat(),
                "type": "entity_associated",
                "event_type": "entity_associated",
                "title": f"Entity Associated: {ent.entity_type}:{ent.entity_key}",
                "actor": "correlation_engine",
                "details": {
                    "entity_type": ent.entity_type,
                    "entity_key": ent.entity_key,
                    "relation": ent.relation,
                },
            })

        # 4. Analyst Notes
        notes = active_db.execute(
            select(IncidentNote).where(IncidentNote.incident_id == real_incident_id)
        ).scalars().all()

        for note in notes:
            timeline.append({
                "timestamp": note.created_at.isoformat(),
                "type": "analyst_note",
                "event_type": "analyst_note",
                "title": f"Note by {note.author_id}",
                "actor": note.author_id,
                "details": {
                    "note_id": note.id,
                    "body": note.body_redacted,
                },
            })

        # 5. Evidence Attachments
        evidences = active_db.execute(
            select(Evidence).where(Evidence.incident_id == real_incident_id)
        ).scalars().all()

        for ev in evidences:
            timeline.append({
                "timestamp": ev.collected_at.isoformat(),
                "type": "evidence_attached",
                "event_type": "evidence_attached",
                "title": f"Evidence Attached: {ev.evidence_type}",
                "actor": ev.created_by,
                "details": {
                    "evidence_id": ev.id,
                    "source_ref": ev.source_ref,
                    "checksum": ev.checksum,
                },
            })

        # 6. Audit Events (Transitions, etc.)
        audits = active_db.execute(
            select(AuditEvent).where(
                AuditEvent.object_type == "incident",
                AuditEvent.object_id == real_incident_id,
            )
        ).scalars().all()

        for audit in audits:
            if audit.action == "incident:transition":
                timeline.append({
                    "timestamp": audit.occurred_at.isoformat(),
                    "type": "state_transition",
                    "event_type": "state_transition",
                    "title": f"State Transition: {audit.metadata_redacted.get('from_state')} -> {audit.metadata_redacted.get('to_state')}",
                    "actor": audit.actor_id,
                    "details": audit.metadata_redacted,
                })

        # Sort timeline chronologically
        timeline.sort(key=lambda item: item["timestamp"])
        return timeline

    def get_incident_timeline(
        self,
        incident_id: str,
        db_session: Optional[Session] = None,
        session: Optional[Session] = None,
    ) -> List[Dict[str, Any]]:
        """Convenience alias for get_timeline."""
        return self.get_timeline(incident_id, db_session=db_session, session=session)



incident_manager = IncidentManager()
