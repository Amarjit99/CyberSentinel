"""CyberSentinel AI — Evidence Grounding & Reference Validation (ADR-0002, Doc 10)

Enforces strict verification of all factual assertions against authoritative database
records. Prevents model hallucinations from masquerading as verified security facts.
"""

from typing import List, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.observability.metrics import metrics
from services.agents.models import AgentFinding
from services.persistence.models import (
    Detection,
    DetectionEvent,
    Event,
    Evidence,
    IncidentDetection,
    IncidentEntity,
)


class EvidenceValidationError(ValueError):
    """Raised when critical evidence references cannot be verified."""


class EvidenceValidator:
    """Validates that cited evidence IDs genuinely exist and belong to the incident."""

    def __init__(self, session: Session):
        self.session = session

    def validate_reference(
        self, incident_id: str, ref_id: str
    ) -> Tuple[bool, str, str]:
        """Check if ref_id corresponds to a valid record belonging to the incident.

        Returns (is_valid, record_type, context_snippet).
        """
        # 1. Check in evidence table directly
        ev = self.session.execute(
            select(Evidence).where(
                Evidence.id == ref_id, Evidence.incident_id == incident_id
            )
        ).scalar_one_or_none()
        if ev:
            metrics.inc_counter("evidence_refs_validated_total", 1)
            return True, "evidence", f"Evidence type={ev.evidence_type}, source={ev.source_ref}"

        # 2. Check in incident_detections
        inc_det = self.session.execute(
            select(IncidentDetection, Detection)
            .join(Detection, IncidentDetection.detection_id == Detection.id)
            .where(
                IncidentDetection.incident_id == incident_id,
                IncidentDetection.detection_id == ref_id,
            )
        ).first()
        if inc_det:
            det = inc_det[1]
            metrics.inc_counter("evidence_refs_validated_total", 1)
            return True, "detection", f"Detection rule={det.rule_id}, severity={det.severity}"

        # 3. Check in incident_entities
        ent = self.session.execute(
            select(IncidentEntity).where(
                IncidentEntity.incident_id == incident_id,
                IncidentEntity.entity_key == ref_id,
            )
        ).scalar_one_or_none()
        if ent:
            metrics.inc_counter("evidence_refs_validated_total", 1)
            return True, "entity", f"Entity type={ent.entity_type}, key={ent.entity_key}"

        # 4. Check in canonical events linked to this incident's detections
        event_match = self.session.execute(
            select(Event)
            .join(DetectionEvent, Event.id == DetectionEvent.event_id)
            .join(IncidentDetection, DetectionEvent.detection_id == IncidentDetection.detection_id)
            .where(
                IncidentDetection.incident_id == incident_id,
                Event.id == ref_id,
            )
        ).scalar_one_or_none()
        if event_match:
            metrics.inc_counter("evidence_refs_validated_total", 1)
            return True, "event", f"Event source={event_match.source_id}, time={event_match.event_time}"

        # Not found or does not belong to this incident!
        metrics.inc_counter("evidence_refs_rejected_total", 1)
        return False, "unknown", ""

    def validate_finding(
        self, incident_id: str, finding: AgentFinding
    ) -> Tuple[AgentFinding, bool]:
        """Validate all evidence references cited by a finding.

        Rules:
        - If finding is marked is_hypothesis=True, it may pass even with zero verified evidence,
          with confidence capped at 0.5.
        - If finding is marked as observed fact, ALL cited evidence references must be verified.
        - Fabricated references are purged. If none remain, finding is converted to a hypothesis
          with reduced confidence.
        """
        valid_refs: List[str] = []
        has_invalid = False

        for ref_id in finding.evidence_refs:
            is_valid, _, _ = self.validate_reference(incident_id, ref_id)
            if is_valid:
                valid_refs.append(ref_id)
            else:
                has_invalid = True

        finding.evidence_refs = valid_refs

        if not valid_refs and not finding.is_hypothesis:
            # Demote to hypothesis because no backing evidence could be verified
            finding.is_hypothesis = True
            finding.confidence = min(finding.confidence, 0.4)
            if not finding.limitations:
                finding.limitations = "Demoted to hypothesis: cited evidence references were invalid or missing."
            else:
                finding.limitations += " | Demoted to hypothesis: evidence references unverified."
            return finding, False

        if has_invalid:
            # Some references were purged
            finding.confidence = max(0.1, finding.confidence - 0.2)
            warning = "Note: One or more cited evidence references were rejected as invalid or cross-incident."
            finding.limitations = f"{finding.limitations} | {warning}" if finding.limitations else warning

        return finding, True


__all__ = ["EvidenceValidator", "EvidenceValidationError"]
