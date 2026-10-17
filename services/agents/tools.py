"""CyberSentinel AI — Read-Only Agent Investigation Tools (ADR-0002, Doc 10)

Exposes a strictly bounded, read-only tool registry for autonomous agents.
Prohibits shell execution, generic database updates, arbitrary network requests,
and live containment actions.
"""

from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.observability.metrics import metrics
from services.persistence.models import (
    AgentFinding,
    AgentRun,
    Detection,
    DetectionEvent,
    Event,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
)


class UnauthorizedToolError(PermissionError):
    """Raised when an agent attempts to invoke an unauthorized or write tool."""


class ReadOnlyInvestigationTools:
    """Registry of approved read-only tools scoped strictly to an incident."""

    ALLOWED_TOOLS = {
        "get_incident_summary",
        "get_incident_detections",
        "get_canonical_events",
        "get_incident_timeline",
        "get_incident_entities",
        "get_incident_evidence",
        "get_prior_findings",
        "lookup_threat_intel",
        "get_incident_risk_assessment",
    }


    def __init__(self, session: Session, incident_id: str):
        self.session = session
        self.incident_id = incident_id

    def execute_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Dispatch a tool call after verifying it is in the approved read-only allowlist."""
        if tool_name not in self.ALLOWED_TOOLS:
            metrics.inc_counter("unauthorized_tool_attempts_total", 1)
            raise UnauthorizedToolError(
                f"Tool '{tool_name}' is not in the approved read-only allowlist. "
                "Shell execution and live response actions are strictly prohibited."
            )

        args = arguments or {}
        method = getattr(self, tool_name)
        return method(**args)

    def get_incident_summary(self) -> Dict[str, Any]:
        """Retrieve authoritative metadata for the scoped incident."""
        inc = self.session.get(Incident, self.incident_id)
        if not inc:
            return {"error": f"Incident '{self.incident_id}' not found"}

        return {
            "id": inc.id,
            "title": inc.title,
            "status": inc.status,
            "severity": inc.severity,
            "confidence": inc.confidence,
            "first_seen": inc.first_seen.isoformat(),
            "last_seen": inc.last_seen.isoformat(),
            "version": inc.version,
        }

    def get_incident_detections(self) -> List[Dict[str, Any]]:
        """Retrieve all Sigma detections associated with the incident."""
        stmt = (
            select(IncidentDetection, Detection)
            .join(Detection, IncidentDetection.detection_id == Detection.id)
            .where(IncidentDetection.incident_id == self.incident_id)
        )
        results = self.session.execute(stmt).all()
        return [
            {
                "detection_id": det.id,
                "rule_id": det.rule_id,
                "rule_version": det.rule_version,
                "severity": det.severity,
                "link_reason": link.link_reason,
                "first_seen": det.first_seen.isoformat(),
                "last_seen": det.last_seen.isoformat(),
            }
            for link, det in results
        ]

    def get_canonical_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve canonical events associated with the incident's detections."""
        safe_limit = max(1, min(limit, 50))
        stmt = (
            select(Event)
            .join(DetectionEvent, Event.id == DetectionEvent.event_id)
            .join(IncidentDetection, DetectionEvent.detection_id == IncidentDetection.detection_id)
            .where(IncidentDetection.incident_id == self.incident_id)
            .limit(safe_limit)
        )
        events = self.session.execute(stmt).scalars().all()
        return [
            {
                "event_id": ev.id,
                "source_id": ev.source_id,
                "event_time": ev.event_time.isoformat(),
                "schema_version": ev.schema_version,
                "raw_ref": ev.raw_ref,
                "classification": ev.classification,
            }
            for ev in events
        ]

    def get_incident_timeline(self) -> List[Dict[str, Any]]:
        """Retrieve the unified chronological timeline for the incident."""
        from services.incidents.manager import incident_manager

        return incident_manager.get_incident_timeline(
            session=self.session, incident_id=self.incident_id
        )

    def get_incident_entities(self) -> List[Dict[str, Any]]:
        """Retrieve all entity relationships attached to this incident."""
        stmt = select(IncidentEntity).where(IncidentEntity.incident_id == self.incident_id)
        entities = self.session.execute(stmt).scalars().all()
        return [
            {
                "entity_type": ent.entity_type,
                "entity_key": ent.entity_key,
                "relation": ent.relation,
                "first_seen": ent.first_seen.isoformat(),
                "last_seen": ent.last_seen.isoformat(),
            }
            for ent in entities
        ]

    def get_incident_evidence(self) -> List[Dict[str, Any]]:
        """Retrieve evidence artifacts recorded for the incident."""
        stmt = select(Evidence).where(Evidence.incident_id == self.incident_id)
        evidences = self.session.execute(stmt).scalars().all()
        return [
            {
                "evidence_id": ev.id,
                "evidence_type": ev.evidence_type,
                "source_ref": ev.source_ref,
                "checksum": ev.checksum,
                "provenance": ev.provenance_json,
                "collected_at": ev.collected_at.isoformat(),
                "created_by": ev.created_by,
            }
            for ev in evidences
        ]

    def get_prior_findings(self) -> List[Dict[str, Any]]:
        """Retrieve findings generated by previous agent runs on this incident."""
        stmt = (
            select(AgentFinding)
            .join(AgentRun, AgentFinding.run_id == AgentRun.id)
            .where(AgentRun.incident_id == self.incident_id)
        )
        findings = self.session.execute(stmt).scalars().all()
        return [
            {
                "finding_id": f.id,
                "finding_type": f.finding_type,
                "claim": f.claim,
                "confidence": f.confidence,
                "evidence_refs": f.evidence_refs_json,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ]

    def lookup_threat_intel(
        self, indicator_type: str, indicator_value: str
    ) -> Dict[str, Any]:
        """Query approved threat intelligence repository for indicator context.

        Returns structured facts with source provenance; clearly states 'unknown' if not present in database.
        """
        from services.threat_intel import ThreatIntelService

        try:
            service = ThreatIntelService(session=self.session)
            result = service.lookup_indicator(
                indicator_type=indicator_type, indicator_value=indicator_value
            )
            return result.to_agent_dict()
        except Exception as ex:
            metrics.inc_counter("threat_intel_lookup_errors_total", 1)
            return {
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "reputation": "unknown",
                "score": 0.0,
                "has_reputation_score": False,
                "error": f"Threat intelligence lookup failed: {ex}",
                "limitations": "Threat intelligence database error. No reputation claims could be verified.",
            }

    def get_incident_risk_assessment(self) -> Dict[str, Any]:
        """Retrieve or calculate the explainable deterministic risk assessment for this incident."""
        from services.persistence.models import IncidentRiskAssessmentModel
        from services.risk import DeterministicRiskEngine

        stmt = (
            select(IncidentRiskAssessmentModel)
            .where(IncidentRiskAssessmentModel.incident_id == self.incident_id)
            .order_by(IncidentRiskAssessmentModel.assessed_at.desc())
        )
        existing = self.session.execute(stmt).scalars().first()
        if existing:
            return {
                "assessment_id": existing.id,
                "incident_id": existing.incident_id,
                "overall_score": existing.overall_score,
                "risk_band": existing.risk_band,
                "policy_version": existing.policy_version,
                "primary_drivers": existing.primary_drivers_json,
                "uncertainties": existing.uncertainties_json,
                "limitations": existing.limitations_json,
                "evidence_refs": existing.evidence_refs_json,
                "assessed_at": existing.assessed_at.isoformat(),
            }

        incident = self.session.get(Incident, self.incident_id)
        if not incident:
            return {
                "error": f"Incident '{self.incident_id}' not found",
                "overall_score": 0.0,
                "risk_band": "LOW",
            }

        engine = DeterministicRiskEngine()
        assessment = engine.assess_incident(
            incident=incident,
            db_session=self.session,
            actor_id="agent:investigation",
            persist=True,
        )
        return {
            "assessment_id": assessment.id,
            "incident_id": assessment.incident_id,
            "overall_score": assessment.overall_score,
            "risk_band": assessment.risk_band.value,
            "policy_version": assessment.policy_version,
            "primary_drivers": assessment.primary_drivers,
            "uncertainties": assessment.uncertainties,
            "limitations": assessment.limitations,
            "evidence_refs": assessment.evidence_refs,
            "assessed_at": assessment.assessed_at.isoformat(),
        }


__all__ = ["ReadOnlyInvestigationTools", "UnauthorizedToolError"]

