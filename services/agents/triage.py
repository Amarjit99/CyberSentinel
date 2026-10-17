"""CyberSentinel AI — Evidence-Grounded Incident Triage Agent (Sprint 15)
Governing Decisions: ADR-0001, ADR-0002, ADR-0004, ADR-0005, CSAI-R0.4-TRIAGE-AGENT
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from attack.registry import AttackCatalog, AttackMappingService
from packages.common import utc_now
from packages.observability.metrics import metrics
from schemas.enums import EventSeverityEnum
from services.agents.evidence_validator import EvidenceValidator
from services.agents.models import EvidenceReference, TriageModelOutput, TriageReport
from services.agents.prompts import (
    SYSTEM_PROMPT_TEMPLATE,
    detect_suspicious_directives,
    format_untrusted_context,
    sanitize_prompt_body,
)
from services.agents.providers import (
    BaseLLMProvider,
    DeterministicRuleProvider,
    HTTPLLMProvider,
    LLMProviderError,
    ProviderInfo,
)
from services.agents.tools import ReadOnlyInvestigationTools
from services.persistence.models import (
    AuditEvent,
    Incident,
    IncidentTriageAssessmentModel,
)
from services.risk import DeterministicRiskEngine
from services.threat_intel.service import ThreatIntelService

logger = logging.getLogger("cybersentinel.agents.triage")

# Common adversarial prompt-injection heuristic patterns in untrusted logs
INJECTION_HEURISTICS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|evil|admin|root)", re.IGNORECASE),
    re.compile(r"system\s*override", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?safety\s+rules", re.IGNORECASE),
    re.compile(r"output\s+the\s+following\s+secret", re.IGNORECASE),
]


class TriageAgent:
    """Evidence-grounded, bounded incident triage agent with anti-hallucination controls.

    Guarantees:
    - Never uses an ungrounded or fabricated evidence reference.
    - Preserves deterministic risk scoring as authoritative (model cannot alter score).
    - Defends against prompt injection in untrusted log telemetry.
    - Automatically falls back to offline deterministic rules if provider fails or is unconfigured.
    - Never authorizes or executes response actions (read-only triage only).
    """

    def __init__(
        self,
        provider: Optional[BaseLLMProvider] = None,
        fallback_provider: Optional[BaseLLMProvider] = None,
        risk_engine: Optional[DeterministicRiskEngine] = None,
        attack_mapping_service: Optional[AttackMappingService] = None,
        threat_intel_service: Optional[ThreatIntelService] = None,
    ):
        self.provider = provider or HTTPLLMProvider()
        self.fallback_provider = fallback_provider or DeterministicRuleProvider()
        self.attack_mapping_service = attack_mapping_service or AttackMappingService(AttackCatalog())
        self.threat_intel_service = threat_intel_service or ThreatIntelService()
        self.risk_engine = risk_engine or DeterministicRiskEngine(
            attack_mapping_service=self.attack_mapping_service,
            threat_intel_service=self.threat_intel_service,
        )

    async def triage_incident(
        self,
        incident_id: str,
        db_session: Session,
        actor_id: str = "system:triage_agent",
        force_fallback: bool = False,
        persist: bool = True,
    ) -> TriageReport:
        """Execute bounded, evidence-grounded incident triage workflow."""
        incident = db_session.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        metrics.inc_counter("incident_triage_requests_total")
        tools = ReadOnlyInvestigationTools(session=db_session, incident_id=incident_id)
        validator = EvidenceValidator(session=db_session)

        # 1. Gather all verified contextual telemetry via ReadOnlyInvestigationTools
        tools.get_incident_summary()
        detections = tools.get_incident_detections()
        entities = tools.get_incident_entities()
        evidence_items = tools.get_incident_evidence()
        tools.get_incident_timeline()

        # 2. Compute or fetch authoritative deterministic risk assessment
        risk_data = tools.get_incident_risk_assessment()
        risk_score = float(risk_data.get("overall_score", 50.0))
        risk_band = str(risk_data.get("risk_band", "MEDIUM"))
        risk_policy_version = str(risk_data.get("policy_version", "1.0.0"))

        # 3. Gather ATT&CK context
        attack_findings: List[Dict[str, Any]] = []
        for det in detections:
            rule_id = det.get("rule_id", "")
            mappings = self.attack_mapping_service.get_mappings_for_rule(rule_id, db_session=db_session) if hasattr(self.attack_mapping_service, "get_mappings_for_rule") else []
            if not mappings:
                # Query catalog directly if rule has tags
                sigma_rule = None
                from services.detection.engine import detection_engine
                sigma_rule = detection_engine.get_rule(rule_id)
                tags = list(sigma_rule.tags) if sigma_rule and sigma_rule.tags else []
                for tag in tags:
                    m = self.attack_mapping_service.resolve_tag(tag, rule_id, "sigma")
                    if m.status == "valid":
                        attack_findings.append({
                            "technique_id": m.technique_id,
                            "tactic": m.tactic,
                            "technique_name": m.technique_name,
                            "detection_rule": rule_id,
                            "limitations": "Rule mapping context; corroboration depends on observed evidence",
                        })

        # 4. Gather Threat Intelligence context
        threat_intel_findings: List[Dict[str, Any]] = []
        for ent in entities:
            ent_type = ent.get("entity_type", "")
            ent_key = ent.get("entity_key", "")
            if ent_type.lower() in ("ip", "ipv4", "ipv6", "domain", "url", "hash", "sha256", "md5"):
                ti_result = tools.lookup_threat_intel(ent_type, ent_key)
                threat_intel_findings.append({
                    "indicator_type": ent_type,
                    "indicator_value": ent_key,
                    "reputation": ti_result.get("reputation", "unknown"),
                    "score": ti_result.get("score", 0.0),
                    "is_expired": ti_result.get("is_expired", False),
                    "provenance": ti_result.get("provenance", []),
                    "limitations": ti_result.get("limitations", "Absence of threat intelligence does not confirm benign status"),
                })

        # 5. Build prompt with injection isolation and heuristic detection
        untrusted_snippets: List[str] = []
        injection_detected = False

        for d in detections:
            raw_text = f"Detection ID: {d.get('detection_id')}, Rule: {d.get('rule_id')}, Severity: {d.get('severity')}"
            is_susp, reasons = detect_suspicious_directives(raw_text)
            if is_susp or any(h.search(raw_text) for h in INJECTION_HEURISTICS):
                injection_detected = True
            untrusted_snippets.append(format_untrusted_context("DETECTION", raw_text, source_id=d.get("detection_id"), incident_id=incident_id))

        for e in entities:
            raw_ent = f"Entity Type: {e.get('entity_type')}, Key: {e.get('entity_key')}, Relation: {e.get('relation')}"
            is_susp, reasons = detect_suspicious_directives(raw_ent)
            if is_susp or any(h.search(raw_ent) for h in INJECTION_HEURISTICS):
                injection_detected = True
            untrusted_snippets.append(format_untrusted_context("ENTITY", raw_ent, source_id=e.get("entity_key"), incident_id=incident_id))

        for ev in evidence_items:
            prov_str = json.dumps(ev.get("provenance", {}))
            raw_ev = f"Evidence ID: {ev.get('evidence_id')}, Type: {ev.get('evidence_type')}, Ref: {ev.get('source_ref')}, Data: {prov_str}"
            is_susp, reasons = detect_suspicious_directives(raw_ev)
            if is_susp or any(h.search(raw_ev) for h in INJECTION_HEURISTICS):
                injection_detected = True
            untrusted_snippets.append(format_untrusted_context("EVIDENCE", raw_ev, source_id=ev.get("evidence_id"), incident_id=incident_id))

        if injection_detected:
            metrics.inc_counter("prompt_injection_attempts_detected_total")
            logger.warning("Prompt injection heuristic triggered for incident %s; context strictly isolated", incident_id)

        prompt_body = (
            f"Incident ID: {incident.id}\n"
            f"Title: {incident.title}\n"
            f"Current Severity: {incident.severity}\n"
            f"Authoritative Risk Score: {risk_score} (Band: {risk_band}, Policy: v{risk_policy_version})\n"
            f"Detections Count: {len(detections)}\n"
            f"Entities Count: {len(entities)}\n"
            f"Evidence Items Count: {len(evidence_items)}\n"
            f"\n--- BEGIN UNTRUSTED INCIDENT TELEMETRY ---\n"
            f"{''.join(untrusted_snippets[:15])}\n"
            f"--- END UNTRUSTED INCIDENT TELEMETRY ---\n"
            f"\nGenerate structured triage output in valid JSON matching schema:\n"
            f"- summary (1-3 sentences)\n"
            f"- suspected_activity\n"
            f"- confidence (0.0 to 1.0)\n"
            f"- recommended_severity (informational, low, medium, high, critical)\n"
            f"- recommended_priority (P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW)\n"
            f"- cited_evidence_ids (list of EXACT detection or evidence IDs cited from above)\n"
            f"- contradictory_evidence (list)\n"
            f"- unresolved_questions (list)\n"
            f"- recommended_steps (list)\n"
            f"- data_gaps (list)\n"
            f"- uncertainties (list)\n"
        )
        prompt_body = sanitize_prompt_body(prompt_body)

        # 6. Execute Provider with Deterministic Fallback
        is_fallback = False
        raw_output: Dict[str, Any] = {}
        provider_used_info: ProviderInfo

        if force_fallback:
            is_fallback = True
            provider_used_info = self.fallback_provider.check_availability()
            raw_output = await self.fallback_provider.generate_json(
                system_prompt=SYSTEM_PROMPT_TEMPLATE,
                user_prompt=prompt_body,
                target_schema=TriageModelOutput,
            )
        else:
            try:
                # Check provider availability
                avail = self.provider.check_availability()
                if not avail.is_available:
                    raise LLMProviderError("Primary AI provider is not available or missing configuration.")

                provider_used_info = avail
                raw_output = await self.provider.generate_json(
                    system_prompt=SYSTEM_PROMPT_TEMPLATE,
                    user_prompt=prompt_body,
                    target_schema=TriageModelOutput,
                    timeout_seconds=30.0,
                )
            except Exception as ex:
                logger.warning("Primary AI provider failed for incident %s (%s); triggering deterministic fallback", incident_id, ex)
                metrics.inc_counter("triage_fallback_invocations_total")
                is_fallback = True
                provider_used_info = self.fallback_provider.check_availability()
                provider_used_info.metadata["fallback_trigger_reason"] = str(ex)
                raw_output = await self.fallback_provider.generate_json(
                    system_prompt=SYSTEM_PROMPT_TEMPLATE,
                    user_prompt=prompt_body,
                    target_schema=TriageModelOutput,
                )

        # 7. Normalize Model Output into TriageModelOutput schema
        try:
            model_out = TriageModelOutput(
                summary=raw_output.get("summary") or f"Triage assessment for {incident.title}",
                suspected_activity=raw_output.get("suspected_activity") or raw_output.get("suspected_category") or "general_security_alert",
                confidence=max(0.1, min(1.0, float(raw_output.get("confidence", 0.8)))),
                recommended_severity=self._parse_severity(raw_output.get("recommended_severity", incident.severity)),
                recommended_priority=str(raw_output.get("recommended_priority") or self._derive_priority(risk_band)),
                cited_evidence_ids=list(raw_output.get("cited_evidence_ids") or raw_output.get("supporting_evidence") or []),
                contradictory_evidence=list(raw_output.get("contradictory_evidence") or []),
                unresolved_questions=list(raw_output.get("unresolved_questions") or []),
                recommended_steps=list(raw_output.get("recommended_steps") or ["Review incident timeline and verify entities"]),
                data_gaps=list(raw_output.get("data_gaps") or raw_output.get("missing_evidence") or []),
                uncertainties=list(raw_output.get("uncertainties") or []),
            )
        except Exception as ve:
            logger.error("Failed to parse provider response into TriageModelOutput: %s", ve)
            # Safe recovery fallback
            model_out = TriageModelOutput(
                summary=f"Automated fallback triage assessment for {incident.title}",
                suspected_activity="unclassified_alert",
                confidence=0.5,
                recommended_severity=self._parse_severity(incident.severity),
                recommended_priority=self._derive_priority(risk_band),
                uncertainties=[f"Model output schema validation error: {ve}"],
            )

        # 8. Evidence Grounding & Anti-Hallucination Verification
        verified_evidence_refs: List[EvidenceReference] = []
        rejected_evidence_ids: List[str] = []

        for ref_id in model_out.cited_evidence_ids:
            is_valid, record_type, snippet = validator.validate_reference(incident_id, ref_id)
            if is_valid:
                verified_evidence_refs.append(
                    EvidenceReference(
                        evidence_id=ref_id,
                        source_type=record_type,
                        record_id=ref_id,
                        verified=True,
                        context_snippet=snippet,
                    )
                )
            else:
                rejected_evidence_ids.append(ref_id)

        # Handle unsupported evidence citations
        if rejected_evidence_ids:
            warning = f"Rejected {len(rejected_evidence_ids)} unsupported evidence references: {', '.join(rejected_evidence_ids)}"
            model_out.contradictory_evidence.append(warning)
            model_out.uncertainties.append(f"Rejected unsupported evidence references (unverified): {', '.join(rejected_evidence_ids)}")
            model_out.confidence = max(0.2, model_out.confidence - 0.2)

        if not verified_evidence_refs and not is_fallback:
            model_out.uncertainties.append("Zero supporting evidence references could be verified against authoritative records.")
            model_out.confidence = min(model_out.confidence, 0.5)

        if injection_detected:
            model_out.uncertainties.append("Prompt-injection markers (prompt injection) detected in untrusted logs; isolated from instructions.")

        # 9. Build Authoritative TriageReport
        triage_report = TriageReport(
            id=f"trg-{uuid4().hex[:24]}",
            incident_id=incident_id,
            lifecycle_state=incident.status,
            summary=model_out.summary,
            suspected_activity=model_out.suspected_activity,
            confidence=round(model_out.confidence, 2),
            recommended_severity=model_out.recommended_severity,
            recommended_priority=model_out.recommended_priority,
            supporting_evidence=verified_evidence_refs,
            contradictory_evidence=model_out.contradictory_evidence,
            unresolved_questions=model_out.unresolved_questions,
            attack_techniques=attack_findings,
            threat_intel_findings=threat_intel_findings,
            risk_assessment={
                "overall_score": risk_score,
                "risk_band": risk_band,
                "policy_version": risk_policy_version,
                "authoritative_source": "DeterministicRiskEngine",
            },
            recommended_steps=model_out.recommended_steps,
            data_gaps=model_out.data_gaps,
            uncertainties=model_out.uncertainties,
            requires_analyst_review=True,
            provider_info=provider_used_info,
            is_fallback=is_fallback,
            triage_policy_version="1.0.0",
            created_at=utc_now(),
        )

        # 10. Persistence & Audit
        if persist:
            self._persist_triage_assessment(triage_report, db_session, actor_id)

        metrics.inc_counter(f"incident_triage_completed_{triage_report.recommended_priority.lower()}_total")
        return triage_report

    def _parse_severity(self, sev_raw: Any) -> EventSeverityEnum:
        try:
            return EventSeverityEnum(str(sev_raw).lower())
        except Exception:
            return EventSeverityEnum.MEDIUM

    def _derive_priority(self, risk_band: str) -> str:
        mapping = {
            "CRITICAL": "P1_CRITICAL",
            "HIGH": "P2_HIGH",
            "MEDIUM": "P3_MEDIUM",
            "LOW": "P4_LOW",
        }
        return mapping.get(risk_band.upper(), "P3_MEDIUM")

    def _persist_triage_assessment(
        self, report: TriageReport, db_session: Session, actor_id: str
    ) -> None:
        """Persist structured triage assessment and record immutable audit event."""
        model = IncidentTriageAssessmentModel(
            id=report.id,
            incident_id=report.incident_id,
            summary=report.summary,
            suspected_activity=report.suspected_activity,
            confidence=report.confidence,
            recommended_severity=report.recommended_severity.value,
            recommended_priority=report.recommended_priority,
            supporting_evidence_json=[e.model_dump() for e in report.supporting_evidence],
            contradictory_evidence_json=report.contradictory_evidence,
            unresolved_questions_json=report.unresolved_questions,
            attack_techniques_json=report.attack_techniques,
            threat_intel_json=report.threat_intel_findings,
            risk_score=report.risk_assessment.get("overall_score", 0.0),
            risk_band=report.risk_assessment.get("risk_band", "LOW"),
            risk_policy_version=report.risk_assessment.get("policy_version", "1.0.0"),
            recommended_steps_json=report.recommended_steps,
            data_gaps_json=report.data_gaps,
            uncertainties_json=report.uncertainties,
            requires_analyst_review=report.requires_analyst_review,
            provider_info_json=report.provider_info.model_dump() if hasattr(report.provider_info, "model_dump") else report.provider_info,
            is_fallback=report.is_fallback,
            triage_policy_version=report.triage_policy_version,
            assessed_by=actor_id,
            created_at=report.created_at,
        )
        db_session.add(model)

        audit = AuditEvent(
            id=str(uuid4()),
            actor_type="AGENT" if actor_id == "system:triage_agent" else "USER",
            actor_id=actor_id,
            action="incident:triage_completed",
            object_type="incident",
            object_id=report.incident_id,
            outcome="SUCCESS",
            reason_code="TRIAGE_AGENT_EVALUATION",
            occurred_at=utc_now(),
            metadata_redacted={
                "triage_id": report.id,
                "suspected_activity": report.suspected_activity,
                "recommended_priority": report.recommended_priority,
                "is_fallback": report.is_fallback,
                "risk_score": report.risk_assessment.get("overall_score"),
            },
        )
        db_session.add(audit)
        db_session.commit()
        logger.info(
            "Persisted triage assessment '%s' for incident '%s' (Priority: %s, Fallback: %s)",
            report.id,
            report.incident_id,
            report.recommended_priority,
            report.is_fallback,
        )
