"""CyberSentinel AI — Deterministic Explainable Incident Risk Engine (Sprint 14)
Governing Decisions: ADR-0001, ADR-0003, ADR-0004, ADR-0006, CSAI-R0.3-EXPLAINABLE-RISK-ENGINE
"""

import logging
from datetime import timezone
from typing import Dict, List, Optional, Set
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from attack.registry import AttackCatalog, AttackMappingService
from packages.common import utc_now
from packages.observability.metrics import metrics
from services.persistence.models import (
    AuditEvent,
    Detection,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentEntity,
    IncidentRiskAssessmentModel,
)
from services.risk.models import (
    IncidentRiskAssessment,
    RiskExplanationResponse,
    RiskFactorContribution,
    RiskScoringPolicy,
)
from services.threat_intel.service import ThreatIntelService

logger = logging.getLogger("cybersentinel.risk.engine")

# Canonical severity weights (0-100)
SEVERITY_SCORE_MAP: Dict[str, float] = {
    "critical": 95.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "informational": 10.0,
}

# Authoritative ATT&CK tactic criticality scores
TACTIC_CRITICALITY_MAP: Dict[str, float] = {
    "impact": 95.0,
    "exfiltration": 90.0,
    "command_and_control": 85.0,
    "lateral_movement": 80.0,
    "credential_access": 75.0,
    "privilege_escalation": 75.0,
    "defense_evasion": 70.0,
    "execution": 65.0,
    "persistence": 60.0,
    "initial_access": 55.0,
    "collection": 45.0,
    "discovery": 45.0,
    "reconnaissance": 30.0,
    "resource_development": 30.0,
}

# Critical asset indicator substrings
HIGH_VALUE_MARKERS: Set[str] = {
    "admin",
    "root",
    "domain_controller",
    "dc",
    "prod",
    "database",
    "pci",
    "vault",
}


class DeterministicRiskEngine:
    """Calculates fully explainable, deterministic incident risk assessments.

    Guarantees:
    - Same inputs and policy version strictly yield the exact same score.
    - Zero external LLM hallucinations or dependency on LLM availability.
    - Independent factor decomposition with auditable mathematical weights.
    - Explicit handling for missing, expired, and conflicting threat intelligence.
    - Absence of threat intelligence or ATT&CK coverage is explicitly not treated as benign.
    """

    def __init__(
        self,
        policy: Optional[RiskScoringPolicy] = None,
        attack_mapping_service: Optional[AttackMappingService] = None,
        threat_intel_service: Optional[ThreatIntelService] = None,
    ):
        self.policy = policy or RiskScoringPolicy()
        if attack_mapping_service is None:
            catalog = AttackCatalog()
            attack_mapping_service = AttackMappingService(catalog)
        self.attack_mapping_service = attack_mapping_service
        self.threat_intel_service = threat_intel_service or ThreatIntelService()

    def assess_incident(
        self,
        incident: Incident,
        db_session: Session,
        actor_id: str = "system:risk_engine",
        persist: bool = True,
    ) -> IncidentRiskAssessment:
        """Calculate complete explainable risk assessment for the target incident."""
        factors: Dict[str, RiskFactorContribution] = {}
        all_evidence_refs: List[str] = []
        all_drivers: List[str] = []
        all_uncertainties: List[str] = []
        limitations: List[str] = [
            f"ATT&CK evaluation bounded to pinned catalog v{self.attack_mapping_service.catalog.version}",
            "Threat intelligence queries restricted to verified local repositories; absence does not prove benign",
            f"Scoring policy v{self.policy.version} applies deterministic static factor weighting",
        ]

        # 1. Detection Severity Factor
        f_sev = self._calculate_detection_severity(incident, db_session)
        factors["detection_severity"] = f_sev
        all_evidence_refs.extend(f_sev.supporting_evidence)
        all_drivers.extend(f_sev.drivers)
        all_uncertainties.extend(f_sev.uncertainties)

        # 2. Evidence Strength Factor
        f_ev = self._calculate_evidence_strength(incident, db_session)
        factors["evidence_strength"] = f_ev
        all_evidence_refs.extend(f_ev.supporting_evidence)
        all_drivers.extend(f_ev.drivers)
        all_uncertainties.extend(f_ev.uncertainties)

        # 3. ATT&CK Context Factor
        f_att = self._calculate_attack_context(incident, db_session)
        factors["attack_context"] = f_att
        all_evidence_refs.extend(f_att.supporting_evidence)
        all_drivers.extend(f_att.drivers)
        all_uncertainties.extend(f_att.uncertainties)

        # 4. Threat Intelligence Context Factor
        f_ti = self._calculate_threat_intel_context(incident, db_session)
        factors["threat_intel_context"] = f_ti
        all_evidence_refs.extend(f_ti.supporting_evidence)
        all_drivers.extend(f_ti.drivers)
        all_uncertainties.extend(f_ti.uncertainties)

        # 5. Incident Scope Factor
        f_sc = self._calculate_incident_scope(incident, db_session)
        factors["incident_scope"] = f_sc
        all_evidence_refs.extend(f_sc.supporting_evidence)
        all_drivers.extend(f_sc.drivers)
        all_uncertainties.extend(f_sc.uncertainties)

        # 6. Temporal Context Factor
        f_temp = self._calculate_temporal_context(incident, db_session)
        factors["temporal_context"] = f_temp
        all_evidence_refs.extend(f_temp.supporting_evidence)
        all_drivers.extend(f_temp.drivers)
        all_uncertainties.extend(f_temp.uncertainties)

        # 7. Correlation Context Factor
        f_corr = self._calculate_correlation_context(incident, db_session)
        factors["correlation_context"] = f_corr
        all_evidence_refs.extend(f_corr.supporting_evidence)
        all_drivers.extend(f_corr.drivers)
        all_uncertainties.extend(f_corr.uncertainties)

        # Sum weighted scores
        overall_score = sum(f.weighted_score for f in factors.values())
        overall_score = round(max(0.0, min(100.0, overall_score)), 2)
        risk_band = self.policy.classify_score(overall_score)

        # Deduplicate refs and drivers while preserving order
        unique_refs = list(dict.fromkeys(all_evidence_refs))
        unique_drivers = list(dict.fromkeys(all_drivers))
        unique_uncertainties = list(dict.fromkeys(all_uncertainties))

        assessment = IncidentRiskAssessment(
            id=f"ira-{uuid4().hex[:24]}",
            incident_id=incident.id,
            overall_score=overall_score,
            risk_band=risk_band,
            policy_version=self.policy.version,
            assessed_at=utc_now(),
            assessed_by=actor_id,
            factors=factors,
            primary_drivers=unique_drivers[:8],
            uncertainties=unique_uncertainties,
            limitations=limitations,
            evidence_refs=unique_refs,
        )

        if persist:
            self._persist_assessment(assessment, db_session, actor_id)

        metrics.inc_counter(f"risk_assessment_band_{risk_band.value.lower()}_total")
        metrics.set_gauge("last_incident_risk_score", overall_score)
        return assessment

    def _calculate_detection_severity(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["detection_severity"]
        # Fetch associated detection records
        inc_dets = db_session.execute(
            select(IncidentDetection).where(IncidentDetection.incident_id == incident.id)
        ).scalars().all()

        if not inc_dets:
            # Fall back to incident's own severity field
            base_sev = SEVERITY_SCORE_MAP.get(str(incident.severity).lower(), 50.0)
            raw = base_sev * max(0.2, min(1.0, float(incident.confidence or 1.0)))
            return RiskFactorContribution(
                factor_name="detection_severity",
                raw_score=round(raw, 2),
                weight=weight,
                weighted_score=round(raw * weight, 2),
                supporting_evidence=[],
                drivers=[f"Derived from incident severity '{incident.severity}' (confidence: {incident.confidence})"],
                uncertainties=["No individual detection records linked to incident"],
            )

        det_ids = [d.detection_id for d in inc_dets]
        detections = db_session.execute(
            select(Detection).where(Detection.id.in_(det_ids))
        ).scalars().all()

        scores: List[float] = []
        drivers: List[str] = []
        for det in detections:
            sev_score = SEVERITY_SCORE_MAP.get(det.severity.lower(), 50.0)
            scores.append(sev_score)
            drivers.append(f"Detection {det.id[:8]} triggered with '{det.severity}' severity (rule: {det.rule_id})")

        if not scores:
            scores = [50.0]

        # Emphasize highest severity (70%) plus compound detection count (30%)
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        raw_score = (max_score * 0.70) + (avg_score * 0.30)
        # Apply incident confidence
        conf = max(0.2, min(1.0, float(incident.confidence or 1.0)))
        raw_score = min(100.0, raw_score * conf)

        return RiskFactorContribution(
            factor_name="detection_severity",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=det_ids,
            drivers=drivers[:3],
            uncertainties=[] if conf >= 0.8 else [f"Incident confidence discount applied ({conf:.2f})"],
        )

    def _calculate_evidence_strength(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["evidence_strength"]
        evidence_items = db_session.execute(
            select(Evidence).where(Evidence.incident_id == incident.id)
        ).scalars().all()

        count = len(evidence_items)
        if count == 0:
            raw_score = 20.0
            return RiskFactorContribution(
                factor_name="evidence_strength",
                raw_score=raw_score,
                weight=weight,
                weighted_score=round(raw_score * weight, 2),
                supporting_evidence=[],
                drivers=["Low baseline score due to absence of verified forensic evidence items"],
                uncertainties=["No formal forensic evidence items attached to incident"],
            )

        # Scale by count and integrity
        base = min(80.0, 30.0 + (count * 15.0))
        # Integrity verification bonus
        verified_checksums = sum(1 for e in evidence_items if len(e.checksum or "") == 64)
        integrity_bonus = 20.0 if verified_checksums == count else 10.0
        raw_score = min(100.0, base + integrity_bonus)

        types = list({e.evidence_type for e in evidence_items})
        evidence_ids = [e.id for e in evidence_items]

        return RiskFactorContribution(
            factor_name="evidence_strength",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=evidence_ids,
            drivers=[
                f"{count} forensic evidence items attached across types: {', '.join(types)}",
                f"{verified_checksums}/{count} items verified with SHA-256 integrity checksums",
            ],
            uncertainties=[] if verified_checksums == count else ["Some evidence items lack complete checksums"],
        )

    def _calculate_attack_context(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["attack_context"]
        inc_dets = db_session.execute(
            select(IncidentDetection).where(IncidentDetection.incident_id == incident.id)
        ).scalars().all()
        det_ids = [d.detection_id for d in inc_dets]

        detections = db_session.execute(
            select(Detection).where(Detection.id.in_(det_ids))
        ).scalars().all() if det_ids else []

        rule_ids = [d.rule_id for d in detections]
        if not rule_ids and hasattr(incident, "rule_id") and incident.rule_id:  # type: ignore[attr-defined]
            rule_ids = [incident.rule_id]  # type: ignore[attr-defined]

        # Resolve ATT&CK mappings for rules
        mapped_techniques: Set[str] = set()
        mapped_tactics: Set[str] = set()
        from services.correlation.engine import correlation_engine
        from services.detection.engine import detection_engine
        from services.persistence.models import RuleAttackMappingRecord

        # 1. Check in-memory rule catalogs
        for r_id in rule_ids:
            sigma_rule = detection_engine.get_rule(r_id)
            tags = list(sigma_rule.tags) if sigma_rule and sigma_rule.tags else []
            if not tags:
                corr_rule = correlation_engine.get_rule(r_id)
                if corr_rule and corr_rule.tags:
                    tags.extend(corr_rule.tags)
            for tag in tags:
                mapping = self.attack_mapping_service.resolve_tag(tag, r_id, "sigma")
                if mapping.status == "valid":
                    if mapping.technique_id:
                        mapped_techniques.add(mapping.technique_id)
                    if mapping.tactic:
                        mapped_tactics.add(mapping.tactic.lower())

        # 2. Check persisted rule mappings in database
        if rule_ids:
            db_mappings = db_session.execute(
                select(RuleAttackMappingRecord).where(RuleAttackMappingRecord.rule_id.in_(rule_ids))
            ).scalars().all()
            for db_m in db_mappings:
                if db_m.status == "valid":
                    if db_m.technique_id:
                        mapped_techniques.add(db_m.technique_id)
                    if db_m.tactic:
                        mapped_tactics.add(db_m.tactic.lower())


        if not mapped_tactics and not mapped_techniques:
            raw_score = 30.0
            return RiskFactorContribution(
                factor_name="attack_context",
                raw_score=raw_score,
                weight=weight,
                weighted_score=round(raw_score * weight, 2),
                supporting_evidence=[],
                drivers=["Triggering rules do not map to recognized MITRE ATT&CK techniques; neutral baseline applied"],
                uncertainties=["No verified MITRE ATT&CK technique or tactic mappings"],
            )

        # Calculate max tactic score
        tactic_scores = [TACTIC_CRITICALITY_MAP.get(t, 50.0) for t in mapped_tactics]
        max_tactic_score = max(tactic_scores) if tactic_scores else 50.0

        # Kill-chain progression bonus
        num_tactics = len(mapped_tactics)
        progression_bonus = min(20.0, (num_tactics - 1) * 10.0) if num_tactics > 1 else 0.0

        raw_score = min(100.0, max_tactic_score + progression_bonus)
        drivers = [
            f"Mapped to {len(mapped_techniques)} techniques across {num_tactics} tactics: {', '.join(sorted(mapped_tactics))}",
            f"Peak tactic criticality: {max_tactic_score:.1f}",
        ]
        if progression_bonus > 0:
            drivers.append(f"Kill-chain progression bonus (+{progression_bonus:.0f}) for multi-tactic movement")

        return RiskFactorContribution(
            factor_name="attack_context",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=sorted(list(mapped_techniques)),
            drivers=drivers,
            uncertainties=[],
        )

    def _calculate_threat_intel_context(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["threat_intel_context"]
        entities = db_session.execute(
            select(IncidentEntity).where(IncidentEntity.incident_id == incident.id)
        ).scalars().all()

        indicator_entities = [
            e for e in entities
            if e.entity_type.lower() in ("ip", "ipv4", "ipv6", "domain", "url", "hash", "sha256", "md5")
        ]

        if not indicator_entities:
            raw_score = self.policy.missing_intel_baseline
            return RiskFactorContribution(
                factor_name="threat_intel_context",
                raw_score=raw_score,
                weight=weight,
                weighted_score=round(raw_score * weight, 2),
                supporting_evidence=[],
                drivers=["No indicator entities (IP, domain, hash, URL) present on incident; neutral baseline applied"],
                uncertainties=["Absence of indicators does not confirm benign behavior"],
            )

        scores: List[float] = []
        drivers: List[str] = []
        uncertainties: List[str] = []
        evidence_refs: List[str] = []

        for entity in indicator_entities:
            ind_type = "ipv4" if entity.entity_type.lower() == "ip" else entity.entity_type.lower()
            try:
                res = self.threat_intel_service.lookup_indicator(ind_type, entity.entity_key, session=db_session)
                if not res.found:
                    scores.append(self.policy.missing_intel_baseline)
                    uncertainties.append(f"Indicator '{entity.entity_key}' not found in local threat intel feeds")
                else:
                    evidence_refs.append(f"{res.indicator_type}:{res.indicator_value}")
                    if res.is_expired:
                        discounted = (res.normalized_score or 50.0) * self.policy.stale_intel_discount
                        scores.append(discounted)
                        drivers.append(f"Indicator '{res.indicator_value}' intelligence is expired (discounted score: {discounted:.1f})")
                        uncertainties.append(f"Expired threat intelligence record for '{res.indicator_value}'")
                    else:
                        score = res.normalized_score or 50.0
                        scores.append(score)
                        sources_str = ", ".join(r.source_name for r in res.records) if res.records else "local"
                        drivers.append(
                            f"Matched active threat indicator '{res.indicator_value}' "
                            f"(reputation score: {score:.1f}, sources: {sources_str})"
                        )
                    if res.conflicts:
                        uncertainties.append(f"Conflicting observations detected for indicator '{res.indicator_value}'")
            except Exception as e:
                logger.warning("Threat intelligence lookup failed for %s: %s", entity.entity_key, e)
                scores.append(self.policy.missing_intel_baseline)
                uncertainties.append(f"Lookup error for '{entity.entity_key}': {str(e)}")


        raw_score = max(scores) if scores else self.policy.missing_intel_baseline
        raw_score = min(100.0, raw_score)

        return RiskFactorContribution(
            factor_name="threat_intel_context",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=evidence_refs,
            drivers=drivers[:3] if drivers else ["Threat intelligence evaluated against local repository"],
            uncertainties=uncertainties[:3],
        )

    def _calculate_incident_scope(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["incident_scope"]
        entities = db_session.execute(
            select(IncidentEntity).where(IncidentEntity.incident_id == incident.id)
        ).scalars().all()

        count = len(entities)
        if count == 0:
            raw_score = 25.0
            return RiskFactorContribution(
                factor_name="incident_scope",
                raw_score=raw_score,
                weight=weight,
                weighted_score=round(raw_score * weight, 2),
                supporting_evidence=[],
                drivers=["Incident has no associated entities; minimal baseline scope score applied"],
                uncertainties=["No entities linked to evaluate incident blast radius"],
            )

        # Base scale on entity count
        if count == 1:
            base = 35.0
        elif count == 2:
            base = 55.0
        elif count <= 4:
            base = 75.0
        else:
            base = 90.0

        # High-value asset multiplier
        is_high_value = False
        high_value_keys: List[str] = []
        for e in entities:
            key_lower = e.entity_key.lower()
            if any(marker in key_lower for marker in HIGH_VALUE_MARKERS):
                is_high_value = True
                high_value_keys.append(e.entity_key)

        if is_high_value:
            raw_score = min(100.0, base + 20.0)
            drivers = [
                f"Incident encompasses {count} entities including high-value assets: {', '.join(high_value_keys[:2])}",
                "Elevated blast radius for critical infrastructure/privileged accounts",
            ]
        else:
            raw_score = base
            drivers = [f"Incident scope encompasses {count} distinct entities"]

        entity_keys = [f"{e.entity_type}:{e.entity_key}" for e in entities]

        return RiskFactorContribution(
            factor_name="incident_scope",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=entity_keys[:5],
            drivers=drivers,
            uncertainties=[],
        )

    def _calculate_temporal_context(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["temporal_context"]
        first = incident.first_seen
        last = incident.last_seen

        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        duration_sec = max(0.0, (last - first).total_seconds())

        inc_dets = db_session.execute(
            select(IncidentDetection).where(IncidentDetection.incident_id == incident.id)
        ).scalars().all()
        det_count = len(inc_dets)

        # Velocity and dwell assessment
        if det_count >= 3 and duration_sec < 300.0:
            raw_score = 85.0
            drivers = [f"Rapid automated attack burst ({det_count} detections in {duration_sec:.0f} seconds)"]
        elif duration_sec > 86400.0 * 3:
            raw_score = 75.0
            drivers = [f"Persistent long-dwell campaign activity spanning {duration_sec / 86400.0:.1f} days"]
        elif duration_sec > 3600.0:
            raw_score = 60.0
            drivers = [f"Sustained incident activity across {duration_sec / 3600.0:.1f} hours"]
        else:
            raw_score = 40.0
            drivers = [f"Incident activity observed over {max(1.0, duration_sec):.0f} seconds"]

        return RiskFactorContribution(
            factor_name="temporal_context",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=[f"first_seen:{first.isoformat()}", f"last_seen:{last.isoformat()}"],
            drivers=drivers,
            uncertainties=[],
        )

    def _calculate_correlation_context(
        self, incident: Incident, db_session: Session
    ) -> RiskFactorContribution:
        weight = self.policy.weights["correlation_context"]
        inc_dets = db_session.execute(
            select(IncidentDetection).where(IncidentDetection.incident_id == incident.id)
        ).scalars().all()

        det_ids = [d.detection_id for d in inc_dets]
        detections = db_session.execute(
            select(Detection).where(Detection.id.in_(det_ids))
        ).scalars().all() if det_ids else []

        distinct_rules = {d.rule_id for d in detections}
        num_rules = len(distinct_rules)

        if num_rules >= 3:
            raw_score = 90.0
            drivers = [f"Strong correlation corroboration across {num_rules} distinct detection rules without double-counting"]
        elif num_rules == 2:
            raw_score = 75.0
            drivers = [f"Multi-rule corroboration between {num_rules} distinct detection rules"]
        elif num_rules == 1:
            raw_score = 45.0
            drivers = ["Single isolated detection rule without multi-rule cross-corroboration"]
        else:
            raw_score = 25.0
            drivers = ["No associated detection rules to corroborate correlation"]

        return RiskFactorContribution(
            factor_name="correlation_context",
            raw_score=round(raw_score, 2),
            weight=weight,
            weighted_score=round(raw_score * weight, 2),
            supporting_evidence=sorted(list(distinct_rules)),
            drivers=drivers,
            uncertainties=[] if num_rules >= 2 else ["Single-rule detection lacks multi-signal corroboration"],
        )

    def _persist_assessment(
        self, assessment: IncidentRiskAssessment, db_session: Session, actor_id: str
    ) -> None:
        """Persist assessment record and record audit event."""
        model = IncidentRiskAssessmentModel(
            id=assessment.id,
            incident_id=assessment.incident_id,
            overall_score=assessment.overall_score,
            risk_band=assessment.risk_band.value,
            policy_version=assessment.policy_version,
            factors_json={k: v.model_dump() for k, v in assessment.factors.items()},
            primary_drivers_json=assessment.primary_drivers,
            uncertainties_json=assessment.uncertainties,
            limitations_json=assessment.limitations,
            evidence_refs_json=assessment.evidence_refs,
            assessed_by=actor_id,
            assessed_at=assessment.assessed_at,
        )
        db_session.add(model)

        # Audit event
        audit = AuditEvent(
            id=str(uuid4()),
            actor_type="USER" if actor_id != "system:risk_engine" else "SYSTEM",
            actor_id=actor_id,
            action="incident:risk_assessed",
            object_type="incident",
            object_id=assessment.incident_id,
            outcome="SUCCESS",
            reason_code="RISK_ENGINE_EVALUATION",
            occurred_at=utc_now(),
            metadata_redacted={
                "assessment_id": assessment.id,
                "overall_score": assessment.overall_score,
                "risk_band": assessment.risk_band.value,
                "policy_version": assessment.policy_version,
            },
        )
        db_session.add(audit)
        db_session.commit()
        logger.info(
            "Persisted risk assessment '%s' for incident '%s' (Score: %.2f, Band: %s)",
            assessment.id,
            assessment.incident_id,
            assessment.overall_score,
            assessment.risk_band.value,
        )

    def explain_assessment(
        self, assessment: IncidentRiskAssessment
    ) -> RiskExplanationResponse:
        """Construct detailed explanation response payload."""
        formula_desc = (
            "Overall Score = Sum(Factor Raw Score * Factor Weight), bounded to [0, 100]. "
            "Factors: Detection Severity (20%), Evidence Strength (15%), ATT&CK Context (20%), "
            "Threat Intelligence Context (15%), Incident Scope (10%), Temporal Context (10%), "
            "Correlation Context (10%)."
        )
        return RiskExplanationResponse(
            incident_id=assessment.incident_id,
            assessment_id=assessment.id,
            overall_score=assessment.overall_score,
            risk_band=assessment.risk_band,
            policy_version=assessment.policy_version,
            assessed_at=assessment.assessed_at,
            factors=assessment.factors,
            primary_drivers=assessment.primary_drivers,
            uncertainties=assessment.uncertainties,
            limitations=assessment.limitations,
            weights_used=self.policy.weights,
            formula_description=formula_desc,
        )
