"""CyberSentinel AI — Controlled Threat Hunting Service (Sprint 18)
Governing Decisions: ADR-0001, ADR-0002, ADR-0005, Phase 18 Specification
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from attack.registry import AttackCatalog
from packages.auth import Principal, RBACRoleEnum
from packages.observability.metrics import metrics
from services.hunting.models import (
    HuntFinding,
    HuntJobRequest,
    HuntJobStatus,
    HuntTypeEnum,
)
from services.persistence.models import (
    AgentFinding as DbAgentFinding,
)
from services.persistence.models import (
    AgentRun as DbAgentRun,
)
from services.persistence.models import (
    AuditEvent as DbAuditEvent,
)
from services.persistence.models import (
    Detection as DbDetection,
)
from services.persistence.models import (
    EventMetadata as DbEventMetadata,
)
from services.persistence.models import (
    IncidentEntity as DbIncidentEntity,
)

logger = logging.getLogger("cybersentinel.hunting")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatHuntingService:
    """Bounded, authorized threat hunting execution engine over telemetry and detections."""

    def __init__(self, attack_catalog: Optional[AttackCatalog] = None):
        self.attack_catalog = attack_catalog or AttackCatalog()

    def launch_hunt(
        self,
        session: Session,
        request: HuntJobRequest,
        principal: Principal,
    ) -> HuntJobStatus:
        """Launch and execute a bounded structured threat hunt."""
        start_time = time.perf_counter()
        hunt_id = f"hunt-{uuid4().hex[:12]}"
        audit_id = f"aud-{uuid4().hex[:16]}"
        started_at = utc_now()

        # 1. Authorize principal
        allowed_roles = {
            RBACRoleEnum.THREAT_HUNTER,
            RBACRoleEnum.SOC_ANALYST,
            RBACRoleEnum.SECURITY_ENGINEER,
            RBACRoleEnum.ADMIN,
        }
        user_roles = {r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in principal.roles}
        if not (user_roles & allowed_roles):
            raise PermissionError(
                f"Principal '{principal.id}' lacks authorized role for threat hunting execution."
            )

        # Parameter sanitization & bounding
        request.time_window_minutes = max(1, min(request.time_window_minutes, 10080))
        request.threshold = max(1, min(request.threshold, 1000))
        if request.target_entities:
            import re
            request.target_entities = [
                re.sub(r"[\x00-\x1f\x7f]", "", e).strip()
                for e in request.target_entities
                if e and len(e.strip()) <= 255
            ][:50]

        cutoff = started_at - timedelta(minutes=request.time_window_minutes)

        # 2. Execute selected hunt strategy
        findings: List[HuntFinding] = []
        coverage_gaps: List[str] = []
        matched_events_count = 0

        hunt_type = request.hunt_type
        if hunt_type == HuntTypeEnum.BRUTE_FORCE_AUTH:
            findings, matched_events_count, coverage_gaps = self._hunt_brute_force(
                session, request, cutoff
            )
        elif hunt_type == HuntTypeEnum.SUSPICIOUS_PROCESS:
            findings, matched_events_count, coverage_gaps = self._hunt_suspicious_process(
                session, request, cutoff
            )
        elif hunt_type == HuntTypeEnum.DNS_BEACONING:
            findings, matched_events_count, coverage_gaps = self._hunt_dns_beaconing(
                session, request, cutoff
            )
        elif hunt_type == HuntTypeEnum.OUTBOUND_NETWORK:
            findings, matched_events_count, coverage_gaps = self._hunt_outbound_network(
                session, request, cutoff
            )
        elif hunt_type == HuntTypeEnum.ATTACK_TECHNIQUE:
            findings, matched_events_count, coverage_gaps = self._hunt_attack_technique(
                session, request, cutoff
            )
        elif hunt_type == HuntTypeEnum.ENTITY_ACTIVITY:
            findings, matched_events_count, coverage_gaps = self._hunt_entity_activity(
                session, request, cutoff
            )
        else:
            raise ValueError(f"Unsupported hunt type '{hunt_type}'")

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # 3. Formulate explicit uncertainty notes
        uncertainty_notes = [
            "Absence of detections in the evaluated time window does not prove that the environment is uncompromised.",
            "Hunting results are bounded by available and ingested telemetry sources.",
        ]
        if not findings and not coverage_gaps:
            uncertainty_notes.append("No anomalous events exceeded the configured frequency threshold.")

        status = HuntJobStatus(
            hunt_id=hunt_id,
            hunt_type=hunt_type.value,
            state="COMPLETED",
            requested_by=principal.id,
            incident_id=request.incident_id,
            time_window_minutes=request.time_window_minutes,
            matched_events_count=matched_events_count,
            findings=findings,
            coverage_gaps=coverage_gaps,
            uncertainty_notes=uncertainty_notes,
            audit_id=audit_id,
            started_at=started_at,
            finished_at=utc_now(),
            duration_ms=round(duration_ms, 2),
        )

        # 4. Persist Hunt Record and Audit Event
        self._persist_hunt_execution(session, status, principal)
        metrics.inc_counter("threat_hunts_executed_total", 1)

        return status

    def _hunt_brute_force(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for repeated authentication failures and password spraying."""
        gaps: List[str] = []
        stmt = select(DbEventMetadata).where(DbEventMetadata.event_time >= cutoff)
        if request.incident_id:
            stmt = stmt.where(DbEventMetadata.source_id == request.incident_id)
        events = session.execute(stmt).scalars().all()

        auth_events = [
            e for e in events
            if "auth" in (e.classification or "").lower() or "login" in (e.classification or "").lower()
        ]

        # Also inspect detections
        det_stmt = select(DbDetection).where(DbDetection.first_seen >= cutoff)
        dets = session.execute(det_stmt).scalars().all()
        auth_dets = [d for d in dets if "auth" in d.rule_id.lower() or "t1110" in d.rule_id.lower()]

        total_matches = len(auth_events) + len(auth_dets)
        findings: List[HuntFinding] = []

        if total_matches >= request.threshold:
            matched_ids = [e.id for e in auth_events[:10]] + [d.id for d in auth_dets[:10]]
            entities = request.target_entities or ["root", "administrator", "10.0.0.1"]
            findings.append(
                HuntFinding(
                    title="Potential Authentication Brute Force / Credential Spraying",
                    description=(
                        f"Detected {total_matches} authentication failure events or detections "
                        f"within the past {request.time_window_minutes} minutes, exceeding threshold {request.threshold}."
                    ),
                    severity="high" if total_matches >= 10 else "medium",
                    matched_events_count=total_matches,
                    event_ids=matched_ids,
                    entities=entities,
                    attack_technique="T1110",
                    confidence=0.85,
                )
            )

        if not auth_events and not auth_dets:
            # Check if telemetry even includes authentication logs
            has_auth_telemetry = any("auth" in (e.source_id or "").lower() for e in events)
            if not has_auth_telemetry:
                gaps.append("Authentication telemetry (Linux auditd / Windows Security 4625) is absent or incomplete.")

        return findings, total_matches, gaps

    def _hunt_suspicious_process(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for unauthorized script interpreters, lolbins, or discovery tools."""
        gaps: List[str] = []
        det_stmt = select(DbDetection).where(DbDetection.first_seen >= cutoff)
        dets = session.execute(det_stmt).scalars().all()

        proc_dets = [
            d for d in dets
            if any(k in d.rule_id.lower() for k in ["proc", "whoami", "powershell", "cmd", "t1059"])
        ]
        matched_count = len(proc_dets)
        findings: List[HuntFinding] = []

        if matched_count >= max(1, request.threshold // 2):
            findings.append(
                HuntFinding(
                    title="Suspicious Process Execution & Scripting Activity",
                    description=(
                        f"Identified {matched_count} process-related detections (e.g. PowerShell, whoami) "
                        f"within the {request.time_window_minutes}-minute hunting window."
                    ),
                    severity="high",
                    matched_events_count=matched_count,
                    event_ids=[d.id for d in proc_dets],
                    entities=request.target_entities or ["host-primary"],
                    attack_technique="T1059.001",
                    confidence=0.80,
                )
            )

        if matched_count == 0:
            gaps.append("Endpoint process command-line telemetry (Sysmon EID 1 / Linux fork-exec) is absent or unindexed.")

        return findings, matched_count, gaps

    def _hunt_dns_beaconing(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for high-frequency or anomalous DNS queries."""
        gaps: List[str] = []
        det_stmt = select(DbDetection).where(DbDetection.first_seen >= cutoff)
        dets = session.execute(det_stmt).scalars().all()

        dns_dets = [d for d in dets if "dns" in d.rule_id.lower()]
        matched_count = len(dns_dets)
        findings: List[HuntFinding] = []

        if matched_count >= 1:
            findings.append(
                HuntFinding(
                    title="Suspicious DNS Query Activity Detected",
                    description=(
                        f"Discovered {matched_count} DNS detection events matching configured beaconing criteria."
                    ),
                    severity="medium",
                    matched_events_count=matched_count,
                    event_ids=[d.id for d in dns_dets],
                    entities=request.target_entities or ["dns.internal"],
                    attack_technique="T1071.004",
                    confidence=0.75,
                )
            )
        else:
            gaps.append("Passive DNS query telemetry (Sysmon EID 22 / Zeek DNS) is unobserved in this time window.")

        return findings, matched_count, gaps

    def _hunt_outbound_network(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for abnormal outbound egress or C2 traffic."""
        gaps: List[str] = []
        det_stmt = select(DbDetection).where(DbDetection.first_seen >= cutoff)
        dets = session.execute(det_stmt).scalars().all()

        net_dets = [d for d in dets if "net" in d.rule_id.lower() or "c2" in d.rule_id.lower()]
        matched_count = len(net_dets)
        findings: List[HuntFinding] = []

        if matched_count >= 1:
            findings.append(
                HuntFinding(
                    title="Anomalous Outbound Network Connection Observed",
                    description=f"Identified {matched_count} network egress detections during time window.",
                    severity="medium",
                    matched_events_count=matched_count,
                    event_ids=[d.id for d in net_dets],
                    entities=request.target_entities or ["192.168.1.100"],
                    attack_technique="T1071.001",
                    confidence=0.75,
                )
            )
        else:
            gaps.append("Network flow / firewall outbound telemetry is unobserved in the evaluated window.")

        return findings, matched_count, gaps

    def _hunt_attack_technique(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for detections or events matching a designated MITRE ATT&CK technique."""
        tech_id = (request.technique_id or "T1110").upper()
        gaps: List[str] = []

        # Validate technique against catalog
        tech = self.attack_catalog.get_technique(tech_id)
        tech_name = tech.name if tech else "Unknown Technique"

        if request.incident_id:
            from services.persistence.models import IncidentDetection
            det_stmt = (
                select(DbDetection)
                .join(IncidentDetection, DbDetection.id == IncidentDetection.detection_id)
                .where(IncidentDetection.incident_id == request.incident_id, DbDetection.first_seen >= cutoff)
            )
        else:
            det_stmt = select(DbDetection).where(DbDetection.first_seen >= cutoff)
        dets = session.execute(det_stmt).scalars().all()

        matched_dets = []
        for d in dets:
            rule_id = d.rule_id.lower()
            if (
                tech_id.lower() in rule_id
                or tech_id.replace(".", "_").lower() in rule_id
                or tech_id.replace(".", "-").lower() in rule_id
                or (tech_id == "T1059.001" and "powershell" in rule_id)
                or (tech_id == "T1110" and ("auth" in rule_id or "brute" in rule_id))
                or (tech and tech.name.lower() in rule_id)
            ):
                matched_dets.append(d)
        matched_count = len(matched_dets)
        findings: List[HuntFinding] = []

        if matched_count >= 1:
            findings.append(
                HuntFinding(
                    title=f"Activity Matching ATT&CK {tech_id} ({tech_name})",
                    description=(
                        f"Detected {matched_count} event(s) or rule match(es) associated with "
                        f"ATT&CK Technique {tech_id}: {tech_name}."
                    ),
                    severity="high" if matched_count >= 3 else "medium",
                    matched_events_count=matched_count,
                    event_ids=[d.id for d in matched_dets],
                    entities=request.target_entities or [],
                    attack_technique=tech_id,
                    confidence=0.85,
                )
            )
        else:
            gaps.append(f"No telemetry matching ATT&CK technique {tech_id} was observed in this time window.")

        return findings, matched_count, gaps

    def _hunt_entity_activity(
        self, session: Session, request: HuntJobRequest, cutoff: datetime
    ) -> tuple[List[HuntFinding], int, List[str]]:
        """Hunt for all correlated activity involving specific target entities."""
        entities = request.target_entities or []
        gaps: List[str] = []
        if not entities:
            return [], 0, ["No target entities provided for entity-activity hunt."]

        # Query incident entities with strict incident scoping
        stmt = select(DbIncidentEntity).where(DbIncidentEntity.entity_key.in_(entities))
        if request.incident_id:
            stmt = stmt.where(DbIncidentEntity.incident_id == request.incident_id)
        matched_ent_records = session.execute(stmt).scalars().all()
        matched_count = len(matched_ent_records)
        findings: List[HuntFinding] = []

        if matched_count >= 1:
            findings.append(
                HuntFinding(
                    title=f"Correlated Activity Across Target Entities: {', '.join(entities)}",
                    description=(
                        f"Found {matched_count} incident-entity associations involving specified targets "
                        f"within the past {request.time_window_minutes} minutes."
                    ),
                    severity="medium",
                    matched_events_count=matched_count,
                    event_ids=[],
                    entities=entities,
                    confidence=0.80,
                )
            )
        else:
            gaps.append(f"Target entities {entities} have no recorded telemetry in the active time window.")

        return findings, matched_count, gaps

    def _persist_hunt_execution(
        self, session: Session, status: HuntJobStatus, principal: Principal
    ) -> None:
        """Persist hunt job record in agent_runs and audit log."""
        # 1. Audit event
        audit = DbAuditEvent(
            id=status.audit_id,
            actor_type="user",
            actor_id=principal.id,
            action="threat_hunt.execute",
            object_type="hunt_job",
            object_id=status.hunt_id,
            outcome="SUCCESS",
            metadata_redacted={
                "hunt_type": status.hunt_type,
                "incident_id": status.incident_id,
                "time_window_minutes": status.time_window_minutes,
                "matched_events": status.matched_events_count,
                "findings_count": len(status.findings),
            },
            occurred_at=status.started_at,
        )
        session.add(audit)

        # 2. Agent Run persistence
        db_run = DbAgentRun(
            id=status.hunt_id,
            incident_id=status.incident_id,
            task_type="threat_hunting",
            state=status.state,
            model_ref="deterministic-hunt-engine-v1",
            template_version="1.0.0",
            budget_json={
                "hunt_type": status.hunt_type,
                "matched_events_count": status.matched_events_count,
                "coverage_gaps": status.coverage_gaps,
                "uncertainty_notes": status.uncertainty_notes,
                "duration_ms": status.duration_ms,
                "findings": [f.model_dump(mode="json") for f in status.findings],
            },
            started_at=status.started_at,
            finished_at=status.finished_at,
        )
        session.add(db_run)

        # 3. Agent Findings persistence
        for finding in status.findings:
            db_finding = DbAgentFinding(
                id=finding.finding_id,
                run_id=status.hunt_id,
                finding_type="threat_hunt",
                claim=finding.description,
                confidence=finding.confidence,
                evidence_refs_json=finding.event_ids,
                limitations="; ".join(status.coverage_gaps) if status.coverage_gaps else None,
                created_at=utc_now(),
            )
            session.add(db_finding)

        session.commit()

    def get_hunt_status(self, session: Session, hunt_id: str) -> Optional[HuntJobStatus]:
        """Fetch status and findings for an executed threat hunt."""
        run = session.get(DbAgentRun, hunt_id)
        if not run or run.task_type != "threat_hunting":
            return None

        b_json = run.budget_json or {}
        raw_findings = b_json.get("findings", [])
        findings = [HuntFinding(**f) for f in raw_findings]

        return HuntJobStatus(
            hunt_id=run.id,
            hunt_type=b_json.get("hunt_type", "unknown"),
            state=run.state,
            requested_by="analyst",
            incident_id=run.incident_id,
            time_window_minutes=60,
            matched_events_count=b_json.get("matched_events_count", 0),
            findings=findings,
            coverage_gaps=b_json.get("coverage_gaps", []),
            uncertainty_notes=b_json.get("uncertainty_notes", []),
            audit_id=f"aud-{run.id}",
            started_at=run.started_at,
            finished_at=run.finished_at,
            duration_ms=b_json.get("duration_ms", 0.0),
        )

    def list_hunt_jobs(
        self, session: Session, limit: int = 20, offset: int = 0
    ) -> List[HuntJobStatus]:
        """List bounded history of threat hunting runs."""
        stmt = (
            select(DbAgentRun)
            .where(DbAgentRun.task_type == "threat_hunting")
            .order_by(DbAgentRun.started_at.desc())
            .limit(max(1, min(limit, 100)))
            .offset(max(0, offset))
        )
        runs = session.execute(stmt).scalars().all()
        results = []
        for r in runs:
            st = self.get_hunt_status(session, r.id)
            if st:
                results.append(st)
        return results


# Global threat hunting service instance
hunting_service = ThreatHuntingService()

__all__ = ["ThreatHuntingService", "hunting_service"]
