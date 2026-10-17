"""CyberSentinel AI — Detection Engineering Assistant Service (Sprint 19)
Governing Decisions: ADR-0002, ADR-0004, ADR-0005, Phase 19 Specification
"""

import logging
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from attack.registry import AttackCatalog, attack_catalog
from packages.auth import Principal, RBACRoleEnum
from packages.observability.metrics import metrics
from services.agents.investigation import INJECTION_HEURISTICS
from services.detection.compiler import CANONICAL_FIELD_MAP
from services.detection.engine import SigmaDetectionEngine, detection_engine
from services.detection.models import (
    CandidateReviewRequest,
    CandidateRuleResponse,
    CandidateRuleStatusEnum,
    RuleExplanationResponse,
    RuleGenerationRequest,
    RuleTestRequest,
    RuleTestResult,
    RuleValidationReport,
    utc_now,
)
from services.detection.testing import SafeRuleTester, safe_rule_tester
from services.detection.validation import SigmaRuleValidator, sigma_validator
from services.persistence.models import AuditEvent, DetectionRuleCandidate

logger = logging.getLogger("cybersentinel.detection.assistant")

AUTHORIZED_ENGINEER_ROLES = {
    RBACRoleEnum.DETECTION_ENGINEER,
    RBACRoleEnum.SECURITY_ENGINEER,
    RBACRoleEnum.ADMIN,
}

AUTHORIZED_READ_ROLES = {
    RBACRoleEnum.DETECTION_ENGINEER,
    RBACRoleEnum.SECURITY_ENGINEER,
    RBACRoleEnum.SOC_ANALYST,
    RBACRoleEnum.THREAT_HUNTER,
    RBACRoleEnum.SOC_MANAGER,
    RBACRoleEnum.ADMIN,
}


class DetectionEngineeringAssistant:
    """Bounded, authorized assistant for Sigma rule generation, validation, safe testing, and review."""

    def __init__(
        self,
        engine: Optional[SigmaDetectionEngine] = None,
        validator: Optional[SigmaRuleValidator] = None,
        tester: Optional[SafeRuleTester] = None,
        catalog: Optional[AttackCatalog] = None,
    ):
        self.engine = engine or detection_engine
        self.validator = validator or sigma_validator
        self.tester = tester or safe_rule_tester
        self.catalog = catalog or attack_catalog

    # =========================================================================
    # 1. Candidate Rule Generation
    # =========================================================================

    def generate_candidate_rule(
        self,
        request: RuleGenerationRequest,
        author: Principal,
        db_session: Optional[Session] = None,
    ) -> CandidateRuleResponse:
        """Generate a structured candidate Sigma rule from a detection objective."""
        # Enforce prompt injection defense on untrusted user objective
        obj_clean = request.objective
        for pattern in INJECTION_HEURISTICS:
            if pattern.search(obj_clean):
                logger.warning("Prompt injection heuristic triggered in rule generation objective.")
                obj_clean = "[POTENTIAL_INJECTION_REDACTED]"
                break

        rule_uuid = str(uuid4())
        target_tech = (request.target_technique or "T1059.001").upper()
        category = request.category or "process_creation"
        product = request.product or "windows"

        # Build clean, valid Sigma YAML document
        rule_dict: Dict[str, Any] = {
            "title": request.title,
            "id": rule_uuid,
            "status": "experimental",
            "description": f"Detects activity matching: {obj_clean}",
            "references": [
                f"https://attack.mitre.org/techniques/{target_tech.replace('.', '/')}/"
            ],
            "author": f"CyberSentinel Detection Engineering Assistant ({author.id})",
            "date": utc_now().strftime("%Y-%m-%d"),
            "logsource": {
                "category": category,
                "product": product,
            },
            "detection": self._build_default_detection_block(category, target_tech, request),
            "falsepositives": [
                "Legitimate administrative automation scripts",
                "Internal deployment and management utilities",
            ],
            "level": request.severity.lower() if request.severity.lower() in ("low", "medium", "high", "critical") else "medium",
            "tags": [
                "attack.execution" if "1059" in target_tech else "attack.defense_evasion",
                f"attack.{target_tech.lower()}",
            ],
        }

        raw_yaml = yaml.dump(rule_dict, sort_keys=False, default_flow_style=False)

        # Validate the generated rule
        active_ids = {r.id for r in self.engine.get_active_rules()}
        val_report = self.validator.validate_yaml(raw_yaml, existing_active_rule_ids=active_ids)

        # Run safe fixture testing
        test_req = RuleTestRequest(rule_yaml=raw_yaml, use_sample_fixtures=True, max_events=20)
        test_result = self.tester.test_rule(test_req, db_session=db_session)

        candidate_id = f"drc-{uuid4().hex[:12]}"
        status = CandidateRuleStatusEnum.VALIDATED if val_report.is_valid else CandidateRuleStatusEnum.VALIDATION_FAILED
        audit_id = f"aud-{uuid4().hex[:16]}"
        now = utc_now()

        candidate_resp = CandidateRuleResponse(
            id=candidate_id,
            rule_id=rule_uuid,
            title=request.title,
            version="1.0.0",
            status=status,
            raw_yaml=raw_yaml,
            original_rule_id=None,
            author_id=author.id,
            description=rule_dict["description"],
            severity=rule_dict["level"],
            logsource=rule_dict["logsource"],
            attack_techniques=[target_tech],
            validation_report=val_report,
            test_results=test_result,
            review_notes=None,
            reviewed_by=None,
            reviewed_at=None,
            activated_at=None,
            activated_by=None,
            created_at=now,
            updated_at=now,
        )

        if db_session:
            db_cand = DetectionRuleCandidate(
                id=candidate_id,
                rule_id=rule_uuid,
                title=request.title,
                version="1.0.0",
                status=status.value,
                raw_yaml=raw_yaml,
                original_rule_id=None,
                author_id=author.id,
                description=rule_dict["description"],
                severity=rule_dict["level"],
                logsource_json=rule_dict["logsource"],
                attack_techniques_json=[target_tech],
                validation_diagnostics_json=[d.model_dump(mode="json") for d in val_report.diagnostics],
                test_results_json=test_result.model_dump(mode="json"),
                review_notes=None,
                reviewed_by=None,
                reviewed_at=None,
                activated_at=None,
                activated_by=None,
                audit_id=audit_id,
                created_at=now,
                updated_at=now,
            )
            db_session.add(db_cand)

            audit = AuditEvent(
                id=audit_id,
                actor_type="user",
                actor_id=author.id,
                action="detection.candidate.generate",
                object_type="detection_rule_candidate",
                object_id=candidate_id,
                outcome="SUCCESS" if val_report.is_valid else "VALIDATION_FAILED",
                metadata_redacted={
                    "rule_id": rule_uuid,
                    "target_technique": target_tech,
                    "is_valid": val_report.is_valid,
                },
                occurred_at=now,
            )
            db_session.add(audit)
            db_session.commit()

        metrics.inc_counter("detection_rules_generated_total", 1)
        return candidate_resp

    def _build_default_detection_block(
        self,
        category: str,
        tech_id: str,
        req: RuleGenerationRequest,
    ) -> Dict[str, Any]:
        """Construct a baseline detection mapping based on telemetry category and target technique."""
        if category == "network_connection" or category == "dns_query":
            return {
                "selection": {
                    "domain|contains": ["c2-beacon", "suspicious-tunnel"],
                },
                "filter_internal": {
                    "domain|endswith": [".corp.internal", ".local"],
                },
                "condition": "selection and not filter_internal",
            }
        elif category == "authentication":
            return {
                "selection": {
                    "event_type": "authentication",
                    "username": "root",
                },
                "filter_known_ip": {
                    "src_ip": "127.0.0.1",
                },
                "condition": "selection and not filter_known_ip",
            }
        else:
            # Default to process_creation
            selection_dict: Dict[str, Any] = {
                "process_name": "powershell.exe" if "1059" in tech_id else "cmd.exe",
                "command_line|contains": ["DownloadString", "Invoke-WebRequest", "whoami", "-nop"],
            }
            if req.required_fields:
                for rf in req.required_fields:
                    canonical = CANONICAL_FIELD_MAP.get(rf.lower(), rf.lower())
                    if canonical not in selection_dict:
                        selection_dict[canonical] = "suspicious_value"

            return {
                "selection": selection_dict,
                "filter_admin": {
                    "username": "AdminProvisioningUser",
                },
                "condition": "selection and not filter_admin",
            }

    # =========================================================================
    # 2. Rule Explanation & Quality Analysis
    # =========================================================================

    def explain_rule(
        self,
        yaml_content: Optional[str] = None,
        candidate_id: Optional[str] = None,
        db_session: Optional[Session] = None,
    ) -> RuleExplanationResponse:
        """Produce an analyst-friendly structured explanation of detection logic, ATT&CK, and blind spots."""
        rule_text = yaml_content
        if not rule_text and candidate_id and db_session:
            cand = db_session.get(DetectionRuleCandidate, candidate_id)
            if not cand:
                raise ValueError(f"Candidate rule '{candidate_id}' not found.")
            rule_text = cand.raw_yaml

        if not rule_text:
            raise ValueError("Either 'yaml_content' or valid 'candidate_id' must be provided for rule explanation.")

        try:
            doc = yaml.safe_load(rule_text) or {}
        except Exception:
            doc = {}

        rule_id = str(doc.get("id") or "unknown")
        title = str(doc.get("title") or "Untitled Detection Rule")
        description = str(doc.get("description") or "No description provided.")
        logsource = doc.get("logsource") or {}
        detection = doc.get("detection") or {}
        condition = str(detection.get("condition") or "none")

        # 1. Logic breakdown
        logic: List[str] = []
        for k, v in detection.items():
            if k == "condition":
                continue
            if isinstance(v, dict):
                terms = [f"{field}: {val}" for field, val in v.items()]
                logic.append(f"Block '{k}': matches ({', '.join(terms)})")
            elif isinstance(v, list):
                logic.append(f"Block '{k}': list of {len(v)} condition alternatives")
        logic.append(f"Overall evaluation condition: '{condition}'")

        # 2. ATT&CK mappings
        attack_mappings: List[Dict[str, Any]] = []
        tags = doc.get("tags") or []
        for t in tags:
            match = re.search(r"(?:attack\.)?(t\d{4}(?:\.\d{3})?)", str(t).lower())
            if match:
                tid = match.group(1).upper()
                tech = self.catalog.get_technique(tid)
                attack_mappings.append({
                    "technique_id": tid,
                    "technique_name": tech.name if tech else "Unknown Technique",
                    "tactic": tech.tactics[0] if tech and tech.tactics else "Execution",
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                })

        # 3. False-positive risks
        fp_risks: List[str] = []
        for k, v in detection.items():
            if k.startswith("filter"):
                continue
            if isinstance(v, dict):
                for f, val in v.items():
                    if f in ("command_line|contains", "command_line"):
                        if isinstance(val, list) and any(len(str(item)) < 4 for item in val):
                            fp_risks.append(f"Short keyword match in '{f}' may trigger high false-positive rates on normal command arguments.")
                    if str(val).strip() in ("*", "**"):
                        fp_risks.append(f"Wildcard match on '{f}' matches every non-null event unconditionally.")

        user_fps = doc.get("falsepositives") or []
        for ufp in user_fps:
            fp_risks.append(str(ufp))
        if not fp_risks:
            fp_risks.append("Legitimate administrative management utilities and scheduled software tasks.")

        # 4. Limitations and blind spots
        blindspots: List[str] = [
            "Binary renaming (e.g., executing target tool renamed to svchost.exe or update.exe) bypasses process_name checks.",
            "Command-line string obfuscation (e.g. environment variable insertion, caret escapes, quotation splitting) may bypass simple substring filters.",
            "In environments without command-line telemetry logging enabled (e.g. Sysmon EID 1 or auditd execve), this rule will not trigger.",
        ]

        # 5. Recommended improvements
        improvements: List[str] = [
            "Consider anchoring selections with file hash (hash_sha256) or parent process relationships for higher precision.",
            "Add exclusions for known enterprise management service accounts to reduce analyst alert fatigue.",
            "Ensure MITRE ATT&CK technique tags align with the exact sub-technique behavior being monitored.",
        ]

        return RuleExplanationResponse(
            rule_id=rule_id,
            title=title,
            summary=f"Rule detects: {description}",
            logic_breakdown=logic,
            expected_telemetry=logsource,
            attack_mappings=attack_mappings,
            false_positive_risks=fp_risks,
            limitations_and_blindspots=blindspots,
            recommended_improvements=improvements,
        )

    # =========================================================================
    # 3. Rule Lifecycle & Human Review Boundary
    # =========================================================================

    def review_candidate(
        self,
        candidate_id: str,
        review_req: CandidateReviewRequest,
        reviewer: Principal,
        db_session: Session,
    ) -> CandidateRuleResponse:
        """Enforce authorized human review of candidate detection rules."""
        # Check authorization
        user_roles = {r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in reviewer.roles}
        if not (user_roles & AUTHORIZED_ENGINEER_ROLES):
            raise PermissionError(
                f"Principal '{reviewer.id}' lacks authorized role (DETECTION_ENGINEER, SECURITY_ENGINEER, ADMIN) to review candidate rules."
            )

        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")

        decision = review_req.decision.upper().strip()
        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError("Review decision must be 'APPROVED' or 'REJECTED'.")

        now = utc_now()
        cand.status = CandidateRuleStatusEnum.APPROVED.value if decision == "APPROVED" else CandidateRuleStatusEnum.REJECTED.value
        cand.review_notes = review_req.notes
        cand.reviewed_by = reviewer.id
        cand.reviewed_at = now
        cand.updated_at = now

        audit = AuditEvent(
            id=f"aud-{uuid4().hex[:16]}",
            actor_type="user",
            actor_id=reviewer.id,
            action="detection.candidate.review",
            object_type="detection_rule_candidate",
            object_id=candidate_id,
            outcome=decision,
            reason_code=decision,
            metadata_redacted={
                "rule_id": cand.rule_id,
                "notes": review_req.notes,
            },
            occurred_at=now,
        )
        db_session.add(audit)
        db_session.commit()

        return self._to_candidate_response(cand)

    def validate_candidate(
        self,
        candidate_id: str,
        db_session: Session,
        caller: Optional[Principal] = None,
    ) -> CandidateRuleResponse:
        """Re-validate candidate rule and update its validation status and diagnostics."""
        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")

        active_ids = {r.id for r in self.engine.get_active_rules()}
        val_report = self.validator.validate_yaml(cand.raw_yaml, existing_active_rule_ids=active_ids)

        now = utc_now()
        cand.validation_diagnostics_json = [d.model_dump(mode="json") for d in val_report.diagnostics]
        cand.status = (
            CandidateRuleStatusEnum.VALIDATED.value
            if val_report.is_valid
            else CandidateRuleStatusEnum.VALIDATION_FAILED.value
        )
        cand.updated_at = now
        db_session.commit()
        return self._to_candidate_response(cand)

    def test_candidate(
        self,
        candidate_id: str,
        test_req: RuleTestRequest,
        db_session: Session,
        caller: Optional[Principal] = None,
    ) -> RuleTestResult:
        """Safely test candidate rule against fixtures and persist test outcomes."""
        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")

        req_to_run = test_req
        if not req_to_run.rule_yaml:
            req_to_run = test_req.model_copy(update={"rule_yaml": cand.raw_yaml})

        result = self.tester.test_rule(req_to_run, db_session=db_session)
        cand.test_results_json = result.model_dump(mode="json")
        cand.updated_at = utc_now()
        db_session.commit()
        return result

    def activate_candidate(
        self,
        candidate_id: str,
        db_session: Session,
        caller: Optional[Principal] = None,
        operator: Optional[Principal] = None,
    ) -> CandidateRuleResponse:
        """Safely load an approved candidate detection rule into production engine."""
        effective_principal = caller or operator
        if not effective_principal:
            raise PermissionError("Authorization principal required for activation.")

        user_roles = {
            r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in effective_principal.roles
        }
        if not (user_roles & AUTHORIZED_ENGINEER_ROLES):
            raise PermissionError(
                f"Principal '{effective_principal.id}' lacks authorized role to activate production detection rules."
            )

        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")

        if cand.status != CandidateRuleStatusEnum.APPROVED.value:
            raise ValueError(
                f"Cannot activate candidate rule in status '{cand.status}'. Rule must be 'APPROVED' by human review before activation."
            )

        try:
            compiled = self.engine.load_rule(cand.raw_yaml, source_name=f"candidate_{cand.rule_id}")
        except Exception as ex:
            logger.error("Failed to compile candidate rule into production engine: %s", ex)
            raise ValueError(f"Rule compilation failed during production activation: {ex}") from ex

        now = utc_now()
        cand.status = CandidateRuleStatusEnum.ACTIVE.value
        cand.activated_at = now
        cand.activated_by = effective_principal.id
        cand.updated_at = now

        audit = AuditEvent(
            id=f"aud-{uuid4().hex[:16]}",
            actor_type="user",
            actor_id=effective_principal.id,
            action="detection.candidate.activate",
            object_type="detection_rule_candidate",
            object_id=candidate_id,
            outcome="ACTIVE",
            metadata_redacted={
                "rule_id": cand.rule_id,
                "compiled_id": compiled.id,
                "title": cand.title,
            },
            occurred_at=now,
        )
        db_session.add(audit)
        db_session.commit()
        metrics.inc_counter("detection_rules_activated_total", 1)

        return self._to_candidate_response(cand)

    def deactivate_candidate(
        self,
        candidate_id: str,
        db_session: Session,
        caller: Optional[Principal] = None,
        operator: Optional[Principal] = None,
    ) -> CandidateRuleResponse:
        """Deactivate an active detection rule from production engine."""
        effective_principal = caller or operator
        if not effective_principal:
            raise PermissionError("Authorization principal required for deactivation.")

        user_roles = {
            r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in effective_principal.roles
        }
        if not (user_roles & AUTHORIZED_ENGINEER_ROLES):
            raise PermissionError("Unauthorized role for rule deactivation.")

        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")

        self.engine.remove_rule(cand.rule_id)

        now = utc_now()
        cand.status = CandidateRuleStatusEnum.DEPRECATED.value
        cand.updated_at = now

        audit = AuditEvent(
            id=f"aud-{uuid4().hex[:16]}",
            actor_type="user",
            actor_id=effective_principal.id,
            action="detection.candidate.deactivate",
            object_type="detection_rule_candidate",
            object_id=candidate_id,
            outcome="DEPRECATED",
            metadata_redacted={"rule_id": cand.rule_id},
            occurred_at=now,
        )
        db_session.add(audit)
        db_session.commit()

        return self._to_candidate_response(cand)

    def get_candidate(
        self,
        candidate_id: str,
        db_session: Session,
        caller: Optional[Principal] = None,
    ) -> CandidateRuleResponse:
        """Fetch candidate rule by ID."""
        cand = db_session.get(DetectionRuleCandidate, candidate_id)
        if not cand:
            raise ValueError(f"Candidate rule '{candidate_id}' not found.")
        return self._to_candidate_response(cand)

    def list_candidates(
        self,
        db_session: Session,
        caller: Optional[Principal] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[CandidateRuleResponse]:
        """List candidate rules with optional status filter."""
        stmt = select(DetectionRuleCandidate).order_by(DetectionRuleCandidate.created_at.desc())
        if status:
            stmt = stmt.where(DetectionRuleCandidate.status == status.upper())
        stmt = stmt.offset(offset).limit(min(limit, 100))

        results = db_session.execute(stmt).scalars().all()
        return [self._to_candidate_response(c) for c in results]

    def _to_candidate_response(self, cand: DetectionRuleCandidate) -> CandidateRuleResponse:
        """Convert ORM model to Pydantic CandidateRuleResponse."""
        val_rep = None
        if cand.validation_diagnostics_json is not None:
            val_rep = RuleValidationReport(
                is_valid=(cand.status not in (CandidateRuleStatusEnum.VALIDATION_FAILED.value, "VALIDATION_FAILED")),
                rule_id=cand.rule_id,
                rule_title=cand.title,
                diagnostics=cand.validation_diagnostics_json,
                error_count=sum(1 for d in cand.validation_diagnostics_json if d.get("severity") == "ERROR"),
                warning_count=sum(1 for d in cand.validation_diagnostics_json if d.get("severity") == "WARNING"),
                parsed_logsource=cand.logsource_json,
                detected_attack_ids=cand.attack_techniques_json,
            )

        test_res = None
        if cand.test_results_json:
            test_res = RuleTestResult(**cand.test_results_json)

        return CandidateRuleResponse(
            id=cand.id,
            rule_id=cand.rule_id,
            title=cand.title,
            version=cand.version,
            status=CandidateRuleStatusEnum(cand.status),
            raw_yaml=cand.raw_yaml,
            original_rule_id=cand.original_rule_id,
            author_id=cand.author_id,
            description=cand.description,
            severity=cand.severity,
            logsource=cand.logsource_json,
            attack_techniques=cand.attack_techniques_json,
            validation_report=val_rep,
            test_results=test_res,
            review_notes=cand.review_notes,
            reviewed_by=cand.reviewed_by,
            reviewed_at=cand.reviewed_at,
            activated_at=cand.activated_at,
            activated_by=cand.activated_by,
            created_at=cand.created_at,
            updated_at=cand.updated_at,
        )


# Global default assistant singleton
detection_assistant = DetectionEngineeringAssistant()

__all__ = ["DetectionEngineeringAssistant", "detection_assistant"]
