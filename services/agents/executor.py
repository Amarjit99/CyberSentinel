"""CyberSentinel AI — Controlled Tool Execution Service & Authorization Boundary (Sprint 16)
Governing Decisions: ADR-0002, ADR-0004, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
"""

import logging
import threading
import time
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy.orm import Session

from packages.auth import Principal
from packages.common import utc_now
from packages.observability.metrics import metrics
from schemas.enums import AgentIdEnum, RBACRoleEnum
from services.agents.providers import sanitize_for_model
from services.agents.registry import (
    ToolAuthorizationError,
    ToolDefinition,
    ToolDisabledError,
    ToolExecutionLimitError,
    ToolNotFoundError,
    ToolRegistry,
    ToolValidationError,
    create_default_tool_registry,
)
from services.agents.tool_schemas import ToolExecutionRequest, ToolExecutionResult
from services.persistence.models import AuditEvent, Incident

logger = logging.getLogger("cybersentinel.agents.executor")


class ToolExecutionService:
    """Controlled single-point execution service enforcing server-side authorization and audit."""

    MAX_CALLS_PER_TASK: int = 50

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        max_calls_per_task: int = 50,
        max_calls_per_tool: int = 25,
    ):
        if registry is None:
            self.registry = create_default_tool_registry(include_extensions=True)
        else:
            self.registry = registry
        self.max_calls_per_task = max_calls_per_task
        self.max_calls_per_tool = max_calls_per_tool
        self._task_call_counts: Dict[str, int] = {}
        self._tool_call_counts: Dict[str, Dict[str, int]] = {}
        self._quota_lock = threading.Lock()

    def execute_tool(
        self,
        request: ToolExecutionRequest,
        principal: Principal,
        db_session: Session,
        agent_id: Optional[AgentIdEnum] = None,
        security_context: Optional[Any] = None,
    ) -> ToolExecutionResult:
        """Execute tool following 7-step authorization & execution boundary."""
        start_time = time.perf_counter()
        tool_name = request.tool_name
        incident_id = request.incident_id or request.arguments.get("incident_id")
        task_id = request.task_id or "adhoc"
        audit_id = f"aud-{uuid4().hex[:20]}"
        policy_version = "1.0.0"
        caller_agent_id = agent_id or request.agent_id

        # 1. Resolve Tool
        tool_def = self.registry.get_tool(tool_name)
        if not tool_def:
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_version="unknown",
                incident_id=incident_id,
                task_id=task_id,
                outcome="FAILED",
                reason_code="TOOL_NOT_FOUND",
                duration_ms=0.0,
                arguments=request.arguments,
                error=f"Tool '{tool_name}' is not registered in central tool registry.",
            )
            metrics.inc_counter("tool_execution_not_found_total", 1)
            raise ToolNotFoundError(f"Tool '{tool_name}' is not registered.")

        policy_version = tool_def.policy_version

        if not tool_def.is_enabled:
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="DENIED",
                reason_code="TOOL_DISABLED",
                duration_ms=0.0,
                arguments=request.arguments,
                error=f"Tool '{tool_name}' is disabled by administrative policy.",
            )
            metrics.inc_counter("tool_execution_disabled_total", 1)
            raise ToolDisabledError(f"Tool '{tool_name}' is currently disabled.")

        # 2. Authentication & Authorization Enforcement (RBAC & Agent Allowlist)
        if security_context is not None:
            try:
                security_context.validate_tool_access(
                    tool_name=tool_name,
                    tool_allowed_roles=tool_def.allowed_roles,
                    tool_allowed_agents=tool_def.allowed_agents,
                    target_incident_id=incident_id,
                )
            except Exception as sec_err:
                self._record_audit(
                    db_session=db_session,
                    audit_id=audit_id,
                    principal=principal,
                    agent_id=caller_agent_id,
                    tool_name=tool_name,
                    tool_version=tool_def.version,
                    incident_id=incident_id,
                    task_id=task_id,
                    outcome="DENIED",
                    reason_code="SECURITY_CONTEXT_VIOLATION",
                    duration_ms=0.0,
                    arguments=request.arguments,
                    error=str(sec_err),
                )
                metrics.inc_counter("tool_execution_denied_total", 1)
                raise ToolAuthorizationError(str(sec_err)) from sec_err

        authorized = any(principal.has_role(r) for r in tool_def.allowed_roles)
        if not authorized:
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="DENIED",
                reason_code="ROLE_NOT_AUTHORIZED",
                duration_ms=0.0,
                arguments=request.arguments,
                error=f"Principal '{principal.name}' lacking required role for tool '{tool_name}'.",
            )
            metrics.inc_counter("tool_execution_denied_total", 1)
            raise ToolAuthorizationError(
                f"Principal '{principal.name}' does not possess required role for tool '{tool_name}'."
            )

        if caller_agent_id is not None and caller_agent_id not in tool_def.allowed_agents:
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=caller_agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="DENIED",
                reason_code="AGENT_TYPE_NOT_AUTHORIZED",
                duration_ms=0.0,
                arguments=request.arguments,
                error=f"Agent type '{caller_agent_id.value}' is not authorized to invoke tool '{tool_name}'.",
            )
            metrics.inc_counter("tool_execution_denied_total", 1)
            raise ToolAuthorizationError(
                f"Agent type '{caller_agent_id.value}' is not authorized to invoke tool '{tool_name}'."
            )

        # 3. Incident Scoping & Cross-Incident Prevention
        if request.incident_id and "incident_id" in request.arguments:
            if str(request.arguments["incident_id"]).strip() != str(request.incident_id).strip():
                self._record_audit(
                    db_session=db_session,
                    audit_id=audit_id,
                    principal=principal,
                    agent_id=caller_agent_id,
                    tool_name=tool_name,
                    tool_version=tool_def.version,
                    incident_id=request.incident_id,
                    task_id=task_id,
                    outcome="DENIED",
                    reason_code="CROSS_INCIDENT_VIOLATION",
                    duration_ms=0.0,
                    arguments=request.arguments,
                    error=f"Cross-incident violation: Scoped '{request.incident_id}' != argument '{request.arguments['incident_id']}'.",
                )
                metrics.inc_counter("tool_execution_cross_incident_denied_total", 1)
                raise ToolValidationError(
                    f"Cross-incident violation: Scoped incident '{request.incident_id}' differs from argument '{request.arguments['incident_id']}'."
                )

        if incident_id and db_session is not None:
            incident = db_session.get(Incident, incident_id)
            if not incident:
                self._record_audit(
                    db_session=db_session,
                    audit_id=audit_id,
                    principal=principal,
                    agent_id=caller_agent_id,
                    tool_name=tool_name,
                    tool_version=tool_def.version,
                    incident_id=incident_id,
                    task_id=task_id,
                    outcome="FAILED",
                    reason_code="INCIDENT_NOT_FOUND",
                    duration_ms=0.0,
                    arguments=request.arguments,
                    error=f"Scoped incident '{incident_id}' does not exist.",
                )
                raise ToolValidationError(f"Scoped incident '{incident_id}' not found.")

        # 4. Input Schema Validation
        try:
            # Ensure incident_id is passed into arguments if required
            merged_args = dict(request.arguments)
            if incident_id and "incident_id" not in merged_args and "incident_id" in tool_def.input_schema.model_fields:
                merged_args["incident_id"] = incident_id
            validated_input = tool_def.input_schema(**merged_args)
        except ValidationError as ve:
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=caller_agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="FAILED",
                reason_code="INPUT_SCHEMA_VALIDATION_FAILED",
                duration_ms=0.0,
                arguments=request.arguments,
                error=str(ve),
            )
            metrics.inc_counter("tool_execution_schema_validation_failed_total", 1)
            raise ToolValidationError(f"Invalid arguments for tool '{tool_name}': {ve}") from ve

        # 5. Execution Limits & Quotas (Per-Task & Per-Tool) - Thread-Safe Atomic Check
        with self._quota_lock:
            current_calls = self._task_call_counts.get(task_id, 0) + 1
            if current_calls > self.max_calls_per_task:
                self._record_audit(
                    db_session=db_session,
                    audit_id=audit_id,
                    principal=principal,
                    agent_id=caller_agent_id,
                    tool_name=tool_name,
                    tool_version=tool_def.version,
                    incident_id=incident_id,
                    task_id=task_id,
                    outcome="DENIED",
                    reason_code="TASK_QUOTA_EXCEEDED",
                    duration_ms=0.0,
                    arguments=request.arguments,
                    error=f"Task '{task_id}' exceeded execution quota of {self.max_calls_per_task} calls.",
                )
                metrics.inc_counter("tool_execution_quota_exceeded_total", 1)
                raise ToolExecutionLimitError(
                    f"Execution limit exceeded: Task '{task_id}' reached max quota of {self.max_calls_per_task} calls."
                )

            tool_counts = self._tool_call_counts.setdefault(task_id, {})
            current_tool_calls = tool_counts.get(tool_name, 0) + 1
            if current_tool_calls > self.max_calls_per_tool:
                self._record_audit(
                    db_session=db_session,
                    audit_id=audit_id,
                    principal=principal,
                    agent_id=caller_agent_id,
                    tool_name=tool_name,
                    tool_version=tool_def.version,
                    incident_id=incident_id,
                    task_id=task_id,
                    outcome="DENIED",
                    reason_code="TOOL_QUOTA_EXCEEDED",
                    duration_ms=0.0,
                    arguments=request.arguments,
                    error=f"Tool '{tool_name}' exceeded quota of {self.max_calls_per_tool} calls in task '{task_id}'.",
                )
                metrics.inc_counter("tool_execution_quota_exceeded_total", 1)
                raise ToolExecutionLimitError(
                    f"Execution limit exceeded: Tool '{tool_name}' reached max quota of {self.max_calls_per_tool} calls in task '{task_id}'."
                )

            # Atomically increment call counts
            self._task_call_counts[task_id] = current_calls
            tool_counts[tool_name] = current_tool_calls

        # 6. Execute registered implementation
        try:
            raw_result = self._dispatch_handler(
                tool_def=tool_def,
                validated_input=validated_input,
                db_session=db_session,
                incident_id=incident_id,
                principal=principal,
            )

            # Output validation & Result Bounding
            if isinstance(raw_result, dict):
                bounded_data = self._bound_result(raw_result, tool_def)
                validated_output = tool_def.output_schema(**bounded_data)
                final_data = validated_output.model_dump(mode="json")
            else:
                final_data = {"result": raw_result}

            # Pre-model gateway redaction on tool execution outputs
            def _redact_value(val: Any) -> Any:
                if isinstance(val, str):
                    return sanitize_for_model(val)
                elif isinstance(val, dict):
                    return {k: _redact_value(v) for k, v in val.items()}
                elif isinstance(val, list):
                    return [_redact_value(v) for v in val]
                return val

            final_data = _redact_value(final_data)

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="SUCCESS",
                reason_code="TOOL_EXECUTION_AUTHORIZED",
                duration_ms=duration_ms,
                arguments=request.arguments,
            )
            metrics.inc_counter("tool_execution_success_total", 1)
            metrics.set_gauge("last_tool_execution_latency_ms", duration_ms)

            return ToolExecutionResult(
                tool_name=tool_name,
                tool_version=tool_def.version,
                status="SUCCESS",
                data=final_data,
                duration_ms=round(duration_ms, 2),
                audit_id=audit_id,
                policy_version=policy_version,
            )

        except Exception as ex:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Tool execution error for '%s': %s", tool_name, ex, exc_info=True)
            self._record_audit(
                db_session=db_session,
                audit_id=audit_id,
                principal=principal,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_version=tool_def.version,
                incident_id=incident_id,
                task_id=task_id,
                outcome="FAILED",
                reason_code="EXECUTION_ERROR",
                duration_ms=duration_ms,
                arguments=request.arguments,
                error=str(ex),
            )
            metrics.inc_counter("tool_execution_failed_total", 1)
            return ToolExecutionResult(
                tool_name=tool_name,
                tool_version=tool_def.version,
                status="FAILED",
                error=f"Execution error: {str(ex)}",
                duration_ms=round(duration_ms, 2),
                audit_id=audit_id,
                policy_version=policy_version,
            )

    def _dispatch_handler(
        self,
        tool_def: ToolDefinition,
        validated_input: Any,
        db_session: Session,
        incident_id: Optional[str],
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        """Dispatch tool handler utilizing ReadOnlyInvestigationTools implementations."""
        from services.agents.tools import ReadOnlyInvestigationTools

        target_inc = incident_id or getattr(validated_input, "incident_id", None)
        tools = ReadOnlyInvestigationTools(session=db_session, incident_id=target_inc or "")

        name = tool_def.name
        if name == "get_incident_summary":
            return tools.get_incident_summary()
        elif name == "get_incident_detections":
            limit = getattr(validated_input, "limit", 50)
            dets = tools.get_incident_detections()[:limit]
            return {"incident_id": target_inc, "total_count": len(dets), "detections": dets}
        elif name == "get_canonical_events":
            limit = getattr(validated_input, "limit", 20)
            events = tools.get_canonical_events(limit=limit)
            return {"incident_id": target_inc, "total_count": len(events), "events": events}
        elif name == "get_incident_timeline":
            timeline = tools.get_incident_timeline()
            return {"incident_id": target_inc, "total_entries": len(timeline), "timeline": timeline}
        elif name == "get_incident_entities":
            entities = tools.get_incident_entities()
            return {"incident_id": target_inc, "total_count": len(entities), "entities": entities}
        elif name == "get_incident_evidence":
            evidence = tools.get_incident_evidence()
            return {"incident_id": target_inc, "total_count": len(evidence), "evidence": evidence}
        elif name == "get_prior_findings":
            findings = tools.get_prior_findings()
            return {"incident_id": target_inc, "total_count": len(findings), "findings": findings}
        elif name == "lookup_threat_intel":
            t_type = getattr(validated_input, "indicator_type")
            t_val = getattr(validated_input, "indicator_value")
            return tools.lookup_threat_intel(indicator_type=t_type, indicator_value=t_val)
        elif name == "get_incident_risk_assessment":
            return tools.get_incident_risk_assessment()
        elif name == "search_knowledge_base":
            from services.rag.engine import rag_engine
            from services.rag.models import RAGQueryRequest, RAGSourceTypeEnum

            raw_sources = getattr(validated_input, "source_types", None)
            st_enums = [RAGSourceTypeEnum(s) for s in raw_sources] if raw_sources else None
            req = RAGQueryRequest(
                query=getattr(validated_input, "query"),
                source_types=st_enums,
                incident_id=target_inc or getattr(validated_input, "incident_id", None),
                top_k=getattr(validated_input, "limit", 5),
            )
            caller_principal = principal or Principal(id="agent", name="Agent Operator", roles=[RBACRoleEnum.SOC_ANALYST, RBACRoleEnum.THREAT_HUNTER])
            rag_res = rag_engine.query(req, caller_principal)
            return {
                "query": rag_res.query,
                "retrieval_method": rag_res.retrieval_method,
                "total_results": len(rag_res.results),
                "results": [r.model_dump(mode="json") for r in rag_res.results],
                "citations": rag_res.citations,
                "generated_summary": rag_res.generated_summary,
            }
        elif name == "run_threat_hunt":
            from services.hunting.models import HuntJobRequest, HuntTypeEnum
            from services.hunting.service import hunting_service

            hunt_req = HuntJobRequest(
                hunt_type=HuntTypeEnum(getattr(validated_input, "hunt_type")),
                incident_id=target_inc or getattr(validated_input, "incident_id", None),
                time_window_minutes=getattr(validated_input, "time_window_minutes", 60),
                target_entities=getattr(validated_input, "target_entities", None),
                technique_id=getattr(validated_input, "technique_id", None),
                threshold=getattr(validated_input, "threshold", 5),
                parameters=getattr(validated_input, "parameters", {}),
            )
            caller_principal = principal or Principal(id="agent", name="Agent Operator", roles=[RBACRoleEnum.THREAT_HUNTER])
            hunt_res = hunting_service.launch_hunt(db_session, hunt_req, caller_principal)
            return {
                "hunt_id": hunt_res.hunt_id,
                "hunt_type": hunt_res.hunt_type,
                "status": hunt_res.state,
                "matched_events_count": hunt_res.matched_events_count,
                "findings": [f.model_dump(mode="json") for f in hunt_res.findings],
                "coverage_gaps": hunt_res.coverage_gaps,
                "uncertainty_notes": hunt_res.uncertainty_notes,
                "audit_id": hunt_res.audit_id,
            }
        elif name == "generate_candidate_rule":
            from services.detection.assistant import detection_assistant
            from services.detection.models import RuleGenerationRequest

            gen_req = RuleGenerationRequest(
                title=getattr(validated_input, "title", None) or f"Sigma: {str(getattr(validated_input, 'objective'))[:40]}",
                objective=getattr(validated_input, "objective"),
                target_technique=getattr(validated_input, "target_technique", None),
                category=getattr(validated_input, "category", "process_creation") or "process_creation",
                product=getattr(validated_input, "product", "windows") or "windows",
                severity=getattr(validated_input, "severity", "medium") or "medium",
            )
            author_principal = principal or Principal(
                id="assistant",
                name="Detection Engineering Assistant",
                roles=[RBACRoleEnum.DETECTION_ENGINEER, RBACRoleEnum.SECURITY_ENGINEER],
            )
            cand_resp = detection_assistant.generate_candidate_rule(gen_req, author=author_principal, db_session=db_session)
            return {
                "candidate_id": cand_resp.id,
                "rule_id": cand_resp.rule_id,
                "title": cand_resp.title,
                "status": cand_resp.status.value,
                "raw_yaml": cand_resp.raw_yaml,
                "attack_techniques": cand_resp.attack_techniques,
                "is_valid": cand_resp.validation_report.is_valid if cand_resp.validation_report else True,
                "diagnostics_count": len(cand_resp.validation_report.diagnostics) if cand_resp.validation_report else 0,
            }
        elif name == "validate_sigma_rule":
            from services.detection.assistant import detection_assistant

            yaml_content = getattr(validated_input, "rule_yaml")
            val_rep = detection_assistant.validator.validate_yaml(yaml_content)
            return {
                "is_valid": val_rep.is_valid,
                "rule_id": val_rep.rule_id,
                "rule_title": val_rep.rule_title,
                "error_count": val_rep.error_count,
                "warning_count": val_rep.warning_count,
                "diagnostics": [d.model_dump(mode="json") for d in val_rep.diagnostics],
                "detected_attack_ids": val_rep.detected_attack_ids,
            }
        elif name == "test_candidate_rule":
            from services.detection.assistant import detection_assistant
            from services.detection.models import RuleTestRequest

            test_req = RuleTestRequest(
                rule_yaml=getattr(validated_input, "rule_yaml"),
                fixtures=getattr(validated_input, "fixtures", None),
                use_sample_fixtures=getattr(validated_input, "use_sample_fixtures", True),
                max_events=getattr(validated_input, "max_events", 50),
            )
            res = detection_assistant.tester.test_rule(test_req, db_session=db_session)
            return res.model_dump(mode="json")
        elif name == "explain_detection_rule":
            from services.detection.assistant import detection_assistant

            rule_yaml = getattr(validated_input, "rule_yaml")
            exp = detection_assistant.explain_rule(yaml_content=rule_yaml, candidate_id=None, db_session=db_session)
            return exp.model_dump(mode="json")
        elif tool_def.handler:
            res = tool_def.handler(validated_input, db_session)
            if isinstance(res, dict):
                return dict(res)
            if hasattr(res, "model_dump"):
                return dict(res.model_dump())
            return {"result": res}
        else:
            raise ToolNotFoundError(f"No execution handler registered for tool '{name}'.")

    def _bound_result(self, data: Dict[str, Any], tool_def: ToolDefinition) -> Dict[str, Any]:
        """Bound list items to max_result_items to prevent memory exhaust or model context poisoning."""
        bounded = dict(data)
        for k, v in list(bounded.items()):
            if isinstance(v, list) and len(v) > tool_def.max_result_items:
                bounded[k] = v[: tool_def.max_result_items]
        return bounded

    def _record_audit(
        self,
        db_session: Session,
        audit_id: str,
        principal: Principal,
        agent_id: Optional[AgentIdEnum],
        tool_name: str,
        tool_version: str,
        incident_id: Optional[str],
        task_id: str,
        outcome: str,
        reason_code: str,
        duration_ms: float,
        arguments: Dict[str, Any],
        error: Optional[str] = None,
    ) -> None:
        """Write immutable audit record without leaking secrets."""
        # Sanitize arguments: scrub potential tokens/passwords
        safe_args: Dict[str, Any] = {}
        for k, v in arguments.items():
            if any(s in k.lower() for s in ("token", "secret", "password", "key", "auth")):
                safe_args[k] = "[REDACTED]"
            elif isinstance(v, str):
                safe_args[k] = sanitize_for_model(v)[:256]
            else:
                safe_args[k] = v

        audit = AuditEvent(
            id=audit_id,
            actor_type="AGENT" if agent_id else "USER",
            actor_id=agent_id.value if agent_id else principal.id,
            action=f"tool:execute:{tool_name}",
            object_type="tool",
            object_id=tool_name,
            outcome=outcome,
            reason_code=reason_code,
            occurred_at=utc_now(),
            metadata_redacted={
                "tool_version": tool_version,
                "incident_id": incident_id,
                "task_id": task_id,
                "duration_ms": round(duration_ms, 2),
                "arguments": safe_args,
                "error": error,
            },
        )
        try:
            db_session.add(audit)
            db_session.commit()
        except Exception as ae:
            logger.error("Failed to commit tool execution audit event: %s", ae)
            db_session.rollback()


# Global default execution service
default_tool_executor = ToolExecutionService()
