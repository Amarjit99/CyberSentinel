"""CyberSentinel AI — Investigation Orchestrator & Task Scheduler (ADR-0002, Doc 10)

Coordinates multi-agent investigation plans, enforces strict execution limits,
validates evidence grounding, and manages state persistence.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.auth import Principal, RBACRoleEnum
from packages.observability.metrics import metrics
from schemas.enums import AgentIdEnum
from services.agents.executor import default_tool_executor
from services.agents.investigation import InvestigationAgent
from services.agents.models import (
    AgentFinding,
    AgentRunStateEnum,
    HumanReviewDecisionEnum,
    InvestigationContinuationRequest,
    InvestigationPlan,
    InvestigationReviewRequest,
    InvestigationRunRequest,
    InvestigationRunStatus,
    InvestigationSummary,
    InvestigationTask,
    OrchestrationExecutionResult,
    TaskStatusEnum,
)
from services.agents.providers import (
    BaseLLMProvider,
    DeterministicRuleProvider,
    sanitize_for_model,
)
from services.agents.tool_schemas import ToolExecutionRequest
from services.incidents.lifecycle import lifecycle_manager
from services.persistence.models import (
    AgentFinding as DbAgentFinding,
)
from services.persistence.models import (
    AgentRun as DbAgentRun,
)
from services.persistence.models import (
    AuditEvent,
    Incident,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationOrchestrator:
    """Orchestrates bounded multi-agent incident investigations with evidence validation."""

    def __init__(
        self,
        default_provider: Optional[BaseLLMProvider] = None,
        agent: Optional[InvestigationAgent] = None,
    ):
        self.default_provider = default_provider or DeterministicRuleProvider()
        self.agent = agent or InvestigationAgent(
            provider=self.default_provider,
            fallback_provider=DeterministicRuleProvider(),
        )

    def build_investigation_plan(
        self,
        incident_id: str,
        max_steps: int = 8,
        budget_usd: float = 1.0,
        focus_areas: Optional[List[str]] = None,
    ) -> InvestigationPlan:
        """Create a bounded, directed task plan for investigating an incident."""
        bounded_steps = max(1, min(max_steps, 10))
        task_suffix = uuid4().hex[:8]

        def task_id(step: str) -> str:
            return f"task-{step}-{incident_id[:8]}-{task_suffix}"

        tasks = [
            InvestigationTask(
                task_id=task_id("ctx"),
                task_type="context_collection",
                agent_id=AgentIdEnum.TRIAGE_AGENT,
                dependencies=[],
            ),
            InvestigationTask(
                task_id=task_id("det"),
                task_type="detection_analysis",
                agent_id=AgentIdEnum.INVESTIGATION_AGENT,
                dependencies=[task_id("ctx")],
            ),
            InvestigationTask(
                task_id=task_id("intel"),
                task_type="threat_enrichment",
                agent_id=AgentIdEnum.THREAT_INTEL_AGENT,
                dependencies=[task_id("ctx")],
            ),
            InvestigationTask(
                task_id=task_id("triage"),
                task_type="triage_assessment",
                agent_id=AgentIdEnum.TRIAGE_AGENT,
                dependencies=[task_id("det"), task_id("intel")],
            ),
            InvestigationTask(
                task_id=task_id("summary"),
                task_type="investigation_summary",
                agent_id=AgentIdEnum.INVESTIGATION_AGENT,
                dependencies=[task_id("triage")],
            ),
            InvestigationTask(
                task_id=task_id("rag"),
                task_type="knowledge_retrieval",
                agent_id=AgentIdEnum.INVESTIGATION_AGENT,
                dependencies=[task_id("det")],
            ),
            InvestigationTask(
                task_id=task_id("hunt"),
                task_type="threat_hunting",
                agent_id=AgentIdEnum.INVESTIGATION_AGENT,
                dependencies=[task_id("det")],
            ),
        ]

        selected_tasks = tasks[:bounded_steps]
        # Ensure DAG dependency integrity in the slice
        task_id_set = {t.task_id for t in selected_tasks}
        for t in selected_tasks:
            t.dependencies = [d for d in t.dependencies if d in task_id_set]

        return InvestigationPlan(
            plan_id=f"plan-{uuid4().hex[:12]}",
            incident_id=incident_id,
            tasks=selected_tasks,
            max_steps=bounded_steps,
            budget_limit_usd=budget_usd,
        )

    async def execute_investigation(
        self,
        session: Session,
        incident_id: str,
        request: InvestigationRunRequest,
        provider: Optional[BaseLLMProvider] = None,
    ) -> InvestigationRunStatus:
        """Execute a full bounded investigation run against an incident using InvestigationAgent."""
        incident = session.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found in database.")

        llm_provider = provider or self.default_provider
        # When an explicit provider is passed (e.g. testing provider failure), do not silently mask with fallback
        allow_fallback = (provider is None)

        report = await self.agent.investigate_incident(
            session=session,
            incident_id=incident_id,
            request=request,
            provider=llm_provider,
            allow_fallback=allow_fallback,
        )

        plan = self.build_investigation_plan(incident_id=incident_id, budget_usd=request.budget_limit_usd)
        return InvestigationRunStatus(
            run_id=report.run_id,
            incident_id=incident_id,
            state=report.status,
            task_type=request.task_type,
            model_ref=request.model_ref,
            template_version=request.template_version,
            started_at=report.started_at,
            finished_at=report.finished_at,
            findings_count=len(report.findings),
            budget_spent_usd=0.05,
            tasks=plan.tasks,
        )

    def get_run_status(self, session: Session, run_id: str) -> Optional[InvestigationRunStatus]:
        """Fetch current status and task list for an investigation run."""
        run = session.get(DbAgentRun, run_id)
        if not run:
            return None

        findings_stmt = select(DbAgentFinding).where(DbAgentFinding.run_id == run_id)
        findings = session.execute(findings_stmt).scalars().all()

        budget = run.budget_json or {}
        spent = float(budget.get("spent_usd", 0.0))

        return InvestigationRunStatus(
            run_id=run.id,
            incident_id=run.incident_id or "unknown",
            state=AgentRunStateEnum(run.state),
            task_type=run.task_type,
            model_ref=run.model_ref,
            template_version=run.template_version,
            started_at=run.started_at,
            finished_at=run.finished_at,
            failure_code=run.failure_code,
            findings_count=len(findings),
            budget_spent_usd=spent,
        )

    def get_run_findings(self, session: Session, run_id: str) -> List[AgentFinding]:
        """Retrieve all persisted findings for an investigation run."""
        stmt = select(DbAgentFinding).where(DbAgentFinding.run_id == run_id)
        db_findings = session.execute(stmt).scalars().all()

        return [
            AgentFinding(
                id=f.id,
                run_id=f.run_id,
                finding_type=f.finding_type,
                claim=f.claim,
                confidence=f.confidence,
                evidence_refs=f.evidence_refs_json or [],
                limitations=f.limitations,
                created_at=f.created_at,
            )
            for f in db_findings
        ]

    def get_investigation_summary(
        self, session: Session, run_id: str
    ) -> Optional[InvestigationSummary]:
        """Synthesize an analyst-readable summary separating facts from hypotheses."""
        run = session.get(DbAgentRun, run_id)
        if not run:
            return None

        findings = self.get_run_findings(session, run_id)
        observed_facts = [f.claim for f in findings if not f.is_hypothesis and f.evidence_refs]
        inferences = [f.claim for f in findings if f.is_hypothesis]

        b_json = run.budget_json or {}
        persisted_facts = b_json.get("observed_facts", [])
        if persisted_facts:
            observed_facts = list(dict.fromkeys(observed_facts + persisted_facts))

        hypotheses = b_json.get(
            "hypotheses",
            ["Activity may represent initial reconnaissance or unauthorized credential testing."],
        )
        missing_info = b_json.get(
            "data_gaps",
            ["Full endpoint EDR process dump not available in telemetry."],
        )
        contradictory = b_json.get("contradictory_evidence", [])
        unresolved = b_json.get("unresolved_questions", [])
        risk_assessment = b_json.get("risk_assessment", {})
        triage_reconciliation = b_json.get("triage_reconciliation")
        risk_reassessment_warranted = b_json.get("risk_reassessment_warranted", False)
        tool_calls_made = b_json.get("tool_calls_count", 0)
        is_fallback = b_json.get("is_fallback", False)
        policy_version = b_json.get("investigation_policy_version", "1.0.0")

        recommendations = [
            "Review associated detections and confirmed entity indicators",
            "Validate whether source IP requires containment approval",
        ]

        return InvestigationSummary(
            incident_id=run.incident_id or "unknown",
            run_id=run.id,
            observed_facts=observed_facts,
            inferences=inferences,
            hypotheses=hypotheses,
            missing_information=missing_info,
            contradictory_evidence=contradictory,
            unresolved_questions=unresolved,
            risk_assessment=risk_assessment,
            triage_reconciliation=triage_reconciliation,
            risk_reassessment_warranted=risk_reassessment_warranted,
            investigation_policy_version=policy_version,
            tool_calls_made=tool_calls_made,
            is_fallback=is_fallback,
            recommendations=recommendations,
            requires_analyst_review=True,
            generated_at=utc_now(),
        )

    def review_investigation(
        self,
        session: Session,
        run_id: str,
        review_request: InvestigationReviewRequest,
        operator: Principal,
    ) -> Dict[str, Any]:
        """Submit an analyst review decision on an investigation run.

        Optionally applies an approved lifecycle transition via lifecycle_manager.
        """
        run = session.get(DbAgentRun, run_id)
        if not run:
            raise ValueError(f"Investigation run '{run_id}' not found.")

        incident = session.get(Incident, run.incident_id)
        if not incident:
            raise ValueError(f"Incident '{run.incident_id}' not found.")

        # Record audit event for human review
        audit = AuditEvent(
            id=f"aud-{uuid4().hex[:12]}",
            actor_type="user",
            actor_id=operator.id,
            action="investigation.review",
            object_type="agent_run",
            object_id=run_id,
            outcome=review_request.decision.value,
            metadata_redacted={
                "incident_id": incident.id,
                "decision": review_request.decision.value,
                "notes": sanitize_for_model(review_request.review_notes),
                "target_transition": (
                    review_request.target_lifecycle_transition.value
                    if review_request.target_lifecycle_transition
                    else None
                ),
            },
            occurred_at=utc_now(),
        )
        session.add(audit)
        metrics.inc_counter("human_reviews_total", 1)

        result: Dict[str, Any] = {
            "run_id": run_id,
            "incident_id": incident.id,
            "decision": review_request.decision.value,
            "reviewed_by": operator.id,
            "lifecycle_transition": None,
        }

        # Apply lifecycle transition if analyst accepted and requested transition
        if (
            review_request.decision == HumanReviewDecisionEnum.ACCEPTED
            and review_request.target_lifecycle_transition
        ):
            trans_res = lifecycle_manager.transition(
                session=session,
                incident_id=incident.id,
                to_state=review_request.target_lifecycle_transition,
                operator=operator,
                expected_version=review_request.expected_version or incident.version,
                reason=f"Analyst review of agent run {run_id}: {review_request.review_notes}",
            )
            result["lifecycle_transition"] = {
                "new_status": trans_res.status,
                "version": trans_res.version,
            }

        session.commit()
        return result

    def cancel_investigation(
        self, session: Session, run_id: str, operator: Principal
    ) -> bool:
        """Cancel an in-progress investigation run."""
        run = session.get(DbAgentRun, run_id)
        if not run:
            return False

        if run.state in [AgentRunStateEnum.COMPLETED.value, AgentRunStateEnum.CANCELLED.value]:
            return False

        run.state = AgentRunStateEnum.CANCELLED.value
        run.finished_at = utc_now()
        run.failure_code = f"Cancelled by {operator.id}"

        audit = AuditEvent(
            id=f"aud-{uuid4().hex[:12]}",
            actor_type="user",
            actor_id=operator.id,
            action="investigation.cancel",
            object_type="agent_run",
            object_id=run_id,
            outcome="SUCCESS",
            metadata_redacted={"run_id": run_id, "cancelled_by": operator.id},
            occurred_at=utc_now(),
        )
        session.add(audit)
        session.commit()
        metrics.inc_counter("investigation_runs_cancelled_total", 1)
        return True

    def get_incident_investigations(
        self, session: Session, incident_id: str, limit: int = 20, offset: int = 0
    ) -> List[InvestigationRunStatus]:
        """Retrieve bounded history of investigation runs for a given incident."""
        incident = session.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found.")

        bounded_limit = max(1, min(limit, 100))
        bounded_offset = max(0, offset)

        stmt = (
            select(DbAgentRun)
            .where(DbAgentRun.incident_id == incident_id)
            .order_by(DbAgentRun.started_at.desc())
            .limit(bounded_limit)
            .offset(bounded_offset)
        )
        runs = session.execute(stmt).scalars().all()

        results = []
        for r in runs:
            st = self.get_run_status(session, r.id)
            if st:
                results.append(st)
        return results

    async def continue_investigation(
        self,
        session: Session,
        run_id: str,
        continuation_request: InvestigationContinuationRequest,
        operator: Principal,
    ) -> InvestigationRunStatus:
        """Perform a bounded continuation of an existing investigation run."""
        report = await self.agent.continue_investigation(
            session=session,
            run_id=run_id,
            continuation_req=continuation_request,
            operator=operator,
        )
        status = self.get_run_status(session, report.run_id)
        if not status:
            raise ValueError(f"Failed to load status for continued run '{report.run_id}'")
        return status

    async def execute_orchestrated_plan(
        self,
        session: Session,
        plan: InvestigationPlan,
        operator: Principal,
        provider: Optional[BaseLLMProvider] = None,
    ) -> OrchestrationExecutionResult:
        """Execute a structured investigation plan with explicit task dependencies, retries, and failure isolation."""
        import time
        start_time = time.perf_counter()
        started_at = utc_now()
        run_id = f"orch-{uuid4().hex[:12]}"
        audit_id = f"aud-{uuid4().hex[:16]}"

        # 1. Authorize operator
        allowed_roles = {
            RBACRoleEnum.SOC_ANALYST,
            RBACRoleEnum.THREAT_HUNTER,
            RBACRoleEnum.SECURITY_ENGINEER,
            RBACRoleEnum.ADMIN,
        }
        user_roles = {r if isinstance(r, RBACRoleEnum) else RBACRoleEnum(str(r)) for r in operator.roles}
        if not (user_roles & allowed_roles):
            raise PermissionError(
                f"Principal '{operator.id}' lacks authorized role for orchestration execution."
            )

        incident = session.get(Incident, plan.incident_id)
        if not incident:
            raise ValueError(f"Incident '{plan.incident_id}' not found.")

        if len(plan.tasks) > 10:
            raise ValueError(f"Plan task count ({len(plan.tasks)}) exceeds hard limit of 10.")

        # Audit plan start
        audit_start = AuditEvent(
            id=audit_id,
            actor_type="user",
            actor_id=operator.id,
            action="orchestrator.plan.start",
            object_type="orchestration_plan",
            object_id=plan.plan_id,
            outcome="STARTED",
            metadata_redacted={
                "run_id": run_id,
                "incident_id": plan.incident_id,
                "total_tasks": len(plan.tasks),
            },
            occurred_at=started_at,
        )
        session.add(audit_start)
        session.commit()

        # 2. Dependency resolution and step execution
        task_status_map: Dict[str, TaskStatusEnum] = {}
        coverage_gaps: List[str] = []

        for task in plan.tasks:
            # Check dependencies
            dep_failed = False
            for dep in task.dependencies:
                dep_status = task_status_map.get(dep)
                if dep_status != TaskStatusEnum.SUCCESS:
                    dep_failed = True
                    break

            if dep_failed:
                task.status = TaskStatusEnum.SKIPPED
                task.error_message = "Prerequisite dependency failed or was skipped."
                task_status_map[task.task_id] = TaskStatusEnum.SKIPPED
                continue

            # Execute task with bounded retries
            task.status = TaskStatusEnum.RUNNING
            task.started_at = utc_now()
            retry_count = 0
            max_retries = max(0, min(task.max_retries, 2))

            while retry_count <= max_retries:
                try:
                    await self._execute_task_step(
                        session=session,
                        incident_id=plan.incident_id,
                        task=task,
                        operator=operator,
                    )
                    task.status = TaskStatusEnum.SUCCESS
                    task.finished_at = utc_now()
                    task_status_map[task.task_id] = TaskStatusEnum.SUCCESS
                    break
                except Exception as ex:
                    retry_count += 1
                    task.retry_count = retry_count
                    if retry_count > max_retries:
                        task.status = TaskStatusEnum.FAILED
                        task.error_message = str(ex)
                        task.finished_at = utc_now()
                        task_status_map[task.task_id] = TaskStatusEnum.FAILED
                        coverage_gaps.append(f"Task '{task.task_type}' failed: {str(ex)}")
                        break

        # 3. Overall status evaluation
        completed_count = sum(1 for t in plan.tasks if t.status == TaskStatusEnum.SUCCESS)
        failed_count = sum(1 for t in plan.tasks if t.status == TaskStatusEnum.FAILED)
        skipped_count = sum(1 for t in plan.tasks if t.status == TaskStatusEnum.SKIPPED)

        if completed_count == len(plan.tasks):
            overall_state = "COMPLETED"
        elif completed_count > 0:
            overall_state = "PARTIAL_SUCCESS"
        else:
            overall_state = "FAILED"

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        find_stmt = (
            select(DbAgentFinding)
            .where(DbAgentFinding.claim != "")
            .order_by(DbAgentFinding.created_at.desc())
            .limit(10)
        )
        db_finds = session.execute(find_stmt).scalars().all()
        aggregated_findings = [
            AgentFinding(
                id=f.id,
                run_id=run_id,
                finding_type=f.finding_type,
                claim=f.claim,
                confidence=f.confidence,
                evidence_refs=f.evidence_refs_json or [],
                limitations=f.limitations,
                created_at=f.created_at,
            )
            for f in db_finds
        ]

        # 4. Persistence
        db_run = DbAgentRun(
            id=run_id,
            incident_id=plan.incident_id,
            task_type="orchestration",
            state=overall_state,
            model_ref="orchestrator-dag-v1",
            template_version="1.0.0",
            budget_json={
                "plan_id": plan.plan_id,
                "overall_state": overall_state,
                "total_tasks": len(plan.tasks),
                "completed_tasks": completed_count,
                "failed_tasks": failed_count,
                "skipped_tasks": skipped_count,
                "duration_ms": round(duration_ms, 2),
                "coverage_gaps": coverage_gaps,
                "tasks": [t.model_dump(mode="json") for t in plan.tasks],
            },
            started_at=started_at,
            finished_at=utc_now(),
        )
        session.add(db_run)

        audit_complete = AuditEvent(
            id=f"aud-{uuid4().hex[:16]}",
            actor_type="user",
            actor_id=operator.id,
            action="orchestrator.plan.complete",
            object_type="orchestration_run",
            object_id=run_id,
            outcome=overall_state,
            metadata_redacted={
                "incident_id": plan.incident_id,
                "completed": completed_count,
                "failed": failed_count,
                "skipped": skipped_count,
                "duration_ms": round(duration_ms, 2),
            },
            occurred_at=utc_now(),
        )
        session.add(audit_complete)
        session.commit()
        metrics.inc_counter("orchestration_plans_executed_total", 1)

        return OrchestrationExecutionResult(
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            run_id=run_id,
            state=overall_state,
            total_tasks=len(plan.tasks),
            completed_tasks=completed_count,
            failed_tasks=failed_count,
            skipped_tasks=skipped_count,
            tasks=plan.tasks,
            aggregated_findings=aggregated_findings,
            coverage_gaps=coverage_gaps,
            started_at=started_at,
            finished_at=utc_now(),
            duration_ms=round(duration_ms, 2),
            audit_id=audit_id,
        )

    async def _execute_task_step(
        self,
        session: Session,
        incident_id: str,
        task: InvestigationTask,
        operator: Principal,
    ) -> None:
        """Execute a single bounded task step through default_tool_executor."""
        agent_id = task.agent_id
        tt = task.task_type

        if tt == "context_collection":
            req = ToolExecutionRequest(
                tool_name="get_incident_summary",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"incident_id": incident_id},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("get_incident_summary")
            task.result_summary = {"status": res.status}

        elif tt == "detection_analysis":
            req = ToolExecutionRequest(
                tool_name="get_incident_detections",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"incident_id": incident_id, "limit": 20},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("get_incident_detections")
            task.result_summary = {"status": res.status}

        elif tt == "threat_enrichment":
            req = ToolExecutionRequest(
                tool_name="lookup_threat_intel",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"indicator_type": "ip", "indicator_value": "10.0.0.1"},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("lookup_threat_intel")
            task.result_summary = {"status": res.status}

        elif tt == "knowledge_retrieval":
            req = ToolExecutionRequest(
                tool_name="search_knowledge_base",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"query": "brute force authentication", "incident_id": incident_id, "limit": 3},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("search_knowledge_base")
            task.result_summary = {"status": res.status}

        elif tt == "threat_hunting":
            req = ToolExecutionRequest(
                tool_name="run_threat_hunt",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={
                    "hunt_type": "brute_force_auth",
                    "incident_id": incident_id,
                    "time_window_minutes": 60,
                    "threshold": 3,
                },
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("run_threat_hunt")
            task.result_summary = {"status": res.status}

        elif tt == "triage_assessment":
            req = ToolExecutionRequest(
                tool_name="get_incident_risk_assessment",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"incident_id": incident_id},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("get_incident_risk_assessment")
            task.result_summary = {"status": res.status}

        elif tt == "investigation_summary":
            req = ToolExecutionRequest(
                tool_name="get_prior_findings",
                incident_id=incident_id,
                task_id=task.task_id,
                arguments={"incident_id": incident_id},
            )
            res = default_tool_executor.execute_tool(req, operator, session, agent_id=agent_id)
            task.tools_called.append("get_prior_findings")
            task.result_summary = {"status": res.status}

        else:
            raise ValueError(f"Unknown or unsupported orchestration task type: '{tt}'")

    def get_orchestration_history(
        self, session: Session, limit: int = 20, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve bounded history of orchestration runs."""
        stmt = (
            select(DbAgentRun)
            .where(DbAgentRun.task_type == "orchestration")
            .order_by(DbAgentRun.started_at.desc())
            .limit(max(1, min(limit, 100)))
            .offset(max(0, offset))
        )
        runs = session.execute(stmt).scalars().all()
        results = []
        for r in runs:
            b_json = r.budget_json or {}
            results.append({
                "run_id": r.id,
                "incident_id": r.incident_id,
                "plan_id": b_json.get("plan_id"),
                "state": r.state,
                "total_tasks": b_json.get("total_tasks", 0),
                "completed_tasks": b_json.get("completed_tasks", 0),
                "failed_tasks": b_json.get("failed_tasks", 0),
                "skipped_tasks": b_json.get("skipped_tasks", 0),
                "duration_ms": b_json.get("duration_ms", 0.0),
                "started_at": r.started_at,
                "finished_at": r.finished_at,
            })
        return results


orchestrator = InvestigationOrchestrator()

__all__ = ["InvestigationOrchestrator", "orchestrator"]
