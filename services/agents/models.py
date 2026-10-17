"""CyberSentinel AI — Investigation Agent Contracts & Models (ADR-0002, ADR-0005)

Defines strongly-typed Pydantic schemas for agent task planning, evidence grounding,
finding generation, triage recommendations, and human review workflows.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from schemas.enums import AgentIdEnum, EventSeverityEnum, IncidentStateEnum


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AgentRunStateEnum(str, Enum):
    """Execution state machine for agent runs (Doc 10 & ADR-0002)."""

    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class TaskStatusEnum(str, Enum):
    """Status of an individual investigation task."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class HumanReviewDecisionEnum(str, Enum):
    """Decision made by an analyst on an investigation assessment."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_INFO = "NEEDS_INFO"


class EvidenceReference(BaseModel):
    """Reference to an authoritative evidence record backing an assertion."""

    evidence_id: str = Field(..., description="Unique ID of the cited record")
    source_type: str = Field(
        ...,
        description="Type of source record: 'event', 'detection', 'evidence', 'entity'",
    )
    record_id: str = Field(..., description="Underlying table record ID")
    verified: bool = Field(default=False, description="Whether record was verified in database")
    context_snippet: Optional[str] = Field(
        default=None, description="Concise supporting snippet from record"
    )


class AgentFinding(BaseModel):
    """Traceable, evidence-grounded finding produced by an agent."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str = Field(..., description="Originating agent run identifier")
    finding_type: str = Field(
        ...,
        description="Finding category: 'detection_analysis', 'threat_intel', 'attack_technique', 'entity_correlation', 'anomaly'",
    )
    claim: str = Field(..., description="Clear factual deduction or hypothesis")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence assessment in claim (0.0 to 1.0)"
    )
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="List of verified evidence/record IDs backing this claim",
    )
    is_hypothesis: bool = Field(
        default=False,
        description="True if finding is an unverified hypothesis rather than observed fact",
    )
    supporting_observations: List[str] = Field(
        default_factory=list, description="Observations supporting claim"
    )
    contradictory_evidence: List[str] = Field(
        default_factory=list, description="Contradictory observations or gaps"
    )
    limitations: Optional[str] = Field(
        default=None, description="Known caveats, blind spots, or missing telemetry"
    )
    created_at: datetime = Field(default_factory=utc_now)


class TriageAssessment(BaseModel):
    """Structured incident triage assessment produced by TriageAgent."""

    incident_id: str
    suspected_category: str = Field(
        ...,
        description="Suspected attack or incident category (e.g., 'credential_access', 'execution')",
    )
    recommended_severity: EventSeverityEnum = Field(
        ..., description="Recommended incident severity level"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in triage recommendation"
    )
    supporting_evidence: List[str] = Field(
        default_factory=list, description="IDs of backing evidence records"
    )
    contradictory_evidence: List[str] = Field(
        default_factory=list, description="Known contradictory signals"
    )
    missing_evidence: List[str] = Field(
        default_factory=list, description="Telemetry or logs needed to confirm"
    )
    potential_impact: str = Field(..., description="Estimated operational impact")
    recommended_steps: List[str] = Field(
        default_factory=list, description="Recommended next analyst investigation steps"
    )
    requires_analyst_review: bool = Field(
        default=True, description="Always requires human confirmation"
    )


class InvestigationSummary(BaseModel):
    """Analyst-readable summary clearly distinguishing facts from hypotheses."""

    incident_id: str
    run_id: str
    observed_facts: List[str] = Field(
        default_factory=list,
        description="Verified facts supported directly by database telemetry",
    )
    inferences: List[str] = Field(
        default_factory=list,
        description="Analytical deductions derived from observed facts",
    )
    hypotheses: List[str] = Field(
        default_factory=list,
        description="Unverified possibilities requiring further investigation",
    )
    missing_information: List[str] = Field(
        default_factory=list, description="Telemetry gaps and missing context"
    )
    contradictory_evidence: List[str] = Field(
        default_factory=list, description="Contradictory observations or conflicting signals"
    )
    unresolved_questions: List[str] = Field(
        default_factory=list, description="Critical unanswered questions requiring human analyst investigation"
    )
    risk_assessment: Dict[str, Any] = Field(
        default_factory=dict, description="Authoritative deterministic risk assessment"
    )
    triage_reconciliation: Optional[str] = Field(
        default=None, description="Explanation of whether findings support, contradict, or leave triage unresolved"
    )
    risk_reassessment_warranted: bool = Field(
        default=False, description="Whether material evidence changes warrant formal risk reassessment"
    )
    investigation_policy_version: str = Field(
        default="1.0.0", description="Policy version governing the investigation"
    )
    tool_calls_made: int = Field(default=0, description="Total authorized tool calls executed")
    is_fallback: bool = Field(default=False, description="True if produced by deterministic fallback")
    recommendations: List[str] = Field(
        default_factory=list, description="Recommended investigation or containment proposals"
    )
    requires_analyst_review: bool = Field(default=True, description="Human review requirement")
    generated_at: datetime = Field(default_factory=utc_now)


class InvestigationTask(BaseModel):
    """An individual bounded task executed as part of an investigation plan."""

    task_id: str = Field(default_factory=lambda: str(uuid4()))
    task_type: str = Field(..., description="Type of task (e.g. context_collection, detection_analysis)")
    agent_id: AgentIdEnum = Field(..., description="Target specialized agent role")
    status: TaskStatusEnum = Field(default=TaskStatusEnum.PENDING)
    dependencies: List[str] = Field(
        default_factory=list, description="Task IDs that must succeed before this task runs"
    )
    input_params: Dict[str, Any] = Field(default_factory=dict)
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=1)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    tool_budget: int = Field(default=10, ge=1, le=50)
    tools_called: List[str] = Field(default_factory=list)
    result_summary: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class InvestigationPlan(BaseModel):
    """Bounded, directed task plan for investigating an incident."""

    plan_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str
    tasks: List[InvestigationTask] = Field(default_factory=list)
    max_steps: int = Field(default=8, ge=1, le=20, description="Strict bound on task count")
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    budget_limit_usd: float = Field(default=1.0, ge=0.01, le=10.0)


class OrchestrationPlanRequest(BaseModel):
    """Request to generate a bounded multi-agent investigation plan."""

    incident_id: str
    max_steps: int = Field(default=6, ge=1, le=10)
    budget_limit_usd: float = Field(default=1.0, ge=0.01, le=10.0)
    focus_areas: Optional[List[str]] = Field(
        default=None,
        description="Optional focus areas: 'credential_access', 'threat_intel', 'lateral_movement'",
    )


class OrchestrationExecutionResult(BaseModel):
    """Result of an orchestrated multi-agent plan execution."""

    plan_id: str
    incident_id: str
    run_id: str
    state: str = Field(..., description="COMPLETED, PARTIAL_SUCCESS, FAILED, CANCELLED")
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    skipped_tasks: int
    tasks: List[InvestigationTask] = Field(default_factory=list)
    aggregated_findings: List[AgentFinding] = Field(default_factory=list)
    coverage_gaps: List[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: float = 0.0
    audit_id: str


class InvestigationRunRequest(BaseModel):
    """API request to launch a bounded agentic investigation."""

    task_type: str = Field(
        default="comprehensive_triage",
        description="Analysis task type: 'comprehensive_triage', 'detection_deep_dive', 'threat_enrichment'",
    )
    model_ref: str = Field(
        default="deterministic-rule-engine-v1",
        description="Designated LLM or SLM reference (e.g. 'gemini-1.5-pro', 'gpt-4o', 'deterministic-rule-engine-v1')",
    )
    template_version: str = Field(default="1.0.0", description="Prompt template version")
    budget_limit_usd: float = Field(default=1.0, ge=0.01, le=10.0)
    timeout_seconds: int = Field(default=60, ge=5, le=300)


class InvestigationRunStatus(BaseModel):
    """Full execution status response for an investigation run."""

    run_id: str
    incident_id: str
    state: AgentRunStateEnum
    task_type: str
    model_ref: str
    template_version: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    failure_code: Optional[str] = None
    findings_count: int = 0
    budget_spent_usd: float = 0.0
    tasks: List[InvestigationTask] = Field(default_factory=list)


class InvestigationReviewRequest(BaseModel):
    """Analyst review submission for an investigation run."""

    decision: HumanReviewDecisionEnum = Field(..., description="Analyst review decision")
    review_notes: str = Field(..., min_length=3, max_length=2000, description="Analyst justification")
    target_lifecycle_transition: Optional[IncidentStateEnum] = Field(
        default=None,
        description="Optional incident state to transition to upon acceptance (e.g. 'CONFIRMED', 'BENIGN')",
    )
    expected_version: Optional[int] = Field(
        default=None,
        description="Expected incident version for optimistic locking when transition is requested",
    )


class TriageModelOutput(BaseModel):
    """Raw structured output expected from AI model completion."""

    summary: str = Field(..., description="Concise incident summary (1-3 sentences)")
    suspected_activity: str = Field(..., description="Suspected threat category or mechanism")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model confidence score")
    recommended_severity: EventSeverityEnum = Field(..., description="Suggested incident severity")
    recommended_priority: str = Field(
        default="P3_MEDIUM",
        description="Suggested triage priority: P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW",
    )
    cited_evidence_ids: List[str] = Field(
        default_factory=list, description="Explicit record/evidence IDs cited by the model"
    )
    contradictory_evidence: List[str] = Field(
        default_factory=list, description="Contradictory findings or anomalous absences"
    )
    unresolved_questions: List[str] = Field(
        default_factory=list, description="Critical unanswered questions requiring human analyst investigation"
    )
    recommended_steps: List[str] = Field(
        default_factory=list, description="Next sequential investigation steps"
    )
    data_gaps: List[str] = Field(
        default_factory=list, description="Missing telemetry, unmonitored assets, or gaps"
    )
    uncertainties: List[str] = Field(
        default_factory=list, description="Analytical caveats and uncertainties"
    )


class TriageReport(BaseModel):
    """Authoritative, evidence-grounded, schema-validated triage assessment (Sprint 15)."""

    id: str = Field(default_factory=lambda: f"trg-{uuid4().hex[:24]}")
    incident_id: str
    lifecycle_state: str
    summary: str
    suspected_activity: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    recommended_severity: EventSeverityEnum
    recommended_priority: str = "P3_MEDIUM"
    supporting_evidence: List[EvidenceReference] = Field(default_factory=list)
    contradictory_evidence: List[str] = Field(default_factory=list)
    unresolved_questions: List[str] = Field(default_factory=list)
    attack_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel_findings: List[Dict[str, Any]] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    recommended_steps: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)
    uncertainties: List[str] = Field(default_factory=list)
    requires_analyst_review: bool = True
    provider_info: Any = Field(default_factory=dict)
    is_fallback: bool = False
    triage_policy_version: str = "1.0.0"
    created_at: datetime = Field(default_factory=utc_now)


class InvestigationContinuationRequest(BaseModel):
    """Request to perform a bounded continuation of an existing investigation (Sprint 17)."""

    additional_steps: int = Field(default=3, ge=1, le=10, description="Number of additional bounded steps")
    budget_limit_usd: float = Field(default=0.5, ge=0.01, le=5.0, description="Additional budget cap")
    additional_hypotheses: List[str] = Field(default_factory=list, description="Additional hypotheses to test")
    timeout_seconds: int = Field(default=30, ge=5, le=120)


class InvestigationReport(BaseModel):
    """Authoritative, evidence-grounded investigation report (Sprint 17)."""

    id: str = Field(default_factory=lambda: f"inv-{uuid4().hex[:20]}")
    incident_id: str
    run_id: str
    status: AgentRunStateEnum
    summary: str
    observed_facts: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    supporting_evidence: List[EvidenceReference] = Field(default_factory=list)
    contradictory_evidence: List[str] = Field(default_factory=list)
    unresolved_questions: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    authoritative_risk_score: float = 50.0
    authoritative_risk_band: str = "MEDIUM"
    risk_policy_version: str = "1.0.0"
    triage_reconciliation: str = "Triage assessment reconciled with investigation findings."
    risk_reassessment_warranted: bool = False
    attack_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel_observations: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    requires_analyst_review: bool = True
    tool_calls_made: int = 0
    investigation_policy_version: str = "1.0.0"
    is_fallback: bool = False
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: Optional[datetime] = None

