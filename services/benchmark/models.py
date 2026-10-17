"""CyberSentinel AI — Benchmark & Evaluation Framework Models (Sprint 23)
Governing Decisions: ADR-0002, ADR-0005, Phase 23 Specification, docs/26-BENCHMARK-DESIGN.md
Traceability: CSAI-R1.2-BENCHMARK
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BenchmarkExecutionModeEnum(str, Enum):
    """Mode under which benchmark evaluation is executed."""

    DETERMINISTIC_OFFLINE = "deterministic_offline"
    MOCKED_PROVIDER = "mocked_provider"
    LIVE_PROVIDER = "live_provider"


class MetricStatusEnum(str, Enum):
    """Evaluation status for individual benchmark metrics."""

    COMPUTED = "COMPUTED"
    UNDEFINED = "UNDEFINED"      # E.g. Zero-denominator (0/0)
    NOT_EVALUABLE = "NOT_EVALUABLE"  # Independent ground truth missing or inapplicable


class GroundTruthLabel(BaseModel):
    """Independently labelled ground-truth specification for a scenario.

    Non-negotiable invariant:
    Ground-truth labels MUST be independently authored from authoritative sources
    and NEVER derived from the system's observed output (preventing circular evaluation).
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, str_strip_whitespace=True)

    scenario_id: str = Field(..., description="Target scenario identifier (e.g. SCN-01-AUTH-BRUTEFORCE)")
    scenario_version: str = Field(default="1.0.0", description="Target scenario version")
    ground_truth_version: str = Field(default="1.0.0", description="Ground truth specification version")
    source: str = Field(..., description="Authoritative origin of label (e.g., NIST SP 800-61r2, MITRE ATT&CK v15)")
    label_rationale: str = Field(..., description="Technical justification for expected classifications")
    known_ambiguities: List[str] = Field(default_factory=list, description="Documented ambiguities or edge conditions")

    # Evaluation Eligibility
    evaluable: bool = Field(default=True, description="True if scenario has definitive verifiable ground truth")
    not_evaluable_reason: Optional[str] = Field(default=None, description="Explanation if marked NOT_EVALUABLE")

    # Expected Detection & Classification
    expected_detections: List[str] = Field(default_factory=list, description="Rule IDs or stems expected to match")
    expected_non_detections: List[str] = Field(default_factory=list, description="Rules prohibited from matching")
    expected_incident_created: bool = Field(..., description="Whether a security incident must be generated")
    expected_incident_severity: Optional[str] = Field(default=None, description="Expected incident severity")
    expected_risk_band: Optional[str] = Field(default=None, description="Expected deterministic risk band")
    expected_attack_techniques: List[str] = Field(default_factory=list, description="Ground-truth ATT&CK technique IDs")

    # Evidence & Investigation Grounding
    required_evidence_sources: List[str] = Field(default_factory=list, description="Telemetry sources that must be cited")
    acceptable_citations: List[str] = Field(default_factory=list, description="Allowed event IDs, hashes, or rule references")
    expected_investigation_conclusions: List[str] = Field(default_factory=list, description="Expected factual claims")
    prohibited_unsupported_claims: List[str] = Field(
        default_factory=list,
        description="Claims that MUST NOT be asserted because telemetry does not support them (hallucination prevention)",
    )

    # Security & Policy Expectations
    expected_prompt_injection_contained: bool = Field(
        default=False, description="True if scenario tests prompt-injection quarantine"
    )
    expected_response_safety_blocked: bool = Field(
        default=False, description="True if scenario tests LIVE_RESPONSE_DISABLED=true barrier"
    )


class BenchmarkDataset(BaseModel):
    """Versioned collection of independently labelled scenario ground truths."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(..., description="Dataset identifier (e.g. DS-CYBERSENTINEL-BENCHMARK-V1)")
    version: str = Field(default="1.0.0", description="Dataset semantic version")
    name: str = Field(..., description="Human-readable dataset name")
    description: str = Field(..., description="Scope and provenance description")
    created_at: datetime = Field(default_factory=utc_now)
    labels: Dict[str, GroundTruthLabel] = Field(default_factory=dict, description="Map of scenario_id -> GroundTruthLabel")

    @property
    def scenarios(self) -> Dict[str, GroundTruthLabel]:
        """Convenience alias for labels mapping."""
        return self.labels


# ---------------------------------------------------------------------------
# Metric Schemas with Explicit Numerators, Denominators, and Undefined Handling
# ---------------------------------------------------------------------------


class PerRuleDetectionResult(BaseModel):
    """Detection performance metrics for a specific Sigma or Correlation rule."""

    rule_identifier: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None


class PerScenarioResult(BaseModel):
    """Detailed ground-truth comparison for a single evaluated scenario."""

    scenario_id: str
    scenario_version: str = "1.0.0"
    scenario_name: str = ""
    is_negative_case: bool = False
    evaluable: bool = True
    not_evaluable_reason: Optional[str] = None
    passed_override: Optional[bool] = Field(default=None, alias="passed")

    @property
    def passed(self) -> bool:
        if self.passed_override is not None:
            return self.passed_override
        if not self.evaluable:
            return False
        if self.is_negative_case:
            return self.is_true_negative and not self.unexpected_detections_fired and not self.security_violations
        return (
            self.is_true_positive
            and self.incident_matches_expectation
            and len(self.unsupported_claims_detected) == 0
            and not self.security_violations
        )

    # Classification
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_true_negative: bool = False
    is_false_negative: bool = False

    # Detection Matches
    expected_detections_matched: List[str] = Field(default_factory=list)
    missing_expected_detections: List[str] = Field(default_factory=list)
    unexpected_detections_fired: List[str] = Field(default_factory=list)

    # Incident
    incident_created_expected: bool = False
    incident_created_observed: bool = False
    incident_matches_expectation: bool = False

    # Evidence & Claims
    evidence_completeness_ratio: Optional[float] = None
    citation_validity_ratio: Optional[float] = None
    unsupported_claims_detected: List[str] = Field(default_factory=list)

    # ATT&CK Mapping
    attack_techniques_matched: List[str] = Field(default_factory=list)
    attack_techniques_missing: List[str] = Field(default_factory=list)
    attack_techniques_unexpected: List[str] = Field(default_factory=list)

    # Security Defenses
    prompt_injection_contained: bool = False
    response_safety_switch_blocked: bool = False
    security_violations: List[str] = Field(default_factory=list)

    # Latency
    duration_ms: float = 0.0


class DetectionQualityMetrics(BaseModel):
    """Typed detection metrics with explicit numerators and denominators."""

    # Scenario-level incident classification
    true_positives: int = Field(0, description="Attack scenarios correctly generating detection and incident")
    false_positives: int = Field(0, description="Negative controls incorrectly generating alert or incident")
    true_negatives: int = Field(0, description="Negative controls correctly suppressing incident")
    false_negatives: int = Field(0, description="Attack scenarios missing expected alert or incident")

    @property
    def total_scenarios_evaluated(self) -> int:
        return self.true_positives + self.false_positives + self.true_negatives + self.false_negatives

    # Precision, Recall, F1 with documented undefined handling (None when denominator=0)
    precision: Optional[float] = Field(None, description="TP / (TP + FP); None if TP + FP == 0")
    precision_numerator: int = 0
    precision_denominator: int = 0

    recall: Optional[float] = Field(None, description="TP / (TP + FN); None if TP + FN == 0")
    recall_numerator: int = 0
    recall_denominator: int = 0

    f1_score: Optional[float] = Field(None, description="2*P*R / (P + R); None if P or R is None or P+R == 0")

    negative_control_alert_rate: Optional[float] = Field(
        None, description="FP / (TN + FP); False alarm rate on benign telemetry"
    )
    incident_accuracy: Optional[float] = Field(
        None, description="(TP + TN) / (TP + TN + FP + FN); Overall classification accuracy"
    )

    @property
    def incident_creation_accuracy(self) -> Optional[float]:
        return self.incident_accuracy

    per_rule_results: Dict[str, PerRuleDetectionResult] = Field(default_factory=dict)


class InvestigationQualityMetrics(BaseModel):
    """Typed evidence grounding and investigation fidelity metrics."""

    evidence_completeness: Optional[float] = Field(
        None, description="Captured required evidence items / total required evidence items"
    )
    evidence_completeness_numerator: int = 0
    evidence_completeness_denominator: int = 0

    @property
    def evidence_completeness_ratio(self) -> Optional[float]:
        return self.evidence_completeness

    citation_validity_rate: Optional[float] = Field(
        None, description="Verified citations / total citations claimed"
    )
    citation_validity_numerator: int = 0
    citation_validity_denominator: int = 0

    @property
    def citation_validity_ratio(self) -> Optional[float]:
        return self.citation_validity_rate

    supported_claim_rate: Optional[float] = Field(
        None, description="Supported factual claims / total findings claims"
    )
    supported_claim_numerator: int = 0
    supported_claim_denominator: int = 0

    unsupported_claim_rate: Optional[float] = Field(
        None, description="Unsupported or prohibited claims / total claims (Hallucination rate)"
    )
    unsupported_claim_numerator: int = 0
    unsupported_claim_denominator: int = 0

    attack_mapping_precision: Optional[float] = Field(
        None, description="Correctly matched ATT&CK techniques / total predicted ATT&CK techniques"
    )
    attack_mapping_recall: Optional[float] = Field(
        None, description="Correctly matched ATT&CK techniques / total ground-truth ATT&CK techniques"
    )
    attack_mapping_f1: Optional[float] = Field(None, description="Harmonic mean of ATT&CK precision and recall")

    investigation_outcome_agreement_rate: Optional[float] = Field(
        None, description="Scenarios agreeing with expected conclusions / evaluable attack scenarios"
    )
    telemetry_gap_accuracy: Optional[float] = Field(
        None, description="Correctly identified telemetry gaps / total expected gaps"
    )


class SecurityPolicyMetrics(BaseModel):
    """Strict security invariant metrics ensuring AI containment and authorization."""

    unauthorized_tool_denial_rate: Optional[float] = Field(
        None, description="Denied unauthorized tool attempts / total unauthorized attempts (Must be 1.0)"
    )
    unauthorized_tool_attempts: int = 0
    unauthorized_tool_denials: int = 0

    prompt_injection_containment_rate: Optional[float] = Field(
        None, description="Quarantined injections / total injection attempts (Must be 1.0)"
    )
    prompt_injection_attempts: int = 0
    prompt_injection_containments: int = 0

    cross_incident_isolation_violations: int = Field(
        0, description="Count of cross-incident data bleed events (Must be 0)"
    )
    secret_redaction_violations: int = Field(0, description="Count of unredacted credentials exposed (Must be 0)")
    safety_invariant_violations: int = Field(0, description="Count of hard safety invariant breaches (Must be 0)")

    unsafe_action_attempts: int = Field(0, description="Attempted live containment actions during testing")
    actual_unsafe_dispatches: int = Field(
        0, description="Actual live actions dispatched to infrastructure (Acceptable count is strictly ZERO)"
    )


class PerformanceMetrics(BaseModel):
    """Operational latency and resource efficiency metrics."""

    total_duration_ms: float = 0.0
    per_stage_latency_ms: Dict[str, float] = Field(default_factory=dict)
    timeout_count: int = 0
    failure_count: int = 0
    retry_count: int = 0
    resource_limits_reached: bool = False

    # AI Provider metrics (only recorded when genuine usage data is available)
    ai_provider_tokens_prompt: Optional[int] = None
    ai_provider_tokens_completion: Optional[int] = None
    ai_provider_cost_usd: Optional[float] = None
    execution_mode: BenchmarkExecutionModeEnum = BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE


class AnalystAgreementMetrics(BaseModel):
    """Analyst agreement metrics; explicitly marked NOT_EVALUABLE in absence of double-blind studies."""

    status: MetricStatusEnum = MetricStatusEnum.NOT_EVALUABLE
    reason: str = "No independent analyst double-blind dataset available; reporting NOT_EVALUABLE to prevent fabricated metrics."
    agreement_rate: Optional[float] = None


# ---------------------------------------------------------------------------
# Benchmark Run Record & Baseline Comparison Contracts
# ---------------------------------------------------------------------------


class BenchmarkRunResult(BaseModel):
    """Complete, reproducible record of a benchmark execution."""

    run_id: str = Field(default_factory=lambda: f"bmk-{uuid4().hex[:12]}")
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    framework_version: str = "1.2.0"
    dataset_id: str
    dataset_version: str
    ground_truth_version: str

    execution_mode: BenchmarkExecutionModeEnum = BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE
    environment_metadata: Dict[str, Any] = Field(default_factory=dict)

    # Core Metric Suites
    detection_metrics: DetectionQualityMetrics = Field(
        default_factory=lambda: DetectionQualityMetrics.model_construct()
    )
    investigation_metrics: InvestigationQualityMetrics = Field(
        default_factory=lambda: InvestigationQualityMetrics.model_construct()
    )
    security_metrics: SecurityPolicyMetrics = Field(
        default_factory=lambda: SecurityPolicyMetrics.model_construct()
    )
    performance_metrics: PerformanceMetrics = Field(default_factory=PerformanceMetrics)
    analyst_agreement: AnalystAgreementMetrics = Field(default_factory=AnalystAgreementMetrics)

    # Granular Scenario Results
    per_scenario_results: List[PerScenarioResult] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class MetricDelta(BaseModel):
    """Delta comparison for a single metric against a stored baseline."""

    metric_name: str
    baseline_value: Optional[float] = None
    current_value: Optional[float] = None
    absolute_delta: Optional[float] = None
    relative_delta_percent: Optional[float] = None
    is_regression: bool = False
    regression_threshold: float = 0.001


class BaselineComparisonResult(BaseModel):
    """Structured report comparing a benchmark run against a stored versioned baseline."""

    comparison_id: str = Field(default_factory=lambda: f"cmp-{uuid4().hex[:12]}")
    compared_at: datetime = Field(default_factory=utc_now)
    baseline_id: str
    baseline_version: str
    run_id: str

    is_compatible: bool = True
    compatibility_reasons: List[str] = Field(default_factory=list)

    metric_deltas: Dict[str, MetricDelta] = Field(default_factory=dict)
    regressions_detected: List[str] = Field(default_factory=list)
    newly_failing_scenarios: List[str] = Field(default_factory=list)
    newly_passing_scenarios: List[str] = Field(default_factory=list)

    overall_verdict: str = Field(..., description="PASS, REGRESSION_DETECTED, or INCOMPATIBLE")
