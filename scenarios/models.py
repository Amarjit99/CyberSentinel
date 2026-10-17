"""CyberSentinel AI — Lab Scenario Models & Data Contracts (Sprint 22)
Governing Decisions: ADR-0005, Phase 22 Specification, CSAI-R1.1-LAB-SCENARIOS
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScenarioCategoryEnum(str, Enum):
    """Categorization for defensive simulation scenarios."""

    AUTHENTICATION = "authentication"
    PROCESS_EXECUTION = "process_execution"
    DISCOVERY = "discovery"
    CREDENTIAL_ACCESS = "credential_access"
    DNS_ACTIVITY = "dns_activity"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    ACCOUNT_TAKEOVER = "account_takeover"
    MULTI_STAGE = "multi_stage"
    PROMPT_INJECTION = "prompt_injection"
    POISONED_KNOWLEDGE = "poisoned_knowledge"
    GOVERNANCE_ABUSE = "governance_abuse"
    BENIGN_BASELINE = "benign_baseline"


class ScenarioStatusEnum(str, Enum):
    """Outcome status for scenario evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class ScenarioDefinition(BaseModel):
    """Declarative, data-driven contract defining a synthetic lab scenario.

    Non-negotiable invariant:
    A scenario definition is pure structured data and must NEVER be treated as executable code.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    scenario_id: str = Field(
        ...,
        pattern=r"^SCN-(?:[0-9]{2}|NEG-[0-9]{2})-[A-Z0-9_-]+$",
        description="Stable scenario identifier (e.g., SCN-01-AUTH-BRUTEFORCE, SCN-NEG-01-BENIGN-AUTH)",
    )
    version: str = Field(
        default="1.0.0",
        pattern=r"^\d+\.\d+\.\d+$",
        description="Semantic version string of the scenario definition",
    )
    name: str = Field(..., min_length=3, max_length=128, description="Human-readable scenario title")
    description: str = Field(..., min_length=10, max_length=1024, description="Detailed operational narrative")
    objective: str = Field(..., min_length=10, max_length=512, description="Defensive security validation goal")
    category: ScenarioCategoryEnum = Field(..., description="Tactical category of the simulated behavior")
    is_negative_case: bool = Field(
        default=False,
        description="True if scenario represents benign or negative control where no alarm should trigger",
    )

    # Telemetry and Schema Requirements
    required_telemetry_sources: List[str] = Field(
        default_factory=list,
        description="Telemetry source types required for execution (e.g., windows, linux, network)",
    )
    required_canonical_fields: List[str] = Field(
        default_factory=list,
        description="Mandatory canonical fields that synthetic events must populate",
    )
    attack_technique_ids: List[str] = Field(
        default_factory=list,
        description="Authoritative MITRE ATT&CK technique IDs expected to be exercised",
    )

    # Synthetic Event Fixtures
    synthetic_events: List[Dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="Chronological list of synthetic telemetry event dictionaries",
    )

    # Expected Ground Truth Behaviors
    expected_detection_rules: List[str] = Field(
        default_factory=list,
        description="Rule IDs or titles expected to match during Sigma evaluation",
    )
    unexpected_detection_rules: List[str] = Field(
        default_factory=list,
        description="Rule IDs or titles that MUST NOT match (for negative control validation)",
    )
    expected_correlation_rules: List[str] = Field(
        default_factory=list,
        description="Correlation rule IDs or names expected to trigger an incident",
    )
    expected_incident_severity: Optional[str] = Field(
        default=None,
        description="Expected severity level of created incident (low, medium, high, critical)",
    )
    expected_risk_band: Optional[str] = Field(
        default=None,
        description="Expected deterministic risk band (Low, Medium, High, Critical)",
    )
    expected_triage_severity: Optional[str] = Field(
        default=None,
        description="Expected triage priority or recommendation",
    )
    expected_investigation_hypotheses: List[str] = Field(
        default_factory=list,
        description="Key factual finding claims expected from grounded agent investigation",
    )
    expected_uncertainty_or_gaps: List[str] = Field(
        default_factory=list,
        description="Expected telemetry gaps or missing data sources to be identified by agent",
    )

    # Safety & Cleanup
    cleanup_policy: str = Field(
        default="session_rollback",
        description="Cleanup strategy: session_rollback, isolated_namespace, or prune_created_ids",
    )
    execution_timeout_seconds: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Maximum wall-clock execution time allowed for the scenario run",
    )


class ScenarioValidationResult(BaseModel):
    """Report of static schema and safety validation for a scenario definition."""

    scenario_id: str
    is_valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    event_count: int = 0
    validated_at: datetime = Field(default_factory=utc_now)


class ScenarioRunRecord(BaseModel):
    """Detailed observation record comparing expected vs. actual pipeline behaviors."""

    run_id: str = Field(default_factory=lambda: f"run-{uuid4().hex[:12]}")
    scenario_id: str
    scenario_version: str
    scenario_name: str
    executed_at: datetime = Field(default_factory=utc_now)
    duration_ms: float = 0.0
    status: ScenarioStatusEnum = ScenarioStatusEnum.PASS

    # Pipeline stages exercised
    stages_exercised: List[str] = Field(default_factory=list)

    # Stage 1: Ingestion & Normalization
    events_ingested_count: int = 0
    events_normalized_count: int = 0
    normalization_errors: List[str] = Field(default_factory=list)

    # Stage 2: Detection Matches
    matched_detection_rules: List[str] = Field(default_factory=list)
    missing_expected_detections: List[str] = Field(default_factory=list)
    unexpected_detections: List[str] = Field(default_factory=list)

    # Stage 3: Correlation & Incident
    correlated_rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    incident_severity: Optional[str] = None
    incident_status: Optional[str] = None
    incident_entities: List[str] = Field(default_factory=list)

    # Stage 4: Risk & Triage
    risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    triage_summary: Optional[str] = None
    triage_severity: Optional[str] = None

    # Stage 5: Investigation & Evidence Grounding
    investigation_run_id: Optional[str] = None
    finding_claims: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    unverified_evidence_refs: List[str] = Field(default_factory=list)
    telemetry_gaps_identified: List[str] = Field(default_factory=list)

    # Stage 6: Security & Governance Invariants
    security_violations: List[str] = Field(default_factory=list)
    prompt_injection_detected: bool = False
    prompt_injection_quarantined: bool = False
    response_safety_switch_verified: bool = False

    # Notes & Limitations
    notes: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class ScenarioSuiteReport(BaseModel):
    """Aggregate summary of multiple scenario evaluations."""

    report_id: str = Field(default_factory=lambda: f"rep-{uuid4().hex[:12]}")
    generated_at: datetime = Field(default_factory=utc_now)
    total_scenarios: int = 0
    passed_scenarios: int = 0
    failed_scenarios: int = 0
    partial_scenarios: int = 0
    total_events_processed: int = 0
    total_duration_ms: float = 0.0

    # Lab Metrics (explicitly identified as synthetic lab observations)
    lab_detection_rate: float = 0.0
    lab_false_positive_count: int = 0
    lab_grounding_fidelity: float = 1.0

    scenario_records: List[ScenarioRunRecord] = Field(default_factory=list)
