"""CyberSentinel AI — Detection Engineering Models & Enums (Sprint 19)
Governing Decisions: ADR-0004, ADR-0005, Phase 19 Specification
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CandidateRuleStatusEnum(str, Enum):
    """Authoritative review lifecycle states for candidate detection rules."""

    DRAFT = "DRAFT"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    VALIDATED = "VALIDATED"
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"


class ValidationSeverityEnum(str, Enum):
    """Diagnostic issue severity."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ValidationDiagnostic(BaseModel):
    """Individual rule validation diagnostic finding with actionable correction advice."""

    model_config = ConfigDict(extra="forbid")

    severity: ValidationSeverityEnum = Field(..., description="Severity of the validation diagnostic")
    code: str = Field(..., description="Machine-readable diagnostic code")
    field: Optional[str] = Field(None, description="Rule field or YAML path where issue was found")
    message: str = Field(..., description="Human-readable explanation of the issue")
    suggested_fix: Optional[str] = Field(None, description="Suggested correction or remediation")


class RuleValidationReport(BaseModel):
    """Comprehensive validation report produced for a Sigma rule."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool = Field(..., description="True if no ERROR severity diagnostics exist")
    rule_id: Optional[str] = Field(None, description="Rule identifier if parsed")
    rule_title: Optional[str] = Field(None, description="Rule title if parsed")
    diagnostics: List[ValidationDiagnostic] = Field(
        default_factory=list, description="List of diagnostics discovered during validation"
    )
    error_count: int = Field(0, description="Count of error-severity issues")
    warning_count: int = Field(0, description="Count of warning-severity issues")
    parsed_logsource: Dict[str, Any] = Field(
        default_factory=dict, description="Parsed logsource mapping"
    )
    detected_attack_ids: List[str] = Field(
        default_factory=list, description="Verified MITRE ATT&CK technique IDs extracted from tags"
    )
    unsupported_constructs: List[str] = Field(
        default_factory=list, description="Identified unsupported Sigma conditions or modifiers"
    )
    validated_at: datetime = Field(default_factory=utc_now, description="Timestamp of validation")


class RuleGenerationRequest(BaseModel):
    """Request to generate a candidate Sigma detection rule from structured security objective."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=255, description="Rule title")
    objective: str = Field(
        ..., min_length=5, description="Detection objective describing malicious behavior to detect"
    )
    target_technique: Optional[str] = Field(
        None, description="Target MITRE ATT&CK technique ID (e.g. T1059.001, T1105)"
    )
    category: Optional[str] = Field(
        default="process_creation", description="Logsource category (e.g. process_creation, network_connection, authentication)"
    )
    product: Optional[str] = Field(
        default="windows", description="Logsource product (e.g. windows, linux, network)"
    )
    service: Optional[str] = Field(default=None, description="Logsource service (e.g. sysmon, auditd)")
    required_fields: List[str] = Field(
        default_factory=list, description="Telemetry fields that must be inspected"
    )
    benign_filters: List[str] = Field(
        default_factory=list, description="Known administrative or benign patterns to exclude"
    )
    severity: str = Field(
        default="medium", description="Initial alert severity level (low, medium, high, critical)"
    )


class RuleExplanationResponse(BaseModel):
    """Analyst-friendly explanation and quality analysis of a detection rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="Rule identifier")
    title: str = Field(..., description="Rule title")
    summary: str = Field(..., description="Plain-language summary of what the rule detects")
    logic_breakdown: List[str] = Field(
        default_factory=list, description="Breakdown of selections, filters, and logical conditions"
    )
    expected_telemetry: Dict[str, Any] = Field(
        default_factory=dict, description="Expected logsource and normalized event fields"
    )
    attack_mappings: List[Dict[str, Any]] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK techniques with catalog details"
    )
    false_positive_risks: List[str] = Field(
        default_factory=list, description="Likely benign activities that could trigger this rule"
    )
    limitations_and_blindspots: List[str] = Field(
        default_factory=list, description="Potential attacker evasions and telemetry blind spots"
    )
    recommended_improvements: List[str] = Field(
        default_factory=list, description="Concrete suggestions to improve detection fidelity"
    )


class RuleTestRequest(BaseModel):
    """Request to safely test a Sigma detection rule against fixtures."""

    model_config = ConfigDict(extra="forbid")

    rule_yaml: str = Field(..., min_length=10, description="Raw YAML content of rule to test")
    fixtures: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="Optional custom synthetic event dictionaries to test against"
    )
    use_sample_fixtures: bool = Field(
        default=True, description="Whether to include built-in positive and negative sample fixtures"
    )
    historical_time_window_minutes: Optional[int] = Field(
        default=None, ge=5, le=1440, description="Optional window to replay recent canonical events from DB"
    )
    max_events: int = Field(default=50, ge=1, le=100, description="Maximum events to evaluate")


class RuleTestResult(BaseModel):
    """Outcome of safe rule execution against test fixtures."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., description="Rule identifier tested")
    total_events_evaluated: int = Field(0, description="Total events evaluated")
    matched_event_ids: List[str] = Field(
        default_factory=list, description="List of event IDs that triggered the rule"
    )
    passed_positive_fixtures: bool = Field(
        True, description="True if expected positive fixtures matched"
    )
    passed_negative_fixtures: bool = Field(
        True, description="True if expected negative/benign fixtures did not trigger alert"
    )
    false_positives_detected: int = Field(
        0, description="Count of negative/benign fixtures that unexpectedly matched"
    )
    coverage_gaps: List[str] = Field(
        default_factory=list, description="Missing telemetry fields or fixture gaps"
    )
    execution_time_ms: float = Field(0.0, description="Evaluation execution duration in milliseconds")
    limitations: List[str] = Field(
        default_factory=list, description="Limitations of synthetic fixture testing"
    )


class CandidateRuleResponse(BaseModel):
    """Full representation of a managed candidate detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Candidate entity ID (drc-*)")
    rule_id: str = Field(..., description="Sigma rule UUID")
    title: str = Field(..., description="Rule title")
    version: str = Field("1.0.0", description="Rule version")
    status: CandidateRuleStatusEnum = Field(..., description="Review lifecycle status")
    raw_yaml: str = Field(..., description="Raw Sigma YAML definition")
    original_rule_id: Optional[str] = Field(None, description="Original rule ID if updating existing rule")
    author_id: str = Field(..., description="Author principal ID")
    description: str = Field("", description="Rule description")
    severity: str = Field("medium", description="Alert severity")
    logsource: Dict[str, Any] = Field(default_factory=dict, description="Logsource definition")
    attack_techniques: List[str] = Field(default_factory=list, description="Mapped ATT&CK techniques")
    validation_report: Optional[RuleValidationReport] = Field(None, description="Latest validation report")
    test_results: Optional[RuleTestResult] = Field(None, description="Latest test results")
    review_notes: Optional[str] = Field(None, description="Review feedback or rationale")
    reviewed_by: Optional[str] = Field(None, description="Principal ID of reviewing engineer")
    reviewed_at: Optional[datetime] = Field(None, description="Timestamp of review decision")
    activated_at: Optional[datetime] = Field(None, description="Timestamp of production activation")
    activated_by: Optional[str] = Field(None, description="Principal ID who activated rule")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last modification timestamp")


class CandidateReviewRequest(BaseModel):
    """Human review decision on a candidate detection rule."""

    model_config = ConfigDict(extra="forbid")

    decision: str = Field(..., description="'APPROVED' or 'REJECTED'")
    notes: str = Field(..., min_length=3, max_length=1000, description="Review notes or justification")


class AdHocValidateRequest(BaseModel):
    """Ad-hoc rule validation request."""

    model_config = ConfigDict(extra="forbid")

    rule_yaml: str = Field(..., min_length=10, description="Sigma YAML content to validate")


class AdHocExplainRequest(BaseModel):
    """Ad-hoc rule explanation request."""

    model_config = ConfigDict(extra="forbid")

    rule_yaml: str = Field(..., min_length=10, description="Sigma YAML content to explain")
