"""CyberSentinel AI — Typed Tool Schemas & Execution Contracts (Sprint 16)
Governing Decisions: ADR-0002, ADR-0004, CSAI-R0.5-TOOL-REGISTRY-AUTHORIZATION
"""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from schemas.enums import AgentIdEnum

# ==============================================================================
# General Execution Contracts
# ==============================================================================


class ToolExecutionRequest(BaseModel):
    """Normalized tool execution invocation request."""

    tool_name: str = Field(..., description="Target tool identifier in the registry")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation arguments")
    incident_id: Optional[str] = Field(default=None, description="Scoped incident identifier")
    task_id: Optional[str] = Field(default=None, description="Calling investigation task identifier")
    agent_id: Optional[AgentIdEnum] = Field(default=None, description="Calling agent identity")
    request_id: Optional[str] = Field(default_factory=lambda: str(uuid4()), description="Trace request identifier")


class ToolExecutionResult(BaseModel):
    """Standardized tool execution outcome."""

    tool_name: str
    tool_version: str = "1.0.0"
    status: str = Field(..., description="Execution outcome: SUCCESS, DENIED, or FAILED")
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    audit_id: Optional[str] = None
    policy_version: str = "1.0.0"

    @property
    def success(self) -> bool:
        return self.status == "SUCCESS"

    @property
    def result(self) -> Optional[Dict[str, Any]]:
        return self.data


# ==============================================================================
# Tool-Specific Typed Input / Output Schemas
# ==============================================================================


class IncidentScopedInput(BaseModel):
    """Base schema for tools scoped to an authoritative incident."""

    incident_id: str = Field(..., min_length=1, max_length=64, description="Target incident ID")


# 1. get_incident_summary
class GetIncidentSummaryInput(IncidentScopedInput):
    pass


class GetIncidentSummaryOutput(BaseModel):
    id: str
    title: str
    status: str
    severity: str
    confidence: float
    first_seen: str
    last_seen: str
    version: int


# 2. get_incident_detections
class GetIncidentDetectionsInput(IncidentScopedInput):
    limit: int = Field(default=50, ge=1, le=100, description="Max detections to retrieve")


class DetectionItem(BaseModel):
    detection_id: str
    rule_id: str
    rule_version: str
    severity: str
    link_reason: Optional[str] = None
    first_seen: str
    last_seen: str


class GetIncidentDetectionsOutput(BaseModel):
    incident_id: str
    total_count: int
    detections: List[Dict[str, Any]]


# 3. get_canonical_events
class GetCanonicalEventsInput(IncidentScopedInput):
    limit: int = Field(default=20, ge=1, le=50, description="Max canonical events to retrieve")


class GetCanonicalEventsOutput(BaseModel):
    incident_id: str
    total_count: int
    events: List[Dict[str, Any]]


# 4. get_incident_timeline
class GetIncidentTimelineInput(IncidentScopedInput):
    pass


class GetIncidentTimelineOutput(BaseModel):
    incident_id: str
    total_entries: int
    timeline: List[Dict[str, Any]]


# 5. get_incident_entities
class GetIncidentEntitiesInput(IncidentScopedInput):
    pass


class GetIncidentEntitiesOutput(BaseModel):
    incident_id: str
    total_count: int
    entities: List[Dict[str, Any]]


# 6. get_incident_evidence
class GetIncidentEvidenceInput(IncidentScopedInput):
    pass


class GetIncidentEvidenceOutput(BaseModel):
    incident_id: str
    total_count: int
    evidence: List[Dict[str, Any]]


# 7. get_prior_findings
class GetPriorFindingsInput(IncidentScopedInput):
    pass


class GetPriorFindingsOutput(BaseModel):
    incident_id: str
    total_count: int
    findings: List[Dict[str, Any]]


# 8. lookup_threat_intel
class LookupThreatIntelInput(BaseModel):
    indicator_type: str = Field(..., min_length=1, max_length=32, description="Type (e.g. ip, domain, hash)")
    indicator_value: str = Field(..., min_length=1, max_length=512, description="Indicator value")
    incident_id: Optional[str] = Field(default=None, description="Optional incident correlation ID")


class LookupThreatIntelOutput(BaseModel):
    indicator_type: str
    indicator_value: str
    reputation: str
    score: float = 0.0
    has_reputation_score: bool = False
    error: Optional[str] = None
    limitations: str
    provenance: Optional[List[Dict[str, Any]]] = None
    is_expired: Optional[bool] = None


# 9. get_incident_risk_assessment
class GetIncidentRiskAssessmentInput(IncidentScopedInput):
    pass


class GetIncidentRiskAssessmentOutput(BaseModel):
    assessment_id: Optional[str] = None
    incident_id: str
    overall_score: float
    risk_band: str
    policy_version: Optional[str] = None
    primary_drivers: Optional[List[Any]] = None
    uncertainties: Optional[List[Any]] = None
    limitations: Optional[List[Any]] = None
    evidence_refs: Optional[List[Any]] = None
    assessed_at: Optional[str] = None
    error: Optional[str] = None


# 10. search_knowledge_base
class SearchKnowledgeBaseInput(BaseModel):
    query: str = Field(..., min_length=2, max_length=500, description="Natural language search query")
    source_types: Optional[List[str]] = Field(
        default=None, description="Optional source types: attack, sigma, threat_intel, playbook, evidence"
    )
    incident_id: Optional[str] = Field(
        default=None, description="Optional incident ID for incident-scoped evidence isolation"
    )
    limit: int = Field(default=5, ge=1, le=20, description="Max candidate chunks to return")


class SearchKnowledgeBaseOutput(BaseModel):
    query: str
    retrieval_method: str = "lexical_bm25"
    total_results: int
    results: List[Dict[str, Any]]
    citations: List[str]
    generated_summary: Optional[str] = None


# 11. run_threat_hunt
class RunThreatHuntInput(BaseModel):
    hunt_type: str = Field(
        ...,
        description="Hunt category: 'brute_force_auth', 'suspicious_process', 'dns_beaconing', 'outbound_network', 'attack_technique', 'entity_activity'",
    )
    incident_id: Optional[str] = Field(
        default=None, description="Optional incident ID for scoped hunting"
    )
    time_window_minutes: int = Field(
        default=60, ge=5, le=1440, description="Search time window in minutes"
    )
    target_entities: Optional[List[str]] = Field(
        default=None, description="Target usernames, IP addresses, or hosts"
    )
    technique_id: Optional[str] = Field(
        default=None, description="MITRE ATT&CK technique ID (e.g. T1110)"
    )
    threshold: int = Field(
        default=5, ge=1, le=1000, description="Minimum frequency threshold"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Additional structured parameters"
    )


class RunThreatHuntOutput(BaseModel):
    hunt_id: str
    hunt_type: str
    status: str
    matched_events_count: int
    findings: List[Dict[str, Any]]
    coverage_gaps: List[str]
    uncertainty_notes: List[str]
    audit_id: str


# 12. generate_candidate_rule (Sprint 19: Detection Engineering Assistant)
class GenerateCandidateRuleInput(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Rule title")
    objective: str = Field(..., min_length=5, description="Detection objective describing activity to catch")
    target_technique: Optional[str] = Field(None, description="Target MITRE ATT&CK technique (e.g. T1059.001)")
    category: Optional[str] = Field("process_creation", description="Logsource category")
    product: Optional[str] = Field("windows", description="Logsource product")
    severity: str = Field("medium", description="Alert severity level")


class GenerateCandidateRuleOutput(BaseModel):
    candidate_id: str
    rule_id: str
    title: str
    status: str
    raw_yaml: str
    attack_techniques: List[str]
    is_valid: bool
    diagnostics_count: int


# 13. validate_sigma_rule (Sprint 19)
class ValidateSigmaRuleInput(BaseModel):
    rule_yaml: str = Field(..., min_length=10, description="Raw YAML content of rule to validate")


class ValidateSigmaRuleOutput(BaseModel):
    is_valid: bool
    rule_id: Optional[str] = None
    rule_title: Optional[str] = None
    error_count: int
    warning_count: int
    diagnostics: List[Dict[str, Any]]
    detected_attack_ids: List[str]


# 14. test_candidate_rule (Sprint 19)
class TestCandidateRuleInput(BaseModel):
    rule_yaml: str = Field(..., min_length=10, description="Raw YAML content of rule to test")
    fixtures: Optional[List[Dict[str, Any]]] = Field(None, description="Optional custom event fixtures")
    use_sample_fixtures: bool = Field(True, description="Whether to include built-in test fixtures")
    max_events: int = Field(50, ge=1, le=100, description="Maximum test events to evaluate")


class TestCandidateRuleOutput(BaseModel):
    rule_id: str
    total_events_evaluated: int
    matched_event_ids: List[str]
    passed_positive_fixtures: bool
    passed_negative_fixtures: bool
    false_positives_detected: int
    coverage_gaps: List[str]
    execution_time_ms: float


# 15. explain_detection_rule (Sprint 19)
class ExplainDetectionRuleInput(BaseModel):
    rule_yaml: str = Field(..., min_length=10, description="Raw YAML content of rule to explain")


class ExplainDetectionRuleOutput(BaseModel):
    rule_id: str
    title: str
    summary: str
    logic_breakdown: List[str]
    expected_telemetry: Dict[str, Any]
    attack_mappings: List[Dict[str, Any]]
    false_positive_risks: List[str]
    limitations_and_blindspots: List[str]
    recommended_improvements: List[str]


# ==============================================================================
# Tool Registry Metadata Representation
# ==============================================================================


class ToolMetadataDTO(BaseModel):
    """Public safe metadata DTO for tool discovery without leaking internal pointers."""

    name: str
    version: str
    description: str
    permitted_purpose: str
    required_permission: str
    allowed_roles: List[str]
    allowed_agents: List[str]
    read_only: bool
    timeout_seconds: float
    max_result_items: int
    max_result_bytes: int
    audit_enabled: bool
    is_enabled: bool
    policy_version: str = "2026.04"
    input_schema_name: str
    output_schema_name: str
    input_schema_json: Optional[Dict[str, Any]] = None
    output_schema_json: Optional[Dict[str, Any]] = None

    @property
    def is_read_only(self) -> bool:
        return self.read_only
