/**
 * CyberSentinel AI — TypeScript Type Definitions
 * Phase 5 / Sprint 24 Frontend Integration
 * Strictly matching backend FastAPI Pydantic & SQLAlchemy models.
 */

export type RBACRole =
  | "SOC_ANALYST"
  | "INCIDENT_COMMANDER"
  | "SECURITY_ENGINEER"
  | "SOC_MANAGER"
  | "ADMIN"
  | "VIEWER";

export type IncidentState =
  | "NEW"
  | "TRIAGED"
  | "INVESTIGATING"
  | "CONTAINMENT_PROPOSED"
  | "CONTAINED"
  | "REMEDIATED"
  | "CLOSED";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export interface ErrorEnvelope {
  error_code: string;
  message: string;
  details?: Record<string, unknown> | Array<unknown> | string;
  request_id?: string;
  timestamp?: string;
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "offline";
  version: string;
  checks: Record<string, string>;
  timestamp: string;
}

export interface ReadinessResponse {
  ready: boolean;
  dependencies: Record<string, boolean>;
  timestamp: string;
}

// Incidents
export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: SeverityLevel;
  status: IncidentState;
  confidence: number;
  priority_score?: number;
  version: number;
  owner_id?: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  entities?: IncidentEntity[];
  evidence?: EvidenceItem[];
}

export interface IncidentEntity {
  id: string;
  entity_type: string;
  entity_value: string;
  role: string;
}

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  source_id?: string;
  content: Record<string, unknown>;
  collected_at?: string;
}

export interface IncidentTimelineEntry {
  id?: string;
  timestamp: string;
  event_type: string;
  summary: string;
  details?: Record<string, unknown>;
}

export interface IncidentRiskAssessment {
  id: string;
  incident_id: string;
  risk_score: number;
  severity_level: SeverityLevel;
  confidence_score: number;
  contributing_factors?: Record<string, unknown>[];
  calculated_at: string;
  model_version?: string;
}

export interface IncidentTriageAssessment {
  id: string;
  incident_id: string;
  severity: SeverityLevel;
  confidence: number;
  recommended_playbook?: string;
  triage_summary: string;
  triaged_at: string;
  triaged_by?: string;
}

// Detections
export interface Detection {
  id: string;
  rule_id: string;
  rule_name?: string;
  severity: SeverityLevel;
  status: string;
  first_seen: string;
  last_seen: string;
  match_count?: number;
  source_events?: Record<string, unknown>[];
}

// Investigations
export interface InvestigationRun {
  id: string;
  incident_id: string;
  task_type: string;
  state: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | "AWAITING_REVIEW";
  model_ref: string;
  template_version: string;
  budget_limit_usd?: number;
  cost_incurred_usd?: number;
  started_at: string;
  completed_at?: string;
  findings_count?: number;
}

export interface InvestigationFinding {
  id: string;
  run_id: string;
  claim: string;
  claim_type: "CONFIRMED_FACT" | "HYPOTHESIS" | "UNKNOWN" | "CONTRADICTION";
  confidence: number;
  supporting_evidence_ids: string[];
  rationale?: string;
  created_at?: string;
}

export interface InvestigationSummary {
  run_id: string;
  incident_id: string;
  summary: string;
  key_findings: string[];
  evidence_gaps: string[];
  hypotheses: string[];
  contradictions: string[];
  recommended_actions: string[];
  citations: Array<{ claim: string; evidence_id: string; excerpt?: string }>;
}

// Threat Intel & MITRE ATT&CK
export interface ThreatIndicator {
  id: string;
  type: string;
  value: string;
  confidence: number;
  severity?: string;
  source: string;
  first_seen: string;
  last_seen?: string;
  expires_at?: string;
  tags?: string[];
  revoked?: boolean;
}

export interface ThreatSource {
  id: string;
  name: string;
  feed_type: string;
  url?: string;
  enabled: boolean;
  last_ingested_at?: string;
  indicator_count?: number;
}

export interface AttackTactic {
  id: string;
  name: string;
  description: string;
  technique_count?: number;
}

export interface AttackTechnique {
  id: string;
  tactic_id: string;
  name: string;
  description?: string;
  detection_rule_count?: number;
}

export interface AttackCoverage {
  tactics: Record<string, { total_techniques: number; covered_techniques: number; coverage_percentage: number }>;
  overall_coverage_percentage: number;
}

// Detection Engineering
export interface DetectionRule {
  id: string;
  title: string;
  status: string;
  severity: string;
  product?: string;
  service?: string;
  category?: string;
  author?: string;
  yaml?: string;
}

export interface DetectionCandidate {
  id: string;
  title: string;
  status: "DRAFT" | "VALIDATED" | "TESTED" | "REVIEWED" | "ACTIVATED" | "REJECTED";
  severity: string;
  product?: string;
  service?: string;
  objective?: string;
  rule_yaml?: string;
  raw_yaml?: string;
  validation_errors?: string[];
  test_outcomes?: Record<string, unknown>;
  reviewer_id?: string;
  reviewed_at?: string;
  review_notes?: string;
  created_at: string;
}

// Response Playbooks & Proposals
export interface ResponseActionCatalogueItem {
  action_type: string;
  name: string;
  description: string;
  target_entity_types: string[];
  requires_multi_person_approval: boolean;
  is_destructive: boolean;
  reversibility: "REVERSIBLE" | "IRREVERSIBLE" | "TIME_BOUND";
}

export interface ResponseProposal {
  id: string;
  incident_id: string;
  action_type: string;
  target_entity: string;
  action_payload: Record<string, unknown>;
  status: "PENDING_APPROVAL" | "APPROVED" | "REJECTED" | "EXECUTED" | "FAILED" | "REVOKED";
  creator_id: string;
  created_at: string;
  expires_at: string;
  reason: string;
  evidence_refs: string[];
  payload_hash: string;
  approvals?: ResponseApproval[];
  execution_result?: Record<string, unknown>;
}

export interface ResponseApproval {
  id: string;
  proposal_id: string;
  approver_id: string;
  decision: "APPROVED" | "REJECTED";
  reason: string;
  approved_at: string;
  policy_version: string;
}

// Benchmarking & Evaluation (Sprint 23)
export interface GroundTruthScenario {
  scenario_id: string;
  category: string;
  description: string;
  expected_detections?: string[];
  expected_incident_severity?: SeverityLevel;
  expected_techniques?: string[];
  prohibited_hallucinations?: string[];
  expected_mitre_tactics?: string[];
}

export interface GroundTruthDataset {
  dataset_id: string;
  version: string;
  description: string;
  name?: string;
  scenarios?: GroundTruthScenario[];
  labels?: GroundTruthScenario[];
}

export interface BenchmarkMetrics {
  detection_quality: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    negative_control_alert_rate: number | null;
    incident_creation_accuracy: number | null;
  };
  investigation_quality: {
    evidence_completeness: number | null;
    citation_validity_rate: number | null;
    supported_claim_rate: number | null;
    unsupported_claim_rate: number | null;
  };
  security_policy: {
    actual_unsafe_dispatches: number;
    safety_invariant_violations: number;
    unauthorized_tool_denial_rate: number | null;
  };
  operations: {
    total_scenarios_evaluated: number;
    duration_ms: number;
  };
}

export interface BenchmarkRunResult {
  run_id: string;
  dataset_version: string;
  execution_mode: "deterministic_offline" | "offline_mock" | "online_hybrid";
  executed_at: string;
  metrics: BenchmarkMetrics;
  per_scenario_results?: Record<string, {
    scenario_id: string;
    passed: boolean;
    observed_detections: string[];
    expected_detections: string[];
    hallucination_detected: boolean;
    duration_ms: number;
  }>;
}

export interface BaselineComparison {
  baseline_id: string;
  evaluated_at: string;
  status: "STABLE" | "IMPROVED" | "REGRESSION";
  deltas: Record<string, {
    metric: string;
    current: number | null;
    baseline: number | null;
    delta: number | null;
    status: "PASS" | "WARN" | "FAIL";
  }>;
}

// Events
export interface TelemetryEvent {
  id: string;
  timestamp: string;
  source_type: string;
  source_name: string;
  event_type: string;
  hostname?: string;
  username?: string;
  src_ip?: string;
  dst_ip?: string;
  process_name?: string;
  command_line?: string;
  severity?: SeverityLevel;
  raw?: Record<string, unknown>;
}

export interface EventSearchParams {
  q?: string;
  source_id?: string;
  event_type?: string;
  hostname?: string;
  username?: string;
  src_ip?: string;
  dst_ip?: string;
  severity?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}
