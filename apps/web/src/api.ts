/**
 * CyberSentinel AI — Centralized API Client
 * Strictly calls actual FastAPI backend endpoints with RBAC role context and request correlation.
 */

import {
  BaselineComparison,
  BenchmarkRunResult,
  Detection,
  DetectionCandidate,
  DetectionRule,
  EventSearchParams,
  GroundTruthDataset,
  HealthResponse,
  Incident,
  IncidentRiskAssessment,
  IncidentTimelineEntry,
  IncidentTriageAssessment,
  InvestigationFinding,
  InvestigationRun,
  InvestigationSummary,
  RBACRole,
  ReadinessResponse,
  ResponseActionCatalogueItem,
  ResponseProposal,
  TelemetryEvent,
  ThreatIndicator,
  ThreatSource,
} from "./types";

let currentRole: RBACRole = "SOC_ANALYST";
let roleListeners: Array<(role: RBACRole) => void> = [];

export function getActiveRole(): RBACRole {
  return currentRole;
}

export function setActiveRole(role: RBACRole) {
  currentRole = role;
  roleListeners.forEach((listener) => listener(role));
}

export function subscribeRole(listener: (role: RBACRole) => void) {
  roleListeners.push(listener);
  return () => {
    roleListeners = roleListeners.filter((l) => l !== listener);
  };
}

export class ApiError extends Error {
  status: number;
  errorCode: string;
  details?: unknown;

  constructor(status: number, message: string, errorCode = "API_ERROR", details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = errorCode;
    this.details = details;
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
  maxRetries?: number;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method || "GET").toUpperCase();
  const isIdempotent = method === "GET" || method === "HEAD";
  const maxRetries = isIdempotent ? (options.maxRetries ?? 1) : 0;
  const timeoutMs = options.timeoutMs ?? 30000;

  let attempt = 0;
  let backoff = 500;

  while (true) {
    attempt++;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const headers = new Headers(options.headers || {});
    if (!headers.has("Authorization")) {
      headers.set("Authorization", `Bearer operator-${currentRole.toLowerCase()}-token`);
    }
    headers.set("X-Operator-Role", currentRole);
    if (!headers.has("Content-Type") && options.body && typeof options.body === "string") {
      headers.set("Content-Type", "application/json");
    }
    if (!headers.has("X-Request-ID")) {
      headers.set("X-Request-ID", `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
    }

    try {
      const response = await fetch(path, {
        ...options,
        headers,
        signal: options.signal || controller.signal,
      });
      clearTimeout(timeoutId);

      // Authorization denial: NEVER retry, fail immediately
      if (response.status === 401 || response.status === 403) {
        let msg = `Authorization denied (HTTP ${response.status}) for role ${currentRole}.`;
        try {
          const errJson = await response.json();
          if (errJson.message) msg = `${errJson.message} (Role: ${currentRole})`;
        } catch {
          // fallback
        }
        throw new ApiError(response.status, msg, "AUTHORIZATION_DENIED");
      }

      // Transient 502/503/504 errors on idempotent GET requests: bounded retry
      if ([502, 503, 504].includes(response.status) && isIdempotent && attempt <= maxRetries) {
        await new Promise((res) => setTimeout(res, backoff));
        backoff *= 2;
        continue;
      }

      if (!response.ok) {
        let errMsg = `Request to ${path} failed with HTTP ${response.status}`;
        let errCode = "HTTP_ERROR";
        let details: unknown;
        try {
          const errJson = await response.json();
          if (errJson.message) errMsg = errJson.message;
          if (errJson.error_code) errCode = errJson.error_code;
          if (errJson.details) details = errJson.details;
        } catch {
          // fallback
        }
        throw new ApiError(response.status, errMsg, errCode, details);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      clearTimeout(timeoutId);

      if (err instanceof ApiError) {
        throw err;
      }

      const isAbort = (err as Error)?.name === "AbortError";
      const errMsg = isAbort
        ? `Request to ${path} timed out after ${timeoutMs}ms`
        : `Network request to ${path} failed: ${(err as Error)?.message || String(err)}`;

      // Only retry transient network errors for idempotent requests
      if (isIdempotent && attempt <= maxRetries && !isAbort) {
        await new Promise((res) => setTimeout(res, backoff));
        backoff *= 2;
        continue;
      }

      throw new ApiError(0, errMsg, isAbort ? "REQUEST_TIMEOUT" : "NETWORK_ERROR");
    }
  }
}

export const api = {
  // System Health
  async getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>("/health");
  },

  async getReadiness(): Promise<ReadinessResponse> {
    return request<ReadinessResponse>("/ready");
  },

  // Incidents
  async getIncidents(): Promise<Incident[]> {
    const res = await request<Incident[] | { incidents: Incident[] }>("/api/v1/incidents");
    if (Array.isArray(res)) return res;
    if ("incidents" in res && Array.isArray(res.incidents)) return res.incidents;
    return [];
  },

  async getIncident(id: string): Promise<Incident> {
    return request<Incident>(`/api/v1/incidents/${id}`);
  },

  async transitionIncident(id: string, toState: string, version: number, reason?: string): Promise<Incident> {
    return request<Incident>(`/api/v1/incidents/${id}/transition`, {
      method: "POST",
      body: JSON.stringify({
        to_state: toState,
        version,
        reason: reason || `Transitioned to ${toState} by ${currentRole}`,
      }),
    });
  },

  async addIncidentNote(id: string, note: string): Promise<unknown> {
    return request(`/api/v1/incidents/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note }),
    });
  },

  async getIncidentTimeline(id: string): Promise<IncidentTimelineEntry[]> {
    const res = await request<{ timeline: IncidentTimelineEntry[] } | IncidentTimelineEntry[]>(`/api/v1/incidents/${id}/timeline`);
    if (Array.isArray(res)) return res;
    return res.timeline || [];
  },

  async triggerIncidentTriage(id: string, forceFallback = false): Promise<IncidentTriageAssessment> {
    return request<IncidentTriageAssessment>(`/api/v1/incidents/${id}/triage?force_fallback=${forceFallback}`, {
      method: "POST",
    });
  },

  async getIncidentTriage(id: string): Promise<IncidentTriageAssessment> {
    return request<IncidentTriageAssessment>(`/api/v1/incidents/${id}/triage?auto_triage=true`);
  },

  async triggerRiskAssessment(id: string): Promise<IncidentRiskAssessment> {
    return request<IncidentRiskAssessment>(`/api/v1/incidents/${id}/risk-assessment`, {
      method: "POST",
    });
  },

  async getIncidentRiskAssessment(id: string): Promise<IncidentRiskAssessment> {
    return request<IncidentRiskAssessment>(`/api/v1/incidents/${id}/risk-assessment?auto_calculate=true`);
  },

  // Investigations
  async getInvestigations(incidentId?: string): Promise<InvestigationRun[]> {
    const path = incidentId ? `/api/v1/incidents/${incidentId}/investigations` : "/api/v1/investigations";
    const res = await request<InvestigationRun[] | { runs: InvestigationRun[] }>(path);
    if (Array.isArray(res)) return res;
    if ("runs" in res && Array.isArray(res.runs)) return res.runs;
    return [];
  },

  async startInvestigation(incidentId: string, taskType = "comprehensive_triage"): Promise<InvestigationRun> {
    return request<InvestigationRun>(`/api/v1/incidents/${incidentId}/investigations`, {
      method: "POST",
      body: JSON.stringify({
        task_type: taskType,
        model_ref: "deterministic-rule-engine-v1",
        template_version: "1.0.0",
        budget_limit_usd: 1.0,
        timeout_seconds: 60,
      }),
    });
  },

  async getInvestigationRun(runId: string): Promise<InvestigationRun> {
    return request<InvestigationRun>(`/api/v1/investigations/${runId}`);
  },

  async getInvestigationFindings(runId: string): Promise<InvestigationFinding[]> {
    const res = await request<InvestigationFinding[] | { findings: InvestigationFinding[] }>(`/api/v1/investigations/${runId}/findings`);
    if (Array.isArray(res)) return res;
    if ("findings" in res && Array.isArray(res.findings)) return res.findings;
    return [];
  },

  async getInvestigationSummary(runId: string): Promise<InvestigationSummary> {
    const res = await request<InvestigationSummary | { summary: InvestigationSummary }>(`/api/v1/investigations/${runId}/summary`);
    if ("summary" in res && typeof res.summary === "object") return res.summary;
    return res as InvestigationSummary;
  },

  async reviewInvestigation(runId: string, decision: "ACCEPTED" | "REJECTED" | "MODIFIED", notes: string): Promise<unknown> {
    return request(`/api/v1/investigations/${runId}/review`, {
      method: "POST",
      body: JSON.stringify({
        decision,
        review_notes: notes,
      }),
    });
  },

  async cancelInvestigation(runId: string): Promise<unknown> {
    return request(`/api/v1/investigations/${runId}/cancel`, {
      method: "POST",
    });
  },

  // Detections & Alerts
  async getDetections(): Promise<Detection[]> {
    const res = await request<Detection[] | { detections: Detection[] }>("/api/v1/detections");
    if (Array.isArray(res)) return res;
    if ("detections" in res && Array.isArray(res.detections)) return res.detections;
    return [];
  },

  async getDetection(id: string): Promise<Detection> {
    return request<Detection>(`/api/v1/detections/${id}`);
  },

  // Threat Intel & MITRE ATT&CK
  async getThreatIndicators(): Promise<ThreatIndicator[]> {
    const res = await request<ThreatIndicator[] | { indicators: ThreatIndicator[] }>("/api/v1/threat-intel/indicators");
    if (Array.isArray(res)) return res;
    if ("indicators" in res && Array.isArray(res.indicators)) return res.indicators;
    return [];
  },

  async getThreatSources(): Promise<ThreatSource[]> {
    const res = await request<ThreatSource[] | { sources: ThreatSource[] }>("/api/v1/threat-intel/sources");
    if (Array.isArray(res)) return res;
    if ("sources" in res && Array.isArray(res.sources)) return res.sources;
    return [];
  },

  async lookupThreatIndicator(indicator: string): Promise<unknown> {
    return request(`/api/v1/threat-intel/lookup?indicator=${encodeURIComponent(indicator)}`);
  },

  async getAttackTactics(): Promise<Record<string, unknown>[]> {
    const res = await request<Record<string, unknown>[] | { tactics: Record<string, unknown>[] }>("/api/v1/attack/tactics");
    if (Array.isArray(res)) return res;
    if ("tactics" in res && Array.isArray(res.tactics)) return res.tactics;
    return [];
  },

  async getAttackTechniques(): Promise<Record<string, unknown>[]> {
    const res = await request<Record<string, unknown>[] | { techniques: Record<string, unknown>[] }>("/api/v1/attack/techniques");
    if (Array.isArray(res)) return res;
    if ("techniques" in res && Array.isArray(res.techniques)) return res.techniques;
    return [];
  },

  async getAttackCoverage(): Promise<Record<string, unknown>> {
    return request<Record<string, unknown>>("/api/v1/attack/coverage");
  },

  // Detection Engineering
  async getActiveRules(): Promise<DetectionRule[]> {
    const res = await request<DetectionRule[] | { rules: DetectionRule[] }>("/api/v1/rules");
    if (Array.isArray(res)) return res;
    if ("rules" in res && Array.isArray(res.rules)) return res.rules;
    return [];
  },

  async getDetectionCandidates(): Promise<DetectionCandidate[]> {
    const res = await request<DetectionCandidate[] | { candidates: DetectionCandidate[] }>("/api/v1/detection/candidates");
    if (Array.isArray(res)) return res;
    if ("candidates" in res && Array.isArray(res.candidates)) return res.candidates;
    return [];
  },

  async generateDetectionCandidate(params: {
    title: string;
    objective: string;
    severity?: string;
    category?: string;
    product?: string;
  }): Promise<DetectionCandidate> {
    return request<DetectionCandidate>("/api/v1/detection/candidates", {
      method: "POST",
      body: JSON.stringify({
        title: params.title,
        objective: params.objective,
        severity: params.severity || "medium",
        category: params.category || "process_creation",
        product: params.product || "windows",
        required_fields: ["EventID", "CommandLine"],
        benign_filters: [],
      }),
    });
  },

  async validateDetectionCandidate(candidateId: string): Promise<unknown> {
    return request(`/api/v1/detection/candidates/${candidateId}/validate`, { method: "POST" });
  },

  async testDetectionCandidate(candidateId: string, ruleYaml: string): Promise<unknown> {
    return request(`/api/v1/detection/candidates/${candidateId}/test`, {
      method: "POST",
      body: JSON.stringify({
        rule_yaml: ruleYaml,
        use_sample_fixtures: true,
        max_events: 50,
      }),
    });
  },

  async reviewDetectionCandidate(candidateId: string, decision: "APPROVED" | "REJECTED" | "APPROVE" | "REJECT", notes: string): Promise<unknown> {
    const normDecision = decision === "APPROVE" ? "APPROVED" : decision === "REJECT" ? "REJECTED" : decision;
    return request(`/api/v1/detection/candidates/${candidateId}/review`, {
      method: "POST",
      body: JSON.stringify({
        decision: normDecision,
        notes,
      }),
    });
  },

  async activateDetectionCandidate(candidateId: string): Promise<unknown> {
    return request(`/api/v1/detection/candidates/${candidateId}/activate`, { method: "POST" });
  },

  // Response Proposals & Approvals
  async getResponseCatalogue(): Promise<ResponseActionCatalogueItem[]> {
    const res = await request<ResponseActionCatalogueItem[] | { catalogue: ResponseActionCatalogueItem[] }>("/api/v1/response/catalogue");
    if (Array.isArray(res)) return res;
    if ("catalogue" in res && Array.isArray(res.catalogue)) return res.catalogue;
    return [];
  },

  async getIncidentProposals(incidentId: string): Promise<ResponseProposal[]> {
    const res = await request<ResponseProposal[] | { proposals: ResponseProposal[] }>(`/api/v1/incidents/${incidentId}/proposals`);
    if (Array.isArray(res)) return res;
    if ("proposals" in res && Array.isArray(res.proposals)) return res.proposals;
    return [];
  },

  async createProposal(incidentId: string, payload: {
    action_type: string;
    target_entity: string;
    reason: string;
    evidence_refs: string[];
    action_payload: Record<string, unknown>;
  }): Promise<ResponseProposal> {
    return request<ResponseProposal>(`/api/v1/incidents/${incidentId}/proposals`, {
      method: "POST",
      body: JSON.stringify({
        ...payload,
        validity_minutes: 60,
      }),
    });
  },

  async approveProposal(proposalId: string, reason: string): Promise<unknown> {
    return request(`/api/v1/proposals/${proposalId}/approve`, {
      method: "POST",
      body: JSON.stringify({
        decision: "APPROVED",
        reason,
        policy_version: "1.0.0",
      }),
    });
  },

  async revokeProposal(proposalId: string, reason: string): Promise<unknown> {
    return request(`/api/v1/proposals/${proposalId}/revoke`, {
      method: "POST",
      body: JSON.stringify({
        decision: "REJECTED",
        reason,
        policy_version: "1.0.0",
      }),
    });
  },

  async executeProposalDryRun(proposalId: string): Promise<unknown> {
    return request(`/api/v1/proposals/${proposalId}/execute`, {
      method: "POST",
      body: JSON.stringify({
        dry_run: true,
        target_environment: "lab",
      }),
    });
  },

  // Benchmarking & Evaluation (Sprint 23)
  async getGroundTruth(): Promise<GroundTruthDataset> {
    return request<GroundTruthDataset>("/api/v1/benchmarks/ground-truth");
  },

  async getBaselines(): Promise<string[] | { baselines: string[] }> {
    return request<string[] | { baselines: string[] }>("/api/v1/benchmarks/baselines");
  },

  async runBenchmark(mode: "deterministic_offline" | "offline_mock" | "online_hybrid" = "deterministic_offline", scenarioIds?: string[]): Promise<BenchmarkRunResult> {
    return request<BenchmarkRunResult>("/api/v1/benchmarks/run", {
      method: "POST",
      body: JSON.stringify({
        execution_mode: mode,
        scenario_ids: scenarioIds && scenarioIds.length > 0 ? scenarioIds : null,
      }),
    });
  },

  async compareBenchmark(runResult: BenchmarkRunResult, baselineId = "baseline_v1_0"): Promise<BaselineComparison> {
    return request<BaselineComparison>("/api/v1/benchmarks/compare", {
      method: "POST",
      body: JSON.stringify({
        run_result: runResult,
        baseline_id: baselineId,
        tolerance: 0.001,
      }),
    });
  },

  // Events Explorer
  async searchEvents(params: EventSearchParams): Promise<{ total: number; events: TelemetryEvent[] }> {
    const query = new URLSearchParams();
    if (params.q) query.set("q", params.q);
    if (params.source_id) query.set("source_id", params.source_id);
    if (params.event_type) query.set("event_type", params.event_type);
    if (params.hostname) query.set("hostname", params.hostname);
    if (params.username) query.set("username", params.username);
    if (params.src_ip) query.set("src_ip", params.src_ip);
    if (params.dst_ip) query.set("dst_ip", params.dst_ip);
    if (params.severity) query.set("severity", params.severity);
    if (params.start_time) query.set("start_time", params.start_time);
    if (params.end_time) query.set("end_time", params.end_time);
    query.set("limit", String(params.limit || 50));
    query.set("offset", String(params.offset || 0));

    const res = await request<{ total: number; events: TelemetryEvent[] } | TelemetryEvent[]>(`/api/v1/events/search?${query.toString()}`);
    if (Array.isArray(res)) return { total: res.length, events: res };
    return { total: res.total ?? res.events?.length ?? 0, events: res.events ?? [] };
  },

  async getEventMetrics(): Promise<Record<string, unknown>> {
    return request<Record<string, unknown>>("/api/v1/events/metrics");
  },

  async getQuarantinedEvents(): Promise<Record<string, unknown>[]> {
    const res = await request<Record<string, unknown>[] | { quarantined: Record<string, unknown>[] }>("/api/v1/events/quarantine");
    if (Array.isArray(res)) return res;
    if ("quarantined" in res && Array.isArray(res.quarantined)) return res.quarantined;
    return [];
  },

  // Tools & Administration
  async getRegisteredTools(): Promise<Record<string, unknown>[]> {
    const res = await request<Record<string, unknown>[] | { tools: Record<string, unknown>[] }>("/api/v1/tools");
    if (Array.isArray(res)) return res;
    if ("tools" in res && Array.isArray(res.tools)) return res.tools;
    return [];
  },
};
