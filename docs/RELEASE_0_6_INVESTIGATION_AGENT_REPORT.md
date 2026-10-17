# CyberSentinel AI — Release 0.6 Exit Report
## Sprint 17: Investigation Agent
**Task ID:** `CSAI-R0.6-INVESTIGATION-AGENT`  
**Gate:** G-Sprint-17 — Evidence-Grounded Investigation Agent & Bounded Execution Boundary  
**Date:** 2026-10-17  
**Status:** COMPLETE  
**Workspace:** `d:/TEST/CyberSentinel`  
**Mandatory Safety Invariant:** `LIVE_RESPONSE_DISABLED=true` (Strictly Enforced)

---

## 1. Executive Summary & Preflight Findings

During the Sprint 17 preflight inspection of `docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md`, `docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md`, `docs/30-IMPLEMENTATION-ROADMAP.md`, `docs/PHASE_ROADMAP_RECONCILIATION_REPORT.md`, `docs/RELEASE_0_2_CONTEXT_INTELLIGENCE_REPORT.md`, `docs/RELEASE_0_3_EXPLAINABLE_RISK_ENGINE_REPORT.md`, `docs/RELEASE_0_4_TRIAGE_AGENT_REPORT.md`, and `docs/RELEASE_0_5_TOOL_REGISTRY_AUTHORIZATION_REPORT.md`, the platform baseline was established:
- **Prior Baseline:** Releases 0.1 through 0.5 established canonical ingestion, Sigma detections, stateful sliding-window correlation, incident lifecycle, deterministic risk scoring, ATT&CK mapping, threat intelligence normalization, triage agent execution, and the Sprint 16 typed tool registry & server-side authorization boundary (`ToolExecutionService`).
- **Baseline Test Suite:** **288 passing tests** across 62 source files.
- **Sprint 17 Objective:** Implement a bounded, evidence-grounded `InvestigationAgent` capable of structured multi-stage security incident investigation. The workflow must strictly operate through the authorized `ToolExecutionService` boundary, distinguish observed facts from hypotheses, validate evidence references against incident evidence stores, guard against prompt injection, preserve authoritative deterministic risk scores, reconcile with triage, provide bounded investigation continuation, and persist complete audit and finding provenance without arbitrary shell, filesystem writes, or autonomous response actions (`LIVE_RESPONSE_DISABLED=true`).

---

## 2. Implemented Architecture & Changed Files

Sprint 17 was implemented within the existing modular monolith architecture, preserving all existing tables, migrations, and boundaries:

### Modified Files:
1. `services/agents/models.py`:
   - Extended `InvestigationSummary` schema with:
     - `contradictory_evidence`: List of observations contradicting primary hypotheses.
     - `unresolved_questions`: Explicit list of unresolved telemetry/investigation questions.
     - `risk_assessment`: Dict preserving deterministic risk score, band, and scoring policy version.
     - `triage_reconciliation`: Structural breakdown (`aligned`, `explanation`, `triage_priority_level`).
     - `risk_reassessment_warranted`: Boolean flag indicating if newly surfaced evidence warrants risk re-calculation.
     - `investigation_policy_version`: Policy version identifier (defaulting to `"2026.04"`).
     - `tool_calls_made`: Metric tracking count of executed authorized tool calls.
     - `is_fallback`: Boolean indicating deterministic rule-based fallback mode.
     - `requires_analyst_review`: Boolean indicating human SOC analyst review requirement.
   - Added `InvestigationContinuationRequest` schema:
     - Allows bounded continuation with `additional_budget_tool_calls` (1-10) and focused `focus_questions`.
   - Added `InvestigationReport` schema for full structured export.

2. `services/agents/investigation.py`:
   - Created the core `InvestigationAgent` class implementing the complete 8-stage bounded investigation lifecycle:
     - **Stage 1: Authorization & Incident Validation**: Checks caller principal, RBAC roles (`SOC_ANALYST`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN`), and incident existence.
     - **Stage 2: Context Retrieval**: Bounded queries to `get_incident_summary`, `get_incident_detections`, `get_incident_evidence`, `get_incident_timeline`, `get_canonical_events`, `get_incident_entities`, `get_incident_risk_assessment`, and `get_prior_findings` strictly via `default_tool_executor.execute_tool(...)`.
     - **Stage 3: Evidence Gap & Contradiction Detection**: Identifies missing telemetry (e.g. absent process logs, auth telemetry) without treating absence as benign, and flags conflicting observations.
     - **Stage 4: Hypothesis Formulation**: Generates testable hypotheses (e.g., credential theft vs valid admin tool usage, malicious C2 beaconing vs telemetry noise).
     - **Stage 5: Bounded Evidence Expansion**: Performs targeted read-only lookups (e.g. `lookup_threat_intel`) within strict quota limits.
     - **Stage 6: Evidence Grounding & Fact/Hypothesis Separation**: Validates evidence references with `EvidenceValidator`; demotes ungrounded claims, purges cross-incident references, and caps confidence at 0.50 if ungrounded.
     - **Stage 7: Deterministic Risk & Triage Reconciliation**: Ingests authoritative deterministic risk score and policy version from `DeterministicRiskEngine`; strictly prevents LLM overrides, reconciles with prior triage findings, and determines if reassessment is warranted.
     - **Stage 8: Persistence & Audit**: Persists structured findings (`DbAgentFinding`), comprehensive execution metadata (`budget_json`), and emits immutable audit events (`AuditEvent`).
   - Implemented prompt injection defense:
     - `format_untrusted_context` with boundary delimiters: `<<<UNTRUSTED_INVESTIGATION_CONTEXT_START>>>` ... `<<<UNTRUSTED_INVESTIGATION_CONTEXT_END>>>`.
     - Static heuristic filters (`INJECTION_HEURISTICS`) flagging prompt injection attacks embedded in logs, usernames, or threat intel.
   - Implemented deterministic fallback mode:
     - Automatically falls back to deterministic rule-based analysis if AI provider fails and fallback is enabled.

3. `services/agents/orchestrator.py`:
   - Updated `InvestigationOrchestrator.execute_investigation()` to delegate execution to `InvestigationAgent`.
   - Enhanced `get_investigation_summary()` to parse rich investigation fields from `DbAgentRun.budget_json`.
   - Added `get_incident_investigations()` for bounded, paginated investigation history.
   - Added `continue_investigation()` to support bounded continuation workflows.

4. `services/agents/__init__.py`:
   - Exported `InvestigationAgent`, `investigation_agent`, `InvestigationReport`, and `InvestigationContinuationRequest`.

5. `apps/api/main.py`:
   - Added `GET /api/v1/incidents/{incident_id}/investigations`: Paginated history of investigation runs with limit/offset controls and authorization checks.
   - Added `POST /api/v1/investigations/{run_id}/continue`: Bounded investigation continuation endpoint supporting analyst-directed queries.

### Test Files Added:
6. `tests/unit/test_investigation_agent.py`: 8 comprehensive unit tests.
7. `tests/integration/test_investigation_execution.py`: 4 integration tests with live SQLite databases and API clients.
8. `tests/security/test_investigation_security.py`: 5 security tests validating RBAC, tool allowlists, cross-incident scoping, and prompt injection resistance.

---

## 3. Investigation Workflow & Bounded Execution Policies

### 3.1 Bounded Execution Envelopes
To prevent runaway autonomous loops and excessive resource consumption:
- **Max Tool Invocations:** Defaults to 15 tool calls per investigation run (configurable; continuation allows up to 10 additional calls).
- **Execution Timeout:** Enforced per-tool invocation (default 5.0 seconds) and per-agent execution.
- **Max Result Items:** Enforced per query (e.g. 50 events, 20 evidence items).
- **Max Response Bytes:** Truncation at 256KB to prevent payload flooding.
- **Step-Bounded Loops:** Investigation progresses sequentially through 8 discrete stages; no cyclic autonomous branching.

### 3.2 Deterministic Risk Engine & Triage Preservation
- **Score Immutability:** The investigation agent cannot alter or recompute risk scores. Authoritative risk scores are sourced directly from `DeterministicRiskEngine` (e.g. score `65.0`, band `HIGH`, policy `2026.04-deterministic`).
- **Triage Reconciliation:** Compares investigation discoveries against initial triage urgency and hypotheses. If lateral movement or verified C2 is confirmed, `risk_reassessment_warranted` is set to `True`, but the actual reassessment must be executed through the authorized risk service.
- **State Invariants:** Incident lifecycle states (e.g. `INVESTIGATING`) are never modified without authorized workflows.

---

## 4. Evidence Grounding & Provenance

### 4.1 Fact vs. Hypothesis Separation
The agent strictly separates:
- **Observed Facts:** Verified observations backed by specific, valid `evidence_id`s in the target incident (e.g., `ev-test-1`).
- **Hypotheses:** Inferences formulated to explain the observed facts.
- **Contradictory Evidence:** Observations that refute or complicate hypotheses (e.g. internal IP space matching or expected administrative maintenance windows).
- **Evidence Gaps / Missing Telemetry:** Explicitly cataloged without assuming absence implies benign activity.

### 4.2 Evidence Reference Validation (`EvidenceValidator`)
Every finding emitted by the agent undergoes strict validation:
1. `evidence_id` existence check against the target incident.
2. Cross-incident isolation: Any reference to an evidence item belonging to another incident is purged.
3. Grounding enforcement: If a claim references an ungrounded or fabricated identifier, the reference is purged and the finding's confidence is capped at `0.50` with an explicit limitation: `"Ungrounded claim: evidence refs [xyz] not found in incident"`.
4. Threat intelligence nuance: A no-match from threat intelligence feeds is explicitly flagged as `"No threat intelligence match; not proof of benign activity"`.

---

## 5. Tool Authorization Integration

All tool interactions are routed exclusively through `ToolExecutionService.execute_tool(...)`:
- **Identity & RBAC:** Principal authenticated and authorized for `AgentIdEnum.INVESTIGATION_AGENT` and allowed roles (`SOC_ANALYST`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN`).
- **Scoping Check:** All tool inputs specify `incident_id` which must match the authorized task context.
- **Audit Logging:** Every tool call (authorized success, role denial, cross-incident attempt, quota exceeded) generates an immutable `AuditEvent` in the database with actor details, action name (`tool:execute:{tool_name}`), outcome, and redacted parameters.
- **Prohibited Tools:** State-changing response actions, arbitrary shell execution, and non-read-only operations are completely blocked at registration time and execution time.

---

## 6. Persistence & API Changes

### 6.1 Database Persistence
No destructive migrations or schema changes were required. The platform leveraged existing tables:
- `agent_runs`: Stores investigation run records (`task_type="investigation"`, `state="COMPLETED"`, `started_at`, `finished_at`), with rich investigation summary details persisted within `budget_json`.
- `agent_findings`: Stores individual findings (`finding_type="FACT"|"HYPOTHESIS"|"SUMMARY"`, `claim`, `confidence`, `evidence_refs_json`, `limitations`).
- `audit_events`: Stores complete tool authorization and execution history.

### 6.2 REST API Endpoints
1. `POST /api/v1/incidents/{incident_id}/investigate`:
   - Initiates an investigation run for an incident with optional `model_ref` and `budget_tool_calls`.
2. `GET /api/v1/incidents/{incident_id}/investigations`:
   - Paginated retrieval of all investigation runs for an incident (`limit`, `offset`, total count).
3. `POST /api/v1/investigations/{run_id}/continue`:
   - Requests bounded continuation with additional budget and focus questions.
4. `GET /api/v1/investigations/{run_id}/report`:
   - Retrieves full structured investigation report.

---

## 7. Verification Commands & Results

All verification suites were run against the workspace:

### 7.1 Linter (Ruff)
```bash
.venv\Scripts\ruff check .
```
**Result:**
```
All checks passed!
```

### 7.2 Type Checker (Mypy)
```bash
.venv\Scripts\mypy services apps
```
**Result:**
```
Success: no issues found in 62 source files
```

### 7.3 Test Suite (Pytest)
```bash
.venv\Scripts\pytest
```
**Result:**
```
====================== 307 passed, 9 warnings in 18.83s =======================
```
- **Total Test Count:** 307 passed (19 new tests added in Sprint 17).
- **Unit Tests:** `tests/unit/test_investigation_agent.py` (8 passed).
- **Integration Tests:** `tests/integration/test_investigation_execution.py` (4 passed), `tests/integration/test_investigation_api.py` (3 passed).
- **Security Tests:** `tests/security/test_investigation_security.py` (5 passed).

---

## 8. Mocked vs. Live Test Distinctions

| Test Category | Execution Mechanism | External Dependencies | Notes |
|---|---|---|---|
| Unit Tests (`tests/unit/`) | In-memory mocks (`MockProvider`, Mock Repositories) | None | Fast execution; validates prompt formatting, boundary limits, grounding logic, and injection heuristics. |
| Integration Tests (`tests/integration/`) | In-memory SQLite engine (`create_engine("sqlite:///:memory:")`) | None | Validates end-to-end service interaction, foreign keys, database transactions, `ToolExecutionService`, and API routers. |
| Security Tests (`tests/security/`) | FastAPI TestClient + SQLite engine | None | Validates RBAC enforcement (`VIEWER` 403), tool allowlist restrictions, cross-incident isolation, and prompt injection resistance. |
| External Services | Simulated / Offline | None | Live network calls to external LLM providers and live containment endpoints were deliberately disabled per safety invariants (`LIVE_RESPONSE_DISABLED=true`). |

---

## 9. Known Limitations & Deferred Work

1. **Sprint 18 Scope Boundaries (Preserved):**
   - Multi-agent autonomous debate and agent orchestration trees are deferred to Sprint 18.
   - Vector database RAG (Retrieval-Augmented Generation) ingestion across historical external knowledge bases is deferred to Sprint 18.
   - Threat hunting campaign automation across unindexed telemetry pools is deferred to Sprint 18.
2. **Deterministic Risk Recalculation:**
   - The Investigation Agent flags when risk reassessment is warranted (`risk_reassessment_warranted=True`), but does not trigger the reassessment directly, respecting separation of duties.

---

## 10. Acceptance Decision

**Decision:** **COMPLETE**

**Justification:**
1. All requirements of Task `CSAI-R0.6-INVESTIGATION-AGENT` and Gate `G-Sprint-17` have been fulfilled.
2. Bounded, structured investigation workflow implemented with strict fact/hypothesis separation, evidence grounding validation, and triage/risk reconciliation.
3. Secure execution boundary enforced: all tool calls pass through `ToolExecutionService` and are audited in `audit_events`.
4. Prompt injection defense and deterministic fallback mechanisms tested and verified.
5. All 307 tests pass cleanly, with 0 Ruff linter errors and 0 Mypy type issues.
6. Safety invariant `LIVE_RESPONSE_DISABLED=true` strictly preserved throughout.
