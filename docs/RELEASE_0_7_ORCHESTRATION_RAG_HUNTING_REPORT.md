# CyberSentinel AI — Release 0.7 Exit Report
## Sprint 18: Orchestration, RAG & Threat Hunting
**Task ID:** `CSAI-R0.7-ORCHESTRATION-RAG-HUNTING`  
**Gate:** G-Sprint-18 — Multi-Agent Orchestration, Evidence-Grounded RAG & Controlled Threat Hunting  
**Date:** 2026-10-17  
**Status:** COMPLETE  
**Workspace:** `d:/TEST/CyberSentinel`  
**Mandatory Safety Invariant:** `LIVE_RESPONSE_DISABLED=true` (Strictly Enforced)

---

## 1. Preflight Findings & Verified Dependencies

During the Sprint 18 preflight review of `docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md`, `docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md`, `docs/30-IMPLEMENTATION-ROADMAP.md`, `docs/PHASE_ROADMAP_RECONCILIATION_REPORT.md`, ADRs, and Release Reports (0.2 through 0.6), the following baseline was verified:
- **Prior Baseline:** Releases 0.1 through 0.6 implemented event ingestion, Sigma detections, correlation, incident lifecycle, deterministic risk engine, ATT&CK mapping, threat intelligence, triage agent, typed tool registry with server-side authorization (`ToolExecutionService`), and the evidence-grounded `InvestigationAgent`.
- **Search Infrastructure Audit:** Roadmap reconciliation previously identified search infrastructure as a gap. Preflight codebase inspection confirmed that OpenSearch is not running as a persistent background daemon in this single-node environment, nor is an external vector database required for offline testing.
- **Backend Selection:** In accordance with the "Ponytail" principle (YAGNI, stdlib first, minimal working solution), an in-memory lexical BM25 retrieval engine (`retrieval_backend="in_memory_lexical_bm25"`, `retrieval_method="lexical_bm25"`) was implemented. It indexes approved static security corpora (ATT&CK catalog, Sigma rules, playbooks) and dynamic incident records (evidence, prior findings, threat intelligence).
- **Safety Invariant Verification:** Verified that `LIVE_RESPONSE_DISABLED=true` is strictly maintained across all response managers and policy engines. Zero autonomous containment or response execution tools were introduced.

---

## 2. Implemented Orchestration Architecture

The `InvestigationOrchestrator` (`services/agents/orchestrator.py`) was extended to support bounded directed acyclic graph (DAG) task execution:
- **Structured Task DAGs:** Plans are structured with explicit task dependencies (`dependencies: List[str]`). The orchestrator executes tasks in topological order.
- **Dependency Failure Isolation:** When a prerequisite task fails, dependent tasks are cleanly marked `TaskStatusEnum.SKIPPED` with explanation `"Prerequisite dependency failed or was skipped."` Unrelated branches continue uninterrupted.
- **Per-Task Execution Limits & Retries:** Tasks define explicit retry limits (max 2 retries per task, defaulting to 1 retry). Retried execution records `retry_count` and failure logs.
- **Execution Budgets & Bounds:** Investigation plans enforce strict bounds: maximum 10 tasks per plan (`len(plan.tasks) <= 10`), default 5 steps, timeout per step (10-15s), and tool budgets per task (max 10 tool calls per task).
- **Zero Direct Function Invocation:** The orchestrator never invokes model-proposed functions or shell scripts directly. All delegated investigation tasks dispatch through the central server-side authorized `ToolExecutionService`.
- **Status & History Tracking:** Plan and task states are tracked through `TaskStatusEnum` (`PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `SKIPPED`, `CANCELLED`). Full orchestration runs are persisted to `DbAgentRun` with `task_type="orchestration"` and complete execution telemetry in `budget_json`.

---

## 3. Retrieval Backend & Retrieval Method

- **Retrieval Engine (`services/rag/engine.py`):** Implemented `RAGEngine` using an in-memory inverted index and standard Okapi BM25 scoring algorithm ($k_1=1.5, b=0.75$).
- **Deterministic Transparency:** The engine explicitly returns `retrieval_backend="in_memory_lexical_bm25"` in its index status and `retrieval_method="lexical_bm25"` in query results. It never mischaracterizes lexical BM25 matching as vector embeddings or semantic search.
- **Query Bounds & Guardrails:** Query requests enforce input length limits (max 500 characters), result limits (max 20 candidates, defaulting to 5), and score thresholds (minimum BM25 score $> 0.10$).
- **No-Match & Fallback Behavior:** When no matching documents exist or scores fall below the relevance threshold, the engine explicitly returns empty results (`results=[]`) and synthesized answer: `"No verified security documentation or incident records match the query."`

---

## 4. Indexed Data Sources & Access-Control Behavior

The RAG engine supports five approved source categories (`RAGSourceTypeEnum`):
1. **MITRE ATT&CK Catalog (`attack_catalog`):** Indexed from the local ATT&CK enterprise catalog (`T1059`, `T1059.001`, `T1110`, etc.).
2. **Sigma Detection Rules (`rules/sigma`):** Indexed from local YAML detection rules with rule ID, title, description, and tags.
3. **Internal Security Playbooks (`playbooks/`):** Indexed from approved SOPs and playbook markdown documents.
4. **Threat Intelligence (`threat_intel`):** Sourced from the local database threat intelligence indicators and attribution summaries.
5. **Incident Artifacts (`incident_evidence`, `incident_findings`):** Dynamically indexed from `Evidence` and `AgentFinding` tables, strictly scoped to an `incident_id`.

### Access Control & Tenant/Incident Isolation
- **Role-Based Access Control:** Pre-query authorization verifies the operator's principal roles. Unprivileged roles (`VIEWER`) are denied with HTTP 403 / `PermissionError`.
- **Incident Scoping & Anti-Leakage:** Chunks tagged with an `incident_id` are strictly isolated. Queries specifying `incident_id="incident-A"` or queries by unauthorized principals are blocked from retrieving chunks belonging to `incident-B`. Global documents (ATT&CK, Sigma) remain accessible across incidents.
- **Audit Logging:** Every RAG query and index update generates an immutable `AuditEvent` record with duration, candidate counts, and sanitized query parameters.

---

## 5. Provenance & Citation Validation

- **Deterministic Citation Labels:** Every indexed chunk receives an immutable, human-auditable citation label (e.g. `[ATT&CK:T1059.001]`, `[SIGMA:powershell_download]`, `[EVIDENCE:ev-456]`, `[FINDING:fnd-789]`).
- **Strict Citation Validation:** Before returning synthesized answers, `RAGEngine._generate_grounded_answer()` cross-references all citation tags in the answer against the actual list of retrieved and scored candidate chunks.
- **Zero Hallucinated Citations:** Any hallucinated, unverified, or cross-incident citation tag is stripped from the returned `citations` list.
- **Prompt Injection Boundary Isolation:** Retrieved document content is wrapped in strict boundary delimiters:
  ```text
  <<<UNTRUSTED_RETRIEVED_DOCUMENT_START [ATT&CK:T1059.001]>>>
  ... untrusted content ...
  <<<UNTRUSTED_RETRIEVED_DOCUMENT_END>>>
  ```
- **Injection Heuristic Defense:** Content containing prompt injection directives (e.g., `IGNORE ALL PREVIOUS INSTRUCTIONS`, `SYSTEM OVERRIDE`, `GRANT ROOT`, `CONTAIN HOST`) is automatically flagged with `injection_flagged=True` and isolated from system instruction contexts.

---

## 6. Controlled Threat Hunting & Supported Telemetry

Implemented `ThreatHuntingService` (`services/hunting/service.py`) providing structured, bounded hypothesis-driven threat hunting:
- **Structured Hunt Strategies (`HuntTypeEnum`):**
  1. `brute_force_auth`: Discovers repeated failed logins exceeding threshold within time window.
  2. `suspicious_process`: Detects Lolbins, unauthorized PowerShell, and command-line execution (e.g., `T1059.001`).
  3. `dns_beaconing`: Identifies high-frequency or anomalous DNS queries (e.g., `T1071.004`).
  4. `outbound_network`: Analyzes abnormal egress and C2 network telemetry (e.g., `T1071.001`).
  5. `attack_technique`: Structured search mapping directly to MITRE ATT&CK technique IDs.
- **Bounded Parameter Validation:** Requires validated parameters (`time_window_minutes` $\in [5, 1440]$, `threshold` $\in [1, 1000]$, `target_entities`, `technique_id`). No arbitrary SQL or natural language query compilation.
- **Explicit Telemetry Gap Reporting:** When required telemetry is absent (e.g., missing Sysmon process logs or auth auditd logs), the engine records explicit `coverage_gaps` (e.g., `"Endpoint process command-line telemetry is absent or unindexed."`).
- **Explicit Uncertainty Notes:** The engine explicitly appends uncertainty disclaimers:
  - *"Absence of detections in the evaluated time window does not prove that the environment is uncompromised."*
  - *"Hunting results are bounded by available and ingested telemetry sources."*
- **Persistence & Audit:** Hunt jobs are recorded in `DbAgentRun` with `task_type="threat_hunting"` and complete results in `budget_json`, along with `AuditEvent` logs.

---

## 7. APIs, Models & Migrations

### REST Endpoints Added
| Method | Path | Summary | Authorized Roles |
|---|---|---|---|
| `POST` | `/api/v1/rag/query` | Execute evidence-grounded RAG query | `SOC_ANALYST`, `DETECTION_ENGINEER`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN` |
| `GET` | `/api/v1/rag/sources` | Inspect RAG index status & sources breakdown | `SOC_ANALYST`, `DETECTION_ENGINEER`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN` |
| `POST` | `/api/v1/hunting/jobs` | Launch structured threat hunt job | `THREAT_HUNTER`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `ADMIN` |
| `GET` | `/api/v1/hunting/jobs/{hunt_id}` | Retrieve hunt job status & findings | `THREAT_HUNTER`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `ADMIN` |
| `GET` | `/api/v1/hunting/jobs` | List recent threat hunting jobs | `THREAT_HUNTER`, `SOC_ANALYST`, `SECURITY_ENGINEER`, `ADMIN` |
| `POST` | `/api/v1/orchestrator/plans` | Generate bounded investigation DAG plan | `SOC_ANALYST`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN` |
| `POST` | `/api/v1/orchestrator/execute` | Execute orchestrated investigation plan | `SOC_ANALYST`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN` |
| `GET` | `/api/v1/orchestrator/history` | List recent orchestration runs | `SOC_ANALYST`, `THREAT_HUNTER`, `SECURITY_ENGINEER`, `ADMIN` |

### Tool Registry Integration
Added two authorized tools to the central `ToolRegistry` (`services/agents/registry.py`):
1. `search_knowledge_base`: Read-only RAG knowledge retrieval tool (`SearchKnowledgeBaseInput` / `SearchKnowledgeBaseOutput`).
2. `run_threat_hunt`: Read-only threat hunting tool (`RunThreatHuntInput` / `RunThreatHuntOutput`).

Both tools strictly enforce `read_only=True`, execution timeout limits, and route exclusively through `ToolExecutionService`.

---

## 8. Exact Commands & Test Results

### 8.1 Unit, Integration & Security Tests for Sprint 18
```bash
.venv\Scripts\python.exe -m pytest tests/unit/test_orchestration.py tests/unit/test_rag.py tests/unit/test_threat_hunting.py tests/integration/test_sprint18_integration.py tests/security/test_sprint18_security.py tests/unit/test_investigation_orchestrator.py tests/unit/test_tool_registry.py tests/integration/test_tool_api.py -v
```
**Result:** `53 passed, 2 warnings in 4.35s` (100% passing).

### 8.2 Full Repository Regression Test Suite
```bash
.venv\Scripts\python.exe -m pytest -q
```
**Result:** `333 passed, 9 warnings in 18.35s` (100% passing across the entire repository).

### 8.3 Code Formatting & Linting
```bash
.venv\Scripts\ruff.exe check .
```
**Result:** `All checks passed!`

### 8.4 Static Type Checking
```bash
.venv\Scripts\mypy.exe services apps
```
**Result:** `Success: no issues found in 68 source files`

---

## 9. Mocked vs. Live Infrastructure Verification

| Component | Status | Details |
|---|---|---|
| **Retrieval Backend** | **LIVE (In-Memory)** | Okapi BM25 inverted index operates directly in memory over actual ATT&CK JSON catalog, Sigma YAML files, playbooks, and SQLite persistence. |
| **OpenSearch Cluster** | **UNAVAILABLE / DEFERRED** | OpenSearch daemon is not deployed in local test environment; lexical BM25 is the verified, authoritative fallback backend. |
| **LLM Provider (Primary)** | **DETERMINISTIC / OFFLINE** | Uses `DeterministicRuleProvider` and `MockLLMProvider` for offline test suites; zero credentials leaked or required for CI/local verification. |
| **Threat Intelligence Feeds** | **LIVE (Local Database)** | Real SQLite-backed threat intelligence tables (`DbThreatIntelRecord`) queried during RAG indexing and hunting. |
| **Execution Safety** | **LIVE** | `ToolExecutionService` strictly validates permissions, scopes incident IDs, enforces quotas, and commits `AuditEvent` records. |
| **Response Actions** | **DISABLED** | `LIVE_RESPONSE_DISABLED=true` is strictly maintained and asserted in security tests. |

---

## 10. Known Limitations & Remaining Roadmap Gaps

1. **Distributed Workflow Engine:** Orchestration is bounded within the monolithic application process; distributed orchestrators (e.g. Celery / Temporal) are intentionally omitted per YAGNI.
2. **Dense Semantic Embeddings:** RAG utilizes lexical BM25 search. Vector embeddings and hybrid dense-sparse search remain deferred until approved embedding endpoints and vector stores are provisioned in future releases.
3. **Continuous Streaming Hunting:** Threat hunting executes point-in-time bounded batch evaluations over indexed tables rather than real-time distributed stream-hunting.

---

## 11. Acceptance Decision

### Decision: **COMPLETE**

**Justification:**
1. Bounded multi-agent investigation orchestration with explicit DAG task dependencies, timeouts, retries, and failure isolation is fully implemented and verified.
2. Evidence-grounded RAG with strict provenance, prompt-injection defense delimiters, incident-level access isolation, and citation validation is fully operational using lexical BM25.
3. Controlled threat hunting executes validated structured queries, records coverage gaps when telemetry is absent, and avoids false claims of security.
4. `LIVE_RESPONSE_DISABLED=true` remains strictly enforced. All tool executions route exclusively through `ToolExecutionService`.
5. 333 tests passing with 0 failures across the complete test suite. Ruff and mypy pass with 0 errors.
