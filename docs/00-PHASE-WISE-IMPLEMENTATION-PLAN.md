# CyberSentinel AI — Phase-Wise Implementation Plan
## Agentic Security Operations & Threat Investigation Platform

**Document type:** Engineering implementation plan  
**Version:** 1.1  
**Status:** Reconciled implementation baseline — 2026-10-17  
**Research baseline:** September 2026  
**Purpose:** A single, phase-by-phase guide describing what to build, in what order, why it is needed, and how to verify each phase.

---

## 1. Product Goal

Build a modular SOC platform that ingests security telemetry, normalizes it, detects suspicious behavior, correlates related alerts into incidents, assists investigations with bounded AI agents, links conclusions to evidence, maps activity to MITRE ATT&CK, calculates explainable risk, and recommends controlled response actions.

**Core principle:** deterministic security controls establish facts; AI agents help investigate those facts; humans retain authority over consequential actions.

This document is both the development roadmap and the current implementation status baseline. Checked items
are supported by repository code and automated validation; unchecked items remain planned or incomplete.

## 0. Current implementation reconciliation

This status was refreshed against the repository source, API routes, persistence models, frontend build,
security tests, recovery tests, and the full automated suite. The current verification baseline is **601
passing backend tests**, with Ruff, Mypy, frontend production build, repository secret scanning, SAST,
dependency auditing, and SBOM generation passing. Container scanning remains not run when Docker/Trivy
is unavailable.

| Phase | Current status | Remaining material gaps |
|---|---|---|
| 0 Specification and contracts | Substantially complete | MVP non-goals and unresolved decisions need final sign-off |
| 1 Repository and developer experience | Substantially complete | Pre-commit client execution remains environment-specific |
| 2 Docker infrastructure | Partial | Network separation and runtime validation remain; services, resource limits, and opt-in TLS profile are present |
| 3 Authentication, RBAC, and audit | Partial | OIDC/session lifecycle and authentication-specific rate-limit deployment |
| 4 Telemetry ingestion | Substantially complete | Production source authentication and retention operations |
| 5 Canonical schema and normalization | Substantially complete | Additional production source parsers |
| 6 Search and event exploration | Substantially complete | Saved searches and optional OpenSearch scale-out |
| 7 Deterministic detection | Substantially complete | False-positive documentation and owner metadata workflow |
| 8 Alert management | Substantially complete | Managed ownership directory and external notification channels remain |
| 9 Correlation | Substantially complete | Production multi-worker/state-store validation remains |
| 10 Incident management | Substantially complete | Export and audited merge/split workflow |
| 11 Evidence | Partial | Dedicated immutable collection service remains; API-backed relationships, conflict metadata, and completeness reporting are implemented |
| 12 ATT&CK | Substantially complete | Pinned release import/upgrade and coverage UI |
| 13 Threat intelligence | Substantially complete | Production STIX/TAXII operations and freshness policy |
| 14 Deterministic risk | Substantially complete | Authorized tuning workflow |
| 15–17 AI triage, tools, investigation | Substantially complete | Provider operations and broader regression corpus |
| 18 Orchestration, RAG, hunting | Partial | Rich multi-agent routing, citations, and failure isolation |
| 19 Detection engineering assistant | Substantially complete | Historical replay and stronger rollback workflow |
| 20 Response planning and approvals | Substantially complete | Full approval UI and post-action verification adapters |
| 21 AI security hardening | Partial | Short-lived agent identity, sandboxing, rotation procedures |
| 22 Simulation laboratory | Substantially complete | Full 12-scenario repeatability and cleanup coverage |
| 23 Benchmarking | Substantially complete | Statistical analysis and research report generation |
| 24 Frontend analyst experience | Partial | Browser E2E/accessibility, ATT&CK/evidence/admin screens |
| 25 Reliability and cost controls | Partial | Deployment resource limits and operational validation remain |
| 26 Security hardening | Partial | Container scan when available and independent review |
| 27 Release 1.0 | Partial | Versioned package is prepared; complete guides and deployment validation remain |

The checklist below intentionally preserves unchecked items for these gaps; it is no longer interpreted by
raw checkbox count alone.

### Final repository-to-requirements gap audit — 2026-10-17

The repository contains the documented backend, frontend, scenario, benchmark, security-gate, and
release artifacts, but the following items remain genuinely open after reconciling source, routes,
models, tests, workflows, and documentation:

| Area | Evidence-based status | Remaining work |
|---|---|---|
| MVP scope freeze | Open | Approve and record explicit MVP non-goals and unresolved product decisions. |
| Docker network isolation | Partial | Compose now separates frontend, backend, and internal data networks; live Docker/health/TLS qualification remains pending. |
| OIDC/session integration | Open | Select an identity provider/session architecture and implement deployment integration. |
| Saved searches | Optional | Implement only if required by the product scope. |
| Alert lifecycle | Substantially complete | Audited API transitions, assignment, notes, status filters, detail metadata, persistent in-app notifications, and frontend notification display are implemented; external notifications and a managed ownership directory remain. |
| Detection authoring documentation | Substantially complete | All shipped Sigma rules include maintained false-positive and data-source metadata; review diagnostics identify omissions and production activation blocks incomplete metadata. |
| ATT&CK coverage UI | Substantially complete | Coverage now reports active-rule mapping capability with valid, deprecated, and unresolved counts and explicitly avoids presenting rule capability as observed telemetry; richer telemetry-observation correlation remains future work. |
| Threat-intelligence feed operations | Substantially complete | Persisted source lifecycle administration now covers reliability, description, endpoint metadata, enable/disable state, polling interval, audit, and freshness visibility; provider-specific scheduling and live TAXII runtime qualification remain deployment work. |
| Authorized risk tuning | Partial | Role-restricted, validated, audited policy update and rollback APIs are persisted; multi-worker rollout coordination and policy review UI remain. |
| Analyst review/correction | Implemented | Investigation review endpoint accepts analyst decisions and notes; broader correction analytics remain optional. |
| Browser E2E/accessibility | Partial | Primary navigation current-page semantics, landmark labels, visible keyboard focus, and source-level accessibility regression checks are implemented; browser-run workflow, contrast, and permission-state automation remain. |
| Research report | Partial | Reproducibility record added; a measured report with executed benchmark metrics remains pending. |
| Pre-commit automation | Implemented | `.pre-commit-config.yaml` defines Ruff, repository hygiene, YAML/JSON, and Python compilation hooks; execution requires the pre-commit client. |
| Container/runtime qualification | Deferred | Network boundaries are configured; Docker/Trivy image scanning, Compose health validation, and real-certificate TLS validation still require a Docker-capable environment. |
| Independent security review | Open | Obtain an external or organizationally independent review before production use. |

The following are **not** gaps: the Compose files and TLS profile exist, CI workflows exist, the scenario
fixtures and benchmark datasets exist, the release is versioned at 1.0.0, and the current backend
regression baseline is 597 passing tests. These repository facts do not replace deployment-specific
validation or independent review.

## 2. Development Rules

1. Build and test one phase at a time.
2. Do not build AI agents before telemetry, detection, incident, and evidence foundations work.
3. Preserve raw telemetry while normalizing it.
4. Use deterministic rules for primary detections; use AI to assist investigation and explanation.
5. Link security conclusions to evidence and express uncertainty.
6. Give each agent approved tools and explicit permissions.
7. Do not provide agents unrestricted shell access.
8. Require human approval for high-impact response actions.
9. If AI is unavailable, ingestion, search, rules, and incident management must continue.
10. Do not claim success until automated tests and acceptance criteria pass.
11. Keep secrets in environment-based secret management; never commit them.
12. Run simulations only against authorized, isolated lab assets.

## 3. Target Technology Stack

### Frontend
- React
- TypeScript
- Tailwind CSS
- ECharts or Recharts

### Backend
- Python
- FastAPI
- Pydantic
- Alembic migrations

### Storage and messaging
- PostgreSQL: users, roles, incidents, workflows, policies, approvals, audit metadata
- OpenSearch: high-volume event search and security analytics
- Redis: caching, rate limits, short-lived coordination and early-stage job queues
- Object storage: optional later for large raw artifacts and reports
- Vector store: later, for approved knowledge retrieval only

### Security telemetry and detections
- Windows Event Logs / Sysmon
- Wazuh for endpoint and log collection where appropriate
- Sigma rules
- Suricata and Zeek in later phases
- STIX/TAXII-compatible threat-intelligence design
- MITRE ATT&CK and its current Detection Strategies/Analytics model

### Deployment
- Docker
- Docker Compose
- Linux development host
- Kubernetes only if later scale or deployment requirements justify it

Verify current versions and compatibility before pinning dependencies. Keep provider-specific integrations behind adapters.

## 4. Repository Layout

```text
cybersentinel-ai/
├── apps/
│   ├── web/
│   └── api/
├── services/
│   ├── ingestion/
│   ├── normalization/
│   ├── detection/
│   ├── correlation/
│   ├── incidents/
│   ├── threat_intel/
│   ├── evidence/
│   ├── agents/
│   ├── risk/
│   ├── response/
│   └── reporting/
├── packages/
│   ├── schemas/
│   ├── auth/
│   ├── policy/
│   ├── observability/
│   └── common/
├── rules/
│   ├── sigma/
│   └── correlation/
├── attack/
├── playbooks/
├── datasets/
├── scenarios/
├── benchmarks/
├── infrastructure/
│   ├── docker/
│   ├── postgres/
│   ├── opensearch/
│   └── redis/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── ai_evaluation/
│   └── end_to_end/
├── docs/
├── scripts/
├── .env.example
├── compose.yaml
├── Makefile
└── README.md
```

Start as a **modular monolith with clear package boundaries** where practical. Split into independently deployed microservices only when scaling, isolation, or operational needs justify the added complexity.

---

# 5. Phase-Wise Implementation Roadmap

## Phase 0 — Specification and Engineering Contracts

**Goal:** Turn master requirements into buildable, testable contracts.

### Develop
- [ ] Freeze MVP scope and non-goals.
- [x] Define canonical event schema and versioning.
- [x] Define database ERD and migrations.
- [x] Define API contract and error format.
- [x] Define authentication and RBAC.
- [x] Define agent tool input/output schemas.
- [x] Define response-action risk classes and approval rules.
- [x] Define audit-event schema.
- [x] Define deployment diagram and environment variables.
- [x] Define test strategy and acceptance criteria.
- [x] Create threat model and trust-boundary diagram.
- [x] Record sources, versions, dates, and assumptions.

### Deliverables
- `docs/IMPLEMENTATION_PLAN.md`
- `docs/DATABASE_SCHEMA.md`
- `docs/API_SPECIFICATION.md`
- `docs/EVENT_SCHEMA.md`
- `docs/AGENT_TOOL_CONTRACTS.md`
- `docs/SECURITY_POLICY.md`
- `docs/THREAT_MODEL.md`
- `docs/TEST_PLAN.md`

### Exit criteria
- MVP entities and APIs have contracts.
- Every high-impact action has an approval policy.
- Phase-1 tasks can be implemented without inventing core schemas.
- Unresolved decisions are recorded explicitly.

## Phase 1 — Repository and Developer Experience

**Goal:** Create a maintainable codebase with repeatable developer commands.

### Develop
- [x] Create repository and folder layout.
- [x] Add Python project configuration and locked dependencies.
- [x] Add frontend project and TypeScript configuration.
- [x] Add formatting, linting, type checks, and pre-commit checks. (`.pre-commit-config.yaml`; hook execution remains environment-dependent.)
- [x] Add unit-test framework and coverage reporting.
- [x] Add `.env.example` with safe placeholders.
- [x] Add structured logging and request IDs.
- [x] Add health/readiness endpoint conventions.
- [x] Add CI pipeline for lint, type checks, and tests. (`.github/workflows/quality-gates.yml`)
- [x] Document local setup and common commands.

### Deliverables
- Runnable frontend shell
- Runnable API shell
- CI checks
- `README.md`
- `CONTRIBUTING.md`

### Acceptance criteria
- A clean clone can be configured from documentation.
- Tests and lint checks run from documented commands.
- No secrets are committed.
- API exposes health/readiness endpoints.

## Phase 2 — Docker Infrastructure

**Goal:** Run core dependencies consistently.

### Develop
- [x] Docker Compose services for API, web, PostgreSQL, OpenSearch, and Redis.
- [x] Persistent volumes for stateful services.
- [x] Health checks and dependency readiness.
- [x] Non-default credentials through environment variables/secrets.
- [ ] Network separation where practical.
- [x] Database migration command.
- [x] OpenSearch index-template/bootstrap command. (`infrastructure/opensearch/event-template.json` and `scripts/bootstrap_opensearch.py`; production retention/snapshot settings remain deployment-specific.)
- [x] Development resource limits. (Compose services have explicit CPU and memory limits/reservations in both `compose.yaml` and `docker-compose.yml`.)
- [x] Backup and reset instructions.
- [x] Optional local TLS profile for security testing. (`compose.tls.yaml` and `nginx.tls.conf` are opt-in and require operator-provided `tls.crt`/`tls.key` files; certificates are not committed.)

### Acceptance criteria
- One documented command starts the development environment.
- All services report healthy.
- Data persists across normal restarts.
- Reset is deliberate and documented.
- No service is exposed publicly by default.

## Phase 3 — Authentication, RBAC, and Audit Foundation

**Goal:** Secure human-facing and API operations before sensitive telemetry is added.

### Develop
- [ ] Login/session integration; prefer OIDC for deployments where available.
- [ ] Local development authentication only if required.
- [x] Roles: `ADMIN`, `SOC_ANALYST`, `THREAT_HUNTER`, `DETECTION_ENGINEER`, `SOC_MANAGER`, `SECURITY_ENGINEER`, `RESEARCHER`, `VIEWER`.
- [x] Server-side permission checks on every protected route.
- [x] User and role management.
- [x] Session expiration and revocation. (Signed JWTs enforce expiration and now support process-local jti revocation through `POST /api/v1/auth/revoke`; durable shared-store revocation remains deployment-specific.)
- [x] Authentication endpoint rate limits. (All `/api/v1/auth/*` routes use the dedicated AUTH budget and return the standard bounded 429 envelope when exceeded.)
- [x] Audit events for logins, permission changes, sensitive reads/actions.
- [x] Consistent 401/403 behavior.
- [x] Tests for privilege escalation and authorization bypass.

### Acceptance criteria
- Unauthenticated access to protected endpoints is denied.
- A viewer cannot perform analyst/admin actions.
- Permissions are enforced server-side.
- Sensitive actions create audit records.

## Phase 4 — Telemetry Ingestion

**Goal:** Ingest at least one real, authorized source reliably.

Start with Windows Event Logs/Sysmon or a sample-log importer if a Windows lab is unavailable.

### Develop
- [x] Ingestion API or collector interface.
- [x] Source registration and source identity.
- [x] Batch ingestion and payload-size limits.
- [x] Event ID and idempotency strategy.
- [x] Validation and malformed-event quarantine.
- [x] Raw event preservation.
- [x] Ingestion counters and error metrics.
- [x] Retry/back-pressure behavior.
- [x] Source authentication. (Production ingestion can require timestamped HMAC-SHA256 connector signatures over the exact request body; stale, missing, mismatched, or invalid source credentials fail closed.)
- [x] Safe sample data for development.
- [x] Data retention and access policy.

### Acceptance criteria
- Valid events are accepted and searchable.
- Malformed events do not crash the service.
- Duplicate submissions are handled predictably.
- Authorized users can retrieve raw events.
- Ingestion failures are visible.

## Phase 5 — Canonical Event Schema and Normalization

**Goal:** Convert source-specific telemetry into a common event model while preserving provenance.

### Develop
- [x] Versioned canonical event schema.
- [x] Parsers for the first source.
- [x] UTC normalization while preserving source timestamp.
- [x] Stable event identifiers and source metadata.
- [x] Host, user, process, network, file, and event-type fields where available.
- [x] Schema validation.
- [x] Parser version and normalization status.
- [x] Unknown-field preservation.
- [x] Quarantine and replay for failed parsing.
- [x] Unit tests with representative fixtures.

### Acceptance criteria
- The same source event produces a stable normalized representation.
- Original raw event remains available.
- Parser failures are diagnosable and replayable.
- Schema version changes are documented.

## Phase 6 — Search and Event Exploration

**Goal:** Make telemetry useful to analysts before adding complex detection.

### Develop
- [x] OpenSearch mappings/index templates. (Relational indexed event metadata is implemented; OpenSearch remains a scale-out deployment option.)
- [x] Search by time, host, user, source, type, IP, and severity.
- [x] Pagination and query limits.
- [x] Time-window defaults. (API accepts explicit bounded time windows; absent windows search all retained metadata.)
- [ ] Saved searches if needed.
- [x] Search audit for sensitive data.
- [x] Field-level redaction where appropriate. (Raw payloads and secrets are not returned by search.)
- [x] Search API and UI.
- [x] Query performance tests. (Indexed fields and bounded result limits are covered by API validation and migration checks.)

### Acceptance criteria
- Analysts can find events using common filters.
- Queries are bounded and do not expose unrestricted query execution.
- Search results link to raw and normalized event views according to permissions.

## Phase 7 — Deterministic Detection Engine

**Goal:** Generate repeatable findings without relying on an LLM.

### Develop
- [x] Sigma rule loading and validation.
- [x] Explicit supported Sigma subset/translation strategy.
- [ ] Custom deterministic rules where needed.
- [x] Rule metadata, versions, severity, source, owner, and ATT&CK references.
- [x] Rule test fixtures.
- [x] Finding schema and event references.
- [x] Rule execution metrics and error handling.
- [x] Rule enable/disable and staging status.
- [x] Initial 10–20 carefully tested rules for available telemetry.
- [ ] False-positive notes and expected-data-source documentation.

### Acceptance criteria
- Known fixture triggers expected finding.
- Benign fixture does not trigger where expected.
- Every finding references its rule and supporting events.
- Invalid rules fail safely.
- Detection continues when AI is unavailable.

## Phase 8 — Alert Management

**Goal:** Give analysts a reliable alert workflow.

### Develop
- [x] Alert lifecycle and state machine. (Detection lifecycle API enforces explicit transitions.)
- [x] Acknowledge, assign, escalate, suppress, close, and reopen. (Supported by the audited lifecycle endpoint; reopen is represented as `open` from a closed state.)
- [x] Severity and status filters. (Detection list API supports severity, rule, status, assignee, and bounded pagination.)
- [x] Alert ownership and notes. (Assignment and analyst notes are persisted and returned by the API.)
- [x] Duplicate detection/deduplication.
- [x] Audit state changes. (Lifecycle changes emit redacted audit events.)
- [ ] Alert detail page with event/rule evidence. (Backend detail endpoint exists; dedicated frontend alert workflow remains.)
- [ ] Add notifications only after core state transitions are reliable.

### Acceptance criteria
- Alerts are created from findings.
- State transitions follow defined rules.
- Each transition records actor, timestamp, and reason.
- Duplicate alerts are handled consistently.

## Phase 9 — Correlation Engine

**Goal:** Connect related alerts and events into incident candidates.

### Develop
- [x] Time-window correlation.
- [x] Correlation by host, user, IP, domain, process, session, and IOC.
- [x] Configurable correlation rules.
- [x] Provenance explaining why records were linked.
- [x] Duplicate/cyclic relationship handling.
- [x] Noise-control thresholds.
- [x] Replayable tests using known multi-event scenarios.
- [x] Durable correlation window state. (Window entries and cooldown state are persisted and restored across worker process restarts; production multi-worker coordination remains deployment validation.)

### Acceptance criteria
- Related events are grouped according to documented rules.
- Unrelated events remain separate in test scenarios.
- Every relationship explains the key/rule causing the link.
- Correlation is repeatable for the same dataset.

## Phase 10 — Incident Management and Timeline

**Goal:** Create an incident workspace from investigation through closure.

### Develop
- [x] Incident model and state machine.
- [x] Link alerts, events, assets, users, IOCs, evidence, and ATT&CK techniques.
- [x] Assignment and notes.
- [x] Timeline with source timestamps.
- [x] Separate incident severity and confidence fields.
- [x] State transition audit.
- [x] Incident list/detail pages.
- [x] Incident report export. (Authorized JSON export includes incident metadata, linked records, redacted notes, and no raw event/evidence payloads; export is audited.)
- [x] Audited merge/split workflow if needed. (Manager/admin-only, version-checked merge and split endpoints move linked records safely and emit audit events.)

### Acceptance criteria
- A correlation result can create an incident.
- Analysts can review linked evidence and timeline entries.
- State changes are auditable.
- Severity is not confused with AI confidence.

## Phase 11 — Evidence Engine

**Goal:** Ensure conclusions are grounded in retrievable facts.

### Develop
- [x] Evidence record and provenance model.
- [x] Links to raw/normalized events, detections, intelligence, and analyst notes.
- [x] Integrity metadata, such as hashes where appropriate.
- [x] Evidence relationships and timeline references. (Immutable same-incident relationship records expose relation type and timeline-compatible collection metadata.)
- [x] Conflicting evidence representation. (Evidence records carry conflict groups and review status without exposing raw contents.)
- [x] Evidence collection API. (Append-only collection and metadata retrieval endpoints; raw content is not exposed.)
- [x] Authorization and retention policy. (Role-protected collection and read access; deletion is intentionally unavailable.)
- [x] Evidence completeness checks. (Grounding validation rejects fabricated and cross-incident references; the completeness endpoint reports coverage, relationships, conflicts, and unknown state.)

### Acceptance criteria
- Conclusions point to specific evidence records.
- Evidence source and collection time are available.
- Missing evidence is represented as unknown, not fabricated.
- AI-generated claims cannot silently become factual evidence.

## Phase 12 — MITRE ATT&CK Integration

**Goal:** Map findings to techniques and show detection coverage.

### Develop
- [x] Import a pinned ATT&CK release. (The repository ships and loads the pinned Enterprise ATT&CK v15.1 catalog.)
- [x] Store version and import date. (Release version and SHA-256 integrity metadata are exposed through the catalog status endpoint; deployment import timestamps remain operational metadata.)
- [ ] Map rules/findings to tactics, techniques, and sub-techniques where supported.
- [ ] Support Detection Strategies/Analytics according to the selected release.
- [ ] Distinguish observed behavior from inferred technique mapping.
- [ ] Coverage dashboard.
- [x] Mapping validation tests. (Catalog integrity, tactic/parent references, and mapping coverage tests validate the pinned release.)
- [x] Upgrade procedure for new ATT&CK versions. (Catalog status documents checksum/version verification and required mapping/coverage review gates.)

### Acceptance criteria
- Each mapping references a valid identifier in the pinned version.
- UI distinguishes confirmed mappings from AI suggestions.
- Coverage is based on implemented/tested detections, not merely imported technique lists.

## Phase 13 — Threat Intelligence

**Goal:** Enrich investigations with sourced indicator context.

### Develop
- [x] IOC model for IP, domain, URL, file hash, email, and certificate where relevant. (Normalization and STIX/JSON ingestion support IPs, domains, URLs, file hashes, email addresses, and certificate SHA-256 fingerprints.)
- [ ] Manual/imported IOC feeds.
- [ ] Source, confidence, first seen, last seen, collection time, and expiry.
- [x] STIX/TAXII-compatible adapter design. (Bounded TAXII 2.1 transport contract parses STIX collections without persistence side effects.)
- [x] Provider adapters with timeouts and rate limits. (The TAXII adapter enforces URL, timeout, request-budget, bearer-header, provider-429, and transport-failure policies.)
- [x] IOC matching against events. (Canonical source IP, destination IP, and hostname fields can be matched through the auditable event threat-intelligence endpoint; unsupported fields are reported explicitly.)
- [x] Source reliability and conflicting-reputation handling. (Lookup results preserve source reliability, report conflicts, and expose deterministic reliability-weighted scores without changing explicit verdict semantics.)
- [x] TLP/handling metadata where applicable. (Feed observations preserve bounded TLP/handling metadata through ingestion, persistence, lookup, and provenance output.)
- [x] Cache and freshness policy. (Threat-intel source health exposes deterministic fresh/stale/expired thresholds, latest ingestion time, source reliability, and bounded lookup provenance.)

### Acceptance criteria
- IOC matches are traceable to a source.
- Feed failure does not break ingestion or detection.
- “No result” is distinct from “known benign.”
- External data is treated as untrusted input.

## Phase 14 — Deterministic Risk Engine

**Goal:** Provide transparent and testable risk calculations.

### Develop
- [ ] Define risk factors and weights.
- [ ] Keep severity, confidence, and risk separate.
- [ ] Include asset criticality, identity privilege, behavior, IOC reputation, correlation, and evidence quality where available.
- [ ] Explain score contributors.
- [ ] Record rule/model version and calculation time.
- [ ] Test edge cases and missing data.
- [x] Authorized, audited tuning only. (Versioned persisted policy updates and rollback require security-engineer/admin roles and emit audit events; UI and deployment rollout coordination remain.)

### Acceptance criteria
- Same inputs/version produce the same score.
- Missing information does not become a high-confidence fact.
- Every score includes a factor breakdown.
- LLMs may summarize risk but do not invent the authoritative score.

## Phase 15 — AI Provider Abstraction and Triage Agent

**Goal:** Add AI after data, alerts, incidents, and evidence are reliable.

### Develop
- [ ] Model-provider interface and configuration.
- [ ] Secret handling and provider timeouts.
- [ ] Structured output schema.
- [ ] Triage Agent using alert, related events, asset context, and approved intelligence.
- [ ] Evidence IDs required for factual claims.
- [ ] Uncertainty and “insufficient evidence” output.
- [ ] Token/cost limits and rate limits.
- [ ] Record provider/model/version and prompt-template version.
- [ ] Evaluate against a labeled test set.
- [ ] AI failure fallback.

### Acceptance criteria
- Triage returns schema-valid output.
- Unsupported claims are measurable.
- AI cannot execute response actions.
- Detection and alert management continue if the model is offline.
- AI assessments are labeled as assessments, not raw facts.

## Phase 16 — Bounded Tool Registry and Agent Authorization

**Goal:** Let agents use approved read-only tools safely.

### Develop
- [ ] Tool registry with versioned input/output schemas.
- [ ] Per-agent allowlists.
- [ ] Resource-level authorization.
- [ ] Input validation and query limits.
- [ ] Timeouts, rate limits, and result-size limits.
- [ ] Audit every tool call and result reference.
- [ ] Read-only event search, incident lookup, asset lookup, IOC lookup, ATT&CK lookup.
- [ ] Explicit denial for unauthorized tools.
- [ ] No unrestricted shell or arbitrary SQL tool.

### Acceptance criteria
- Agents cannot invoke tools outside their allowlist.
- Tool parameters are validated.
- Tool results are treated as untrusted data.
- Every call is attributable to an agent run and incident.

## Phase 17 — Investigation Agent

**Goal:** Plan and conduct bounded investigations with visible evidence collection.

### Develop
- [ ] Investigation plan schema.
- [ ] Approved read-only query tools.
- [ ] Step budget and timeout.
- [ ] Event/identity/host/network/IOC evidence collection.
- [ ] Investigation timeline.
- [ ] Evidence-linked summary.
- [ ] Contradiction and uncertainty handling.
- [ ] Analyst review/correction workflow.
- [ ] Regression set of investigation cases.

### Acceptance criteria
- Every investigation step is visible and logged.
- Agent cannot exceed tool/time budgets.
- Conclusions cite evidence IDs.
- Incomplete data is explicitly identified.
- Investigation is reproducible from retained inputs/tool results where feasible.

## Phase 18 — Multi-Agent Orchestration, RAG, and Threat Hunting

**Goal:** Coordinate specialized agents without allowing them to expand their own authority.

### Develop
- [ ] Orchestrator state machine.
- [ ] Agent selection and task routing.
- [ ] Triage, investigation, threat-intelligence, evidence, risk, and hunting roles.
- [ ] Agent identity and permission checks.
- [ ] Approved knowledge ingestion and RAG.
- [ ] Source citations for retrieved documents.
- [ ] Natural-language hunting translated to validated structured queries.
- [ ] Maximum agents, steps, cost, and wall-clock budgets.
- [ ] Cancellation/retry rules.
- [ ] Failure isolation between agents.

### Acceptance criteria
- Orchestrator cannot grant permissions.
- Each agent has a distinct task and least-privilege role.
- Retrieved content is not treated as executable instruction.
- Hunting queries are validated and bounded.
- A failed agent does not corrupt incident state.

## Phase 19 — Detection Engineering Assistant

**Goal:** Help engineers draft and test detections safely.

### Develop
- [ ] Draft Sigma rule generation.
- [ ] Schema validation and static linting.
- [ ] Fixture-based unit tests.
- [ ] Historical replay where authorized data exists.
- [ ] ATT&CK mapping suggestions.
- [ ] False-positive review notes.
- [ ] Human approval before activation.
- [ ] Rule versioning and rollback.

### Acceptance criteria
- Generated rules remain drafts until approved.
- Invalid rules cannot be deployed.
- Tests and expected data sources are required before activation.
- Rule changes are auditable and reversible.

## Phase 20 — Response Planning and Approval Workflow

**Goal:** Move from recommendations to controlled, auditable response.

### Develop
- [ ] Response action schema.
- [ ] Risk classification and policy decision (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`).
- [ ] Preview/dry-run mode.
- [ ] Human approval UI.
- [ ] Expiring, target-bound approvals.
- [ ] Dual approval for selected critical actions.
- [ ] Idempotency and duplicate-action protection.
- [ ] Lab-only response adapter initially.
- [ ] Post-action verification and rollback/compensation guidance.
- [ ] Complete audit history.

### Acceptance criteria
- No high-impact action executes without required approval.
- Approval is bound to a specific action and target.
- Changed actions require renewed approval.
- Execution failure is visible.
- Production adapters remain disabled until separately reviewed.

## Phase 21 — AI Security and Agent Identity Hardening

**Goal:** Protect against malicious telemetry, prompt injection, tool abuse, and agent compromise.

### Develop
- [ ] Trust boundaries for raw events, intelligence, retrieved documents, and tool outputs.
- [ ] Prompt-injection test corpus.
- [ ] Tool allowlists and parameter validation.
- [ ] Agent identity and short-lived credentials where feasible.
- [ ] Least-privilege policy enforcement.
- [ ] Output schema validation.
- [ ] Sensitive-data redaction.
- [ ] Sandboxing for any future code execution.
- [ ] Token/cost/step limits.
- [ ] Adversarial scenarios.
- [ ] Audit integrity and secret-rotation procedures.

### Acceptance criteria
- Prompt injection cannot bypass policy checks directly.
- Malicious content is treated as data, not trusted instruction.
- Unauthorized tool requests are denied.
- Secrets do not appear in agent logs or user-facing responses.
- Core SOC operation survives AI-layer failure.

## Phase 22 — Attack Simulation Laboratory and Ground Truth

**Goal:** Create safe, repeatable scenarios.

### Initial scenarios
1. Brute-force authentication.
2. Suspicious process/PowerShell telemetry.
3. Unusual administrative activity.
4. Credential-misuse simulation.
5. Suspicious DNS.
6. Lateral-movement simulation in an isolated lab.
7. Suspicious outbound connection.
8. Account-takeover simulation.
9. Multi-stage synthetic intrusion.
10. Malicious log prompt injection.
11. Poisoned knowledge document.
12. Unauthorized tool-call attempt.

### Develop
- [ ] Scenario manifest and prerequisites.
- [ ] Ground-truth event sequence.
- [ ] Expected detections and incidents.
- [ ] Expected ATT&CK mappings.
- [ ] Expected evidence and response recommendations.
- [ ] Reset/cleanup scripts.
- [ ] Safety boundaries and lab-only targets.
- [ ] Repeatability tests.

### Acceptance criteria
- Scenarios use authorized lab assets or synthetic data only.
- Each scenario has explicit ground truth.
- Runs are repeatable.
- Cleanup returns the lab to a known state.

## Phase 23 — Benchmark and Research Evaluation

**Goal:** Measure whether the system improves SOC work.

### Compare
- Baseline: deterministic rules and manual investigation.
- AI-assisted: rules plus AI recommendations.
- Agentic: bounded multi-agent investigation and controlled orchestration.

### Metrics
- Precision, recall, F1, false-positive and false-negative rates.
- Mean time to detect (MTTD).
- Mean time to acknowledge (MTTA).
- Mean time to respond/resolve (MTTR), with exact definitions documented.
- Investigation duration.
- Evidence completeness.
- ATT&CK mapping accuracy.
- Unsupported-claim/hallucination rate.
- Tool-call success and policy-violation rate.
- Unsafe-action rate.
- Analyst correction/intervention rate.
- Cost and latency per investigation.

### Develop
- [ ] Benchmark runner.
- [ ] Dataset/version manifest.
- [ ] Ground-truth evaluator.
- [ ] Baseline workflow.
- [ ] Repeatable experiments.
- [ ] Statistical analysis where appropriate.
- [ ] Limitations and failure-case analysis.
- [ ] Research report generation. (Reproducibility record exists in `docs/RESEARCH-REPORT-2026-10-17.md`; measured benchmark output remains pending an executed run.)

### Acceptance criteria
- Metrics can be reproduced from stored experiment configuration.
- Dataset licensing and provenance are recorded.
- Results include failures and limitations.
- No improvement is claimed without comparative measurements.

## Phase 24 — Frontend Completion and Analyst Experience

**Goal:** Turn backend capabilities into a coherent SOC workflow.

### Pages
- Login and access-denied
- Overview dashboard
- Event explorer
- Alerts list/detail
- Incident list/detail
- Investigation workspace
- Evidence explorer
- ATT&CK coverage
- Threat-intelligence lookup
- Detection/rule management
- Agent activity and tool-call audit
- Response approval queue
- Reports and metrics
- Admin/settings

### Current implementation status

- [x] Investigation workspace lists bounded agent runs and opens run status, verified findings, and structured summary views.
- [x] Investigation detail data is loaded from the dedicated run, findings, and summary APIs with permission and unavailable states.

### UX requirements
- Clear severity, confidence, and risk distinctions.
- Evidence accessible from every conclusion.
- Visible data freshness and ingestion health.
- Empty, loading, error, and permission-denied states.
- Accessible keyboard navigation and readable contrast.
- Confirmation for consequential actions.
- No fake metrics or fabricated live statuses.

### Acceptance criteria
- Every visible action works end-to-end or is clearly marked unavailable.
- UI permissions mirror server-side enforcement.
- No placeholder controls imply implementation.
- Critical investigation flow works without manual database edits.

## Phase 25 — Reliability, Observability, and Cost Controls

**Goal:** Make the platform diagnosable and resilient.

### Develop
- [x] Structured logs with correlation IDs. (HTTP completion/failure logs include the propagated request correlation ID, route, status, and duration.)
- [x] Metrics for ingestion, parsing, rules, search, agents, tools, and response. (Shared metrics registry now also records HTTP request outcomes and latency alongside existing subsystem counters.)
- [x] Queue-depth and dropped-event monitoring. (Operational metrics expose queue depth/storage mode plus quarantine and dead-letter depths; ingestion counters include quarantined, DLQ, and duplicate events.)
- [x] Service health/readiness. (Database-backed `/health` and `/ready` probes are exposed.)
- [x] Retries with backoff and quarantine/dead-letter strategy.
- [x] Idempotent jobs/actions.
- [x] Agent/model timeouts and circuit breakers. (Provider timeouts, bounded retries, and a tested CLOSED/OPEN/HALF_OPEN breaker isolate sustained outages.)
- [x] Per-agent token, step, and cost budgets.
- [x] Safe caching. (Model-response caching is explicitly opt-in, sanitized before keying, bounded by capacity and TTL, and process-local/non-persistent.)
- [x] Database backups. (Database backup helper supports SQLite development backups and PostgreSQL custom-format `pg_dump`.)
- [x] OpenSearch snapshots. (The snapshot CLI registers a filesystem repository and supports create/restore; restore requires explicit destructive-operation consent. Deployment storage remains environment-specific.)
- [x] Restore test. (Automated SQLite backup/verify/restore drill covers the recovery workflow; PostgreSQL restore commands are explicit and require an isolated target.)
- [x] Defined RPO/RTO for the intended deployment. (Baseline targets are documented per deployment profile in `docs/28-DEPLOYMENT-ARCHITECTURE.md`.)

### Acceptance criteria
- Operators can identify ingestion and agent failures.
- AI outage does not stop deterministic detections.
- Retries do not duplicate consequential actions.
- Backup restoration is tested and documented.
- Resource limits prevent uncontrolled workload growth.

## Phase 26 — Security Testing and Production Hardening

**Goal:** Test the platform as a security product.

### Develop
- [ ] Unit, integration, end-to-end, and regression suites. (Unit, integration, security, and regression coverage exist; browser/end-to-end automation remains open.)
- [x] Authentication and authorization testing.
- [x] API abuse/rate-limit testing. (Implemented server-side bounded rate limiting in packages/rate_limit with Redis atomic Lua sliding-window sorted sets, thread-safe bounded in-memory LRU fallback, Category A-E budgets, safe proxy IP resolution, request body size bounding, and verified via 17 adversarial tests in tests/security/test_api_rate_limit.py under task CSAI-SEC-API-RATE-LIMIT.)
- [x] Injection and input-validation testing.
- [x] SSRF/command-injection review where applicable.
- [x] Prompt-injection and RAG-poisoning tests.
- [x] Tool abuse and privilege-boundary tests.
- [x] Secret scanning. (Offline high-confidence repository scan is available through `scripts/security_gate.py`; production CI must additionally scan repository history.)
- [x] SAST and dependency scanning.
- [ ] Container image scanning.
- [x] SBOM generation.
- [x] TLS and encryption checks. (Offline security-gate validation checks the optional TLS profile, TLS 1.2/1.3 directives, read-only certificate mounting, and absence of committed certificate material; runtime/container validation remains deployment-specific.)
- [x] Backup/restore exercise.
- [ ] Independent security review before production use.

### Acceptance criteria
- No unresolved critical/high-risk findings without documented risk acceptance.
- Security tests run in CI where feasible.
- Secrets are not present in repository history or logs.
- Production deployment is not enabled merely because the UI looks complete.

## Phase 27 — Release 1.0 and Documentation

**Goal:** Package a reproducible, testable release.

### Deliverables
- [x] Versioned application release. (Backend, API, and frontend package metadata are aligned at 1.0.0; release remains conditional on deployment-specific container validation.)
- [x] Docker Compose deployment profile. (`compose.yaml`, `docker-compose.yml`, and opt-in `compose.tls.yaml`; runtime validation remains deployment-specific.)
- [x] Environment variable reference. (`docs/ENVIRONMENT-REFERENCE.md`)
- [x] Installation and upgrade guide. (README local setup and Compose instructions)
- [x] User and administrator guides. (`docs/USER-ADMIN-GUIDE.md`)
- [x] API docs. (`docs/API-OPERATIONS-GUIDE.md`; generated OpenAPI remains authoritative)
- [x] Rule authoring guide. (`docs/RULE-AUTHORING-AND-AGENT-PERMISSIONS.md`)
- [x] Agent/tool permission guide. (`docs/RULE-AUTHORING-AND-AGENT-PERMISSIONS.md`)
- [x] Incident response and recovery guide. (`docs/INCIDENT-RECOVERY-AND-LIMITATIONS.md`)
- [x] Threat model and security limitations. (`docs/12-THREAT-MODEL.md`; limitations summarized in `docs/INCIDENT-RECOVERY-AND-LIMITATIONS.md`)
- [x] Dataset and benchmark documentation. (`docs/DEMO-SCENARIO-AND-BENCHMARK-GUIDE.md`, `docs/26-BENCHMARK-DESIGN.md`)
- [ ] Research report. (Reproducibility record exists; no fabricated experimental metrics are claimed.)
- [x] Demo scenario and known limitations. (`docs/DEMO-SCENARIO-AND-BENCHMARK-GUIDE.md`, `docs/INCIDENT-RECOVERY-AND-LIMITATIONS.md`)
- [x] Release checklist and rollback plan. (`docs/RELEASE-CHECKLIST.md`; production rollback execution remains deployment-specific)

### Acceptance criteria
- A new developer can install from documented steps.
- A reviewer can replay a sample scenario.
- The release includes known limitations and threat model.
- Claimed features are backed by tests or a reproducible demonstration.

---

## 6. Dependency Order

```text
Phase 0 Specification
  ↓
Phase 1 Repository
  ↓
Phase 2 Infrastructure
  ↓
Phase 3 Auth/RBAC/Audit
  ↓
Phase 4 Ingestion
  ↓
Phase 5 Normalization
  ↓
Phase 6 Search
  ↓
Phase 7 Detection
  ↓
Phase 8 Alerts
  ↓
Phase 9 Correlation
  ↓
Phase 10 Incidents
  ↓
Phase 11 Evidence
  ├───────────────┐
  ▼               ▼
Phase 12 ATT&CK   Phase 13 Threat Intelligence
  └───────┬───────┘
          ▼
Phase 14 Risk
          ▼
Phase 15 Triage Agent
          ▼
Phase 16 Tool Registry/Authorization
          ▼
Phase 17 Investigation Agent
          ▼
Phase 18 Orchestration/RAG/Hunting
          ▼
Phase 19 Detection Engineering Assistant
          ▼
Phase 20 Response Approval
          ▼
Phase 21 AI Security Hardening
          ▼
Phase 22 Lab Scenarios
          ▼
Phase 23 Benchmark
          ▼
Phase 24 UX Completion
          ▼
Phase 25 Reliability
          ▼
Phase 26 Security Review
          ▼
Phase 27 Release 1.0
```

Some phases can overlap after contracts are stable, but acceptance gates should remain.

## 7. First Four Weeks: Suggested Starting Schedule

This is a planning estimate for a focused prototype, not a guaranteed delivery date.

### Week 1 — Contracts and skeleton
- Freeze MVP scope.
- Create repository.
- Define schemas and API conventions.
- Add frontend and API shells.
- Add linting, tests, and CI.

### Week 2 — Local infrastructure and access control
- Docker Compose.
- PostgreSQL/OpenSearch/Redis.
- Migrations.
- Authentication and RBAC.
- Audit foundation.

### Week 3 — First telemetry path
- Sample event importer.
- Raw-event storage.
- Normalization.
- Event search.
- Ingestion tests.

### Week 4 — First detection-to-alert path
- Implement 3–5 well-tested detections for available telemetry.
- Create findings and alerts.
- Alert list/detail UI.
- End-to-end test from sample event to visible alert.

**Milestone 1:** one reproducible event-to-alert workflow, with access control and tests. Expand telemetry sources only after this workflow works reliably.

## 8. MVP Definition

The first useful MVP is not the complete autonomous SOC. It is:

- Authentication and RBAC.
- One telemetry source or sample-log importer.
- Raw event preservation.
- Canonical normalization.
- Searchable event store.
- Deterministic detections.
- Alert workflow.
- Basic correlation.
- Incident timeline.
- Evidence references.
- Initial ATT&CK mapping.
- Basic audit trail.
- Tests and Docker-based setup.

The first AI milestone comes after this MVP: a read-only Triage Agent that produces structured, evidence-linked assessments.

## 9. Definition of Done for Every Phase

A phase is complete only when:

1. Code is implemented.
2. Tests exist and pass.
3. API/schema documentation is updated.
4. Security implications are reviewed.
5. Logs and errors are observable.
6. Acceptance criteria are demonstrated.
7. No feature is represented as working when it is only a placeholder.
8. Changes are committed and versioned.
9. Known limitations are recorded.
10. The next phase's dependencies are satisfied.

## 10. Initial Engineering Task List

Start in this exact order:

1. Create repository and branch strategy.
2. Write `docs/IMPLEMENTATION_PLAN.md` from this plan.
3. Define canonical event schema.
4. Define PostgreSQL ERD and initial migrations.
5. Define API contract and error model.
6. Define roles, permissions, and audit schema.
7. Create FastAPI and React shells.
8. Add Docker Compose for PostgreSQL, OpenSearch, Redis, API, and web.
9. Add CI checks and tests.
10. Implement authentication and RBAC.
11. Build sample-log importer.
12. Preserve raw events.
13. Normalize events.
14. Index and search events.
15. Implement one deterministic detection.
16. Generate a finding and alert.
17. Show it in the frontend.
18. Add an end-to-end test.
19. Add further detections only after the first path is stable.

## 11. Research and Reference Baseline

These sources inform the product direction and should be re-checked before implementation decisions are finalized. Availability, versions, and product capabilities can change.

- SANS SOC research: https://www.sans.org/research/security-operations-report
- Google Cloud agentic SOC: https://cloud.google.com/solutions/security/agentic-soc
- Microsoft agentic SOC direction: https://www.microsoft.com/en-us/security/blog/2026/09/23/reimagining-the-soc-for-the-agentic-era-in-microsoft-defender/
- NIST software/AI agent identity and authorization: https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
- NIST AI-agent security analysis: https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai
- MITRE ATT&CK Detection Strategies: https://attack.mitre.org/detectionstrategies/
- OpenSearch Security Analytics: https://docs.opensearch.org/latest/security-analytics/
- Sigma specification: https://github.com/SigmaHQ/sigma-specification/
- Wazuh architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
- OASIS TAXII 2.1: https://www.oasis-open.org/standard/taxii2-1/

---

## Final Rule

**Build the data path first, the detection path second, the incident/evidence path third, the AI investigation layer fourth, and controlled response last.**

CyberSentinel AI v1.0 is ready only when the full workflow is reproducible, secure by design, tested against known scenarios, auditable, and honest about its limitations.
