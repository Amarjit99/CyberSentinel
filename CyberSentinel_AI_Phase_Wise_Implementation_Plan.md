# CyberSentinel AI — Phase-Wise Implementation Plan
## Agentic Security Operations & Threat Investigation Platform

**Document type:** Engineering implementation plan  
**Version:** 1.0  
**Status:** Development planning baseline  
**Research baseline:** September 2026  
**Purpose:** A single, phase-by-phase guide describing what to build, in what order, why it is needed, and how to verify each phase.

---

## 1. Product Goal

Build a modular SOC platform that ingests security telemetry, normalizes it, detects suspicious behavior, correlates related alerts into incidents, assists investigations with bounded AI agents, links conclusions to evidence, maps activity to MITRE ATT&CK, calculates explainable risk, and recommends controlled response actions.

**Core principle:** deterministic security controls establish facts; AI agents help investigate those facts; humans retain authority over consequential actions.

This is a development roadmap, not a claim that the product has already been implemented or is production-ready.

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
- [ ] Define canonical event schema and versioning.
- [ ] Define database ERD and migrations.
- [ ] Define API contract and error format.
- [ ] Define authentication and RBAC.
- [ ] Define agent tool input/output schemas.
- [ ] Define response-action risk classes and approval rules.
- [ ] Define audit-event schema.
- [ ] Define deployment diagram and environment variables.
- [ ] Define test strategy and acceptance criteria.
- [ ] Create threat model and trust-boundary diagram.
- [ ] Record sources, versions, dates, and assumptions.

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
- [ ] Create repository and folder layout.
- [ ] Add Python project configuration and locked dependencies.
- [ ] Add frontend project and TypeScript configuration.
- [ ] Add formatting, linting, type checks, and pre-commit checks.
- [ ] Add unit-test framework and coverage reporting.
- [ ] Add `.env.example` with safe placeholders.
- [ ] Add structured logging and request IDs.
- [ ] Add health/readiness endpoint conventions.
- [ ] Add CI pipeline for lint, type checks, and tests.
- [ ] Document local setup and common commands.

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
- [ ] Docker Compose services for API, web, PostgreSQL, OpenSearch, and Redis.
- [ ] Persistent volumes for stateful services.
- [ ] Health checks and dependency readiness.
- [ ] Non-default credentials through environment variables/secrets.
- [ ] Network separation where practical.
- [ ] Database migration command.
- [ ] OpenSearch index-template/bootstrap command.
- [ ] Development resource limits.
- [ ] Backup and reset instructions.
- [ ] Optional local TLS profile for security testing.

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
- [ ] Roles: `ADMIN`, `SOC_ANALYST`, `THREAT_HUNTER`, `DETECTION_ENGINEER`, `SOC_MANAGER`, `SECURITY_ENGINEER`, `RESEARCHER`, `VIEWER`.
- [ ] Server-side permission checks on every protected route.
- [ ] User and role management.
- [ ] Session expiration and revocation.
- [ ] Authentication endpoint rate limits.
- [ ] Audit events for logins, permission changes, sensitive reads/actions.
- [ ] Consistent 401/403 behavior.
- [ ] Tests for privilege escalation and authorization bypass.

### Acceptance criteria
- Unauthenticated access to protected endpoints is denied.
- A viewer cannot perform analyst/admin actions.
- Permissions are enforced server-side.
- Sensitive actions create audit records.

## Phase 4 — Telemetry Ingestion

**Goal:** Ingest at least one real, authorized source reliably.

Start with Windows Event Logs/Sysmon or a sample-log importer if a Windows lab is unavailable.

### Develop
- [ ] Ingestion API or collector interface.
- [ ] Source registration and source identity.
- [ ] Batch ingestion and payload-size limits.
- [ ] Event ID and idempotency strategy.
- [ ] Validation and malformed-event quarantine.
- [ ] Raw event preservation.
- [ ] Ingestion counters and error metrics.
- [ ] Retry/back-pressure behavior.
- [ ] Source authentication.
- [ ] Safe sample data for development.
- [ ] Data retention and access policy.

### Acceptance criteria
- Valid events are accepted and searchable.
- Malformed events do not crash the service.
- Duplicate submissions are handled predictably.
- Authorized users can retrieve raw events.
- Ingestion failures are visible.

## Phase 5 — Canonical Event Schema and Normalization

**Goal:** Convert source-specific telemetry into a common event model while preserving provenance.

### Develop
- [ ] Versioned canonical event schema.
- [ ] Parsers for the first source.
- [ ] UTC normalization while preserving source timestamp.
- [ ] Stable event identifiers and source metadata.
- [ ] Host, user, process, network, file, and event-type fields where available.
- [ ] Schema validation.
- [ ] Parser version and normalization status.
- [ ] Unknown-field preservation.
- [ ] Quarantine and replay for failed parsing.
- [ ] Unit tests with representative fixtures.

### Acceptance criteria
- The same source event produces a stable normalized representation.
- Original raw event remains available.
- Parser failures are diagnosable and replayable.
- Schema version changes are documented.

## Phase 6 — Search and Event Exploration

**Goal:** Make telemetry useful to analysts before adding complex detection.

### Develop
- [ ] OpenSearch mappings/index templates.
- [ ] Search by time, host, user, source, type, IP, and severity.
- [ ] Pagination and query limits.
- [ ] Time-window defaults.
- [ ] Saved searches if needed.
- [ ] Search audit for sensitive data.
- [ ] Field-level redaction where appropriate.
- [ ] Search API and UI.
- [ ] Query performance tests.

### Acceptance criteria
- Analysts can find events using common filters.
- Queries are bounded and do not expose unrestricted query execution.
- Search results link to raw and normalized event views according to permissions.

## Phase 7 — Deterministic Detection Engine

**Goal:** Generate repeatable findings without relying on an LLM.

### Develop
- [ ] Sigma rule loading and validation.
- [ ] Explicit supported Sigma subset/translation strategy.
- [ ] Custom deterministic rules where needed.
- [ ] Rule metadata, versions, severity, source, owner, and ATT&CK references.
- [ ] Rule test fixtures.
- [ ] Finding schema and event references.
- [ ] Rule execution metrics and error handling.
- [ ] Rule enable/disable and staging status.
- [ ] Initial 10–20 carefully tested rules for available telemetry.
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
- [ ] Alert lifecycle and state machine.
- [ ] Acknowledge, assign, escalate, suppress, close, and reopen.
- [ ] Severity and status filters.
- [ ] Alert ownership and notes.
- [ ] Duplicate detection/deduplication.
- [ ] Audit state changes.
- [ ] Alert detail page with event/rule evidence.
- [ ] Add notifications only after core state transitions are reliable.

### Acceptance criteria
- Alerts are created from findings.
- State transitions follow defined rules.
- Each transition records actor, timestamp, and reason.
- Duplicate alerts are handled consistently.

## Phase 9 — Correlation Engine

**Goal:** Connect related alerts and events into incident candidates.

### Develop
- [ ] Time-window correlation.
- [ ] Correlation by host, user, IP, domain, process, session, and IOC.
- [ ] Configurable correlation rules.
- [ ] Provenance explaining why records were linked.
- [ ] Duplicate/cyclic relationship handling.
- [ ] Noise-control thresholds.
- [ ] Replayable tests using known multi-event scenarios.

### Acceptance criteria
- Related events are grouped according to documented rules.
- Unrelated events remain separate in test scenarios.
- Every relationship explains the key/rule causing the link.
- Correlation is repeatable for the same dataset.

## Phase 10 — Incident Management and Timeline

**Goal:** Create an incident workspace from investigation through closure.

### Develop
- [ ] Incident model and state machine.
- [ ] Link alerts, events, assets, users, IOCs, evidence, and ATT&CK techniques.
- [ ] Assignment and notes.
- [ ] Timeline with source timestamps.
- [ ] Separate incident severity and confidence fields.
- [ ] State transition audit.
- [ ] Incident list/detail pages.
- [ ] Incident report export.
- [ ] Audited merge/split workflow if needed.

### Acceptance criteria
- A correlation result can create an incident.
- Analysts can review linked evidence and timeline entries.
- State changes are auditable.
- Severity is not confused with AI confidence.

## Phase 11 — Evidence Engine

**Goal:** Ensure conclusions are grounded in retrievable facts.

### Develop
- [ ] Evidence record and provenance model.
- [ ] Links to raw/normalized events, detections, intelligence, and analyst notes.
- [ ] Integrity metadata, such as hashes where appropriate.
- [ ] Evidence relationships and timeline references.
- [ ] Conflicting evidence representation.
- [ ] Evidence collection API.
- [ ] Authorization and retention policy.
- [ ] Evidence completeness checks.

### Acceptance criteria
- Conclusions point to specific evidence records.
- Evidence source and collection time are available.
- Missing evidence is represented as unknown, not fabricated.
- AI-generated claims cannot silently become factual evidence.

## Phase 12 — MITRE ATT&CK Integration

**Goal:** Map findings to techniques and show detection coverage.

### Develop
- [ ] Import a pinned ATT&CK release.
- [ ] Store version and import date.
- [ ] Map rules/findings to tactics, techniques, and sub-techniques where supported.
- [ ] Support Detection Strategies/Analytics according to the selected release.
- [ ] Distinguish observed behavior from inferred technique mapping.
- [ ] Coverage dashboard.
- [ ] Mapping validation tests.
- [ ] Upgrade procedure for new ATT&CK versions.

### Acceptance criteria
- Each mapping references a valid identifier in the pinned version.
- UI distinguishes confirmed mappings from AI suggestions.
- Coverage is based on implemented/tested detections, not merely imported technique lists.

## Phase 13 — Threat Intelligence

**Goal:** Enrich investigations with sourced indicator context.

### Develop
- [ ] IOC model for IP, domain, URL, file hash, email, and certificate where relevant.
- [ ] Manual/imported IOC feeds.
- [ ] Source, confidence, first seen, last seen, collection time, and expiry.
- [ ] STIX/TAXII-compatible adapter design.
- [ ] Provider adapters with timeouts and rate limits.
- [ ] IOC matching against events.
- [ ] Source reliability and conflicting-reputation handling.
- [ ] TLP/handling metadata where applicable.
- [ ] Cache and freshness policy.

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
- [ ] Authorized, audited tuning only.

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
- [ ] Research report generation.

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
- [ ] Structured logs with correlation IDs.
- [ ] Metrics for ingestion, parsing, rules, search, agents, tools, and response.
- [ ] Queue-depth and dropped-event monitoring.
- [ ] Service health/readiness.
- [ ] Retries with backoff and quarantine/dead-letter strategy.
- [ ] Idempotent jobs/actions.
- [ ] Agent/model timeouts and circuit breakers.
- [ ] Per-agent token, step, and cost budgets.
- [ ] Safe caching.
- [ ] Database and OpenSearch backups.
- [ ] Restore test.
- [ ] Defined RPO/RTO for the intended deployment.

### Acceptance criteria
- Operators can identify ingestion and agent failures.
- AI outage does not stop deterministic detections.
- Retries do not duplicate consequential actions.
- Backup restoration is tested and documented.
- Resource limits prevent uncontrolled workload growth.

## Phase 26 — Security Testing and Production Hardening

**Goal:** Test the platform as a security product.

### Develop
- [ ] Unit, integration, end-to-end, and regression suites.
- [ ] Authentication and authorization testing.
- [ ] API abuse/rate-limit testing.
- [ ] Injection and input-validation testing.
- [ ] SSRF/command-injection review where applicable.
- [ ] Prompt-injection and RAG-poisoning tests.
- [ ] Tool abuse and privilege-boundary tests.
- [ ] Secret scanning.
- [ ] SAST and dependency scanning.
- [ ] Container image scanning.
- [ ] SBOM generation.
- [ ] TLS and encryption checks.
- [ ] Backup/restore exercise.
- [ ] Independent security review before production use.

### Acceptance criteria
- No unresolved critical/high-risk findings without documented risk acceptance.
- Security tests run in CI where feasible.
- Secrets are not present in repository history or logs.
- Production deployment is not enabled merely because the UI looks complete.

## Phase 27 — Release 1.0 and Documentation

**Goal:** Package a reproducible, testable release.

### Deliverables
- [ ] Versioned application release.
- [ ] Docker Compose deployment profile.
- [ ] Environment variable reference.
- [ ] Installation and upgrade guide.
- [ ] User and administrator guides.
- [ ] API docs.
- [ ] Rule authoring guide.
- [ ] Agent/tool permission guide.
- [ ] Incident response and recovery guide.
- [ ] Threat model and security limitations.
- [ ] Dataset and benchmark documentation.
- [ ] Research report.
- [ ] Demo scenario and known limitations.
- [ ] Release checklist and rollback plan.

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
