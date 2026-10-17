# CyberSentinel AI — Comprehensive Conflict Register

**Audit Baseline:** Phase 0 Pre-Implementation Baseline  
**Date of Audit:** October 16, 2026  
**Status:** All P0 and P1 Conflicts Documented & Mapped to Architecture Decision Records (ADRs)  
**Machine-Readable Twin:** [`docs/audit/conflict_register.json`](conflict_register.json)  

---

## 1. Conflict Summary Dashboard

| Severity | Total Found | Resolved by ADR | Awaiting User Review | Blocker Status |
|---|:---:|:---:|:---:|---|
| **P0 (Critical / Blocker)** | 1 | 1 | 0 | Resolved via ADR-0001 |
| **P1 (High)** | 7 | 7 | 0 | Resolved via ADR-0002 to ADR-0006 & Traceability Matrix |
| **P2 (Medium)** | 2 | 2 | 0 | Resolved via ADR-0007 & Privacy Protocol |
| **Total Conflicts** | **10** | **10** | **0** | **Phase 0 Unblocked** |

---

## 2. Granular Conflict Records

### CONFL-001: Incident Lifecycle States and State Machine Transitions Contradiction

- **Severity:** `P0` | **Category:** Incident Lifecycle State Machine | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0001-unified-incident-lifecycle.md`](../decisions/ADR-0001-unified-incident-lifecycle.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 27 (Incident Lifecycle) (Lines 1296-1320)
  - Declared: `NEW, TRIAGED, INVESTIGATING, CONFIRMED / BENIGN, CONTAINMENT_PENDING, CONTAINED, ERADICATION, RECOVERY, CLOSED, LESSONS_LEARNED`
- **[06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md):** Incident Management (Line 19)
  - Declared: `NEW, TRIAGE, INVESTIGATING, AWAITING_APPROVAL, CONTAINMENT, RECOVERY, CLOSED, REOPENED`
- **[20-INCIDENT-LIFECYCLE.md](file:///docs/20-INCIDENT-LIFECYCLE.md):** Lifecycle State Machine (Line 19)
  - Declared: `NEW, TRIAGE, INVESTIGATING, AWAITING_APPROVAL, CONTAINMENT, RECOVERY, CLOSED, REOPENED`

#### Architectural Impact & Blast Radius
High blast radius. A fractured state machine breaks database check constraints, frontend state rendering, API transition validations, and automated playbook triggers. If the backend expects 'TRIAGED' but the frontend transitions to 'TRIAGE', or if approval gating relies on 'AWAITING_APPROVAL' while forensic workflows expect 'CONTAINMENT_PENDING', state corruption and deadlocks occur.

#### Root Cause Analysis
The master requirements specification modeled an extended NIST/ISO forensic incident lifecycle (including containment, eradication, and post-incident lessons learned), whereas companion documents 06 and 20 condensed the states for operational workflow ergonomics, introducing approval and reopening states without updating the master document.

#### Recommended Resolution & Architecture Decision
Ratify a unified, comprehensive 11-state incident lifecycle state machine via ADR-0001: NEW -> TRIAGE -> INVESTIGATING -> CONFIRMED (or BENIGN) -> AWAITING_APPROVAL -> CONTAINMENT -> ERADICATION -> RECOVERY -> CLOSED -> LESSONS_LEARNED (with bidirectional REOPENED transition from CLOSED).

#### Verification & Test Strategy
Automated state transition matrix test (TEST-FR-011) verifying all legal state transitions, illegal transition rejections, and state enum consistency across Pydantic schemas and PostgreSQL DDL.

---

### CONFL-002: Agent Role Catalog and Delegation Taxonomy Discrepancy

- **Severity:** `P1` | **Category:** Multi-Agent Architecture & Taxonomy | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0002-standardized-agent-taxonomy.md`](../decisions/ADR-0002-standardized-agent-taxonomy.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 9 & Section 11 (Lines 565-670, 699-713)
  - Declared: `Triage Agent, Investigation Agent, Threat Intelligence Agent, Threat Hunting Agent, Evidence Agent, Risk Agent, Detection Engineering Agent, Response Agent`
- **[10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md):** Proposed specialized agents (Lines 6-15)
  - Declared: `Triage agent, Evidence collector, Threat-intelligence analyst, ATT&CK mapper, Correlation assistant, Investigation planner, Response advisor, Report writer`

#### Architectural Impact & Blast Radius
Agent permission matrices, SPIFFE/SPIRE workload identities, and tool allowlists depend on canonical agent identifiers. Divergent agent naming prevents RBAC policy enforcement at the Policy Enforcement Point (PEP) and obscures audit log attribution.

#### Root Cause Analysis
Doc 10 decomposed investigation and reporting into micro-skills (planner, mapper, correlation assistant, report writer), while the master specification grouped them into 8 autonomous specialized service agents.

#### Recommended Resolution & Architecture Decision
Ratify an authoritative 8-agent core system in ADR-0002. Map Doc 10's functional specializations as modular sub-capabilities executed within the 8 core agent identities: Investigation Agent incorporates Investigation Planner, ATT&CK Mapper, and Correlation Assistant; Response Agent executes Response Advisor playbooks; Evidence Agent serves as Evidence Collector; and Triage Agent handles triage classification and draft reporting.

#### Verification & Test Strategy
Agent registry schema validation (TEST-FR-014, TEST-FR-027) ensuring every agent run references a valid canonical AgentId with verified least-privilege tool allowlists.

---

### CONFL-003: Database Relational Entity Model vs Monolithic Table List Divergence

- **Severity:** `P1` | **Category:** Database Architecture & Storage Tiering | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0003-storage-tiering-and-database-entities.md`](../decisions/ADR-0003-storage-tiering-and-database-entities.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 14 (Database Model) (Lines 787-861)
  - Declared: 45+ tables listed monolithically including raw_events, normalized_events, detections, rules, attack mappings, etc.
- **[18-DATABASE-SCHEMA.md](file:///docs/18-DATABASE-SCHEMA.md):** Core relational entities & Storage split (Lines 3-24)
  - Declared: 17 authoritative relational entities in PostgreSQL (users, roles, user_roles, connectors, events, detections, detection_events, incidents, incident_detections, incident_entities, evidence, incident_notes, agent_runs, agent_findings, response_proposals, approvals, response_actions, audit_events).
- **[09-DATA-ARCHITECTURE.md](file:///docs/09-DATA-ARCHITECTURE.md):** Storage placement (Lines 14-20)
  - Declared: Defines hybrid split: PostgreSQL for relational state, OpenSearch for high-volume telemetry, Redis for ephemeral caching.

#### Architectural Impact & Blast Radius
Attempting to create all 45 tables in PostgreSQL for high-volume raw telemetry leads to severe I/O bottlenecks and bloat. Conversely, omitting detection and incident tables from migrations causes pipeline failures.

#### Root Cause Analysis
Master specification §14 documented an abstract, conceptual entity-relationship catalog. Doc 18 designed the concrete, transaction-safe PostgreSQL relational schema, purposefully delegating event document storage to OpenSearch.

#### Recommended Resolution & Architecture Decision
Ratify the hybrid storage tiering architecture via ADR-0003: PostgreSQL manages the 17 authoritative transactional entities defined in Doc 18; OpenSearch manages normalized telemetry indices (canonical_events-*, raw_events-*); Redis provides short-lived lock and task coordination; and Object Storage archives raw payloads and evidence files.

#### Verification & Test Strategy
Database migration integration tests (TEST-FR-003, TEST-FR-026) running Alembic upgrade/downgrade scripts and verifying table constraints and foreign keys.

---

### CONFL-004: Role-Based Access Control System Role Taxonomy Alignment

- **Severity:** `P1` | **Category:** Identity & Access Control (RBAC) | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0004-rbac-roles-and-permissions.md`](../decisions/ADR-0004-rbac-roles-and-permissions.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 24 (Authentication and Authorization) (Lines 1184-1195)
  - Declared: `SOC_ANALYST, THREAT_HUNTER, DETECTION_ENGINEER, SOC_MANAGER, SECURITY_ENGINEER, ADMIN, RESEARCHER, VIEWER`
- **[01-PROJECT-VISION.md](file:///docs/01-PROJECT-VISION.md):** Primary users (Lines 19-25)
  - Declared: `SOC analyst, Detection engineer, SOC lead, Platform/security administrator, Researcher/evaluator`
- **[11-SECURITY-ARCHITECTURE.md](file:///docs/11-SECURITY-ARCHITECTURE.md):** Identity and access (Lines 6-12)
  - Declared: None

#### Architectural Impact & Blast Radius
Inconsistent role strings break JWT claim parsing, route-level authorization decorators in FastAPI, and database role assignment tables.

#### Root Cause Analysis
Vision documents used conversational job personas ('SOC lead', 'Platform administrator'), whereas technical architecture specified formal UPPERCASE machine-enforceable role enums.

#### Recommended Resolution & Architecture Decision
Standardize the 8 authoritative system role enum values in ADR-0004: SOC_ANALYST, THREAT_HUNTER, DETECTION_ENGINEER, SOC_MANAGER, SECURITY_ENGINEER, ADMIN, RESEARCHER, VIEWER. Map user personas directly to these canonical roles.

#### Verification & Test Strategy
Automated RBAC authorization test suite (TEST-FR-026) verifying role-permission mappings and negative access control checks.

---

### CONFL-005: Canonical Event Schema Field Definitions and Normalization Contracts

- **Severity:** `P1` | **Category:** Telemetry Pipeline & Event Schema | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0005-canonical-event-schema-standards.md`](../decisions/ADR-0005-canonical-event-schema-standards.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 13 (Canonical Event Schema) (Lines 751-785)
  - Declared: 23 minimum fields in JSON format: event_id, timestamp, ingest_timestamp, source_type, source_name, event_type, host_id, hostname, user_id, username, src_ip, dst_ip, src_port, dst_port, process_name, process_id, parent_process, command_line, hash_sha256, domain, url, severity, raw_event.
- **[09-DATA-ARCHITECTURE.md](file:///docs/09-DATA-ARCHITECTURE.md):** Data domains (Lines 4-13)
  - Declared: High-level domain descriptions (normalized timestamp, event category/action/outcome, source product, host/user/process/network/cloud entities).
- **[00-PHASE-WISE-IMPLEMENTATION-PLAN.md](file:///docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md):** Phase 5 (Lines 185-215)
  - Declared: Pydantic CanonicalEvent model with field validators.

#### Architectural Impact & Blast Radius
Incompatible normalization pipelines create ingestion crashes, unparseable detection queries in Sigma, and broken timeline visualizations.

#### Root Cause Analysis
Different documents presented schema at different levels of abstraction (abstract domain vs concrete JSON vs Pydantic model).

#### Recommended Resolution & Architecture Decision
Codify the authoritative CanonicalEvent Pydantic v2 model via ADR-0005, enforcing strict UTC ISO-8601 timestamps, UUIDv4 event IDs, network IP validation, and an extensible dictionary structure for custom telemetry.

#### Verification & Test Strategy
Schema validation and normalization test suite (TEST-FR-003, TEST-FR-004) processing valid, missing-field, and malformed telemetry events.

---

### CONFL-006: Response Action Risk Tiering and Approval Classification Nomenclature

- **Severity:** `P1` | **Category:** Response Orchestration & Governance | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0006-response-action-risk-tiering.md`](../decisions/ADR-0006-response-action-risk-tiering.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 12 (Human-in-the-Loop Policy) (Lines 715-749)
  - Declared: 3-tier classification: Low-risk (automated), Medium-risk (analyst approval), High-risk (explicit dual approval).
- **[21-RESPONSE-PLAYBOOKS.md](file:///docs/21-RESPONSE-PLAYBOOKS.md):** Action risk tiers (Lines 14-19)
  - Declared: 4-tier classification: Tier 0 (read-only/enrichment), Tier 1 (reversible/lab), Tier 2 (containment/identity - human approval), Tier 3 (destructive/broad - disabled).

#### Architectural Impact & Blast Radius
Mismatched risk tiers can lead to either accidental unapproved execution of disruptive actions (e.g. host isolation) or approval fatigue on harmless lookups.

#### Root Cause Analysis
The master spec used intuitive risk labels (Low/Medium/High), while the response playbook companion adopted a numerical zero-indexed tier system (Tier 0 to Tier 3) to explicitly distinguish read-only actions from reversible changes.

#### Recommended Resolution & Architecture Decision
Harmonize the taxonomy in ADR-0006 by establishing a 4-tier model with dual labels: Tier 0 (Autonomous / Low), Tier 1 (Lab-Safe / Low), Tier 2 (Disruptive Containment / Medium - Requires Single Analyst Approval), Tier 3 (High-Impact / Consequential - Requires Explicit Dual Authorization). Destructive actions remain permanently disabled in Phase 0-1.

#### Verification & Test Strategy
Policy Enforcement Point test suite (TEST-FR-023, TEST-FR-025) verifying approval gates, payload hash validation, and execution blocking.

---

### CONFL-007: Implementation Phase Numbering and Milestone Structure Reconciliation

- **Severity:** `P2` | **Category:** Project Roadmap & Sequencing | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0007-implementation-phase-reconciliation.md`](../decisions/ADR-0007-implementation-phase-reconciliation.md)

#### Conflicting Sources & Exact Citations
- **[00-PHASE-WISE-IMPLEMENTATION-PLAN.md](file:///docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md):** Phases (Lines 65-885)
  - Declared: 28 granular phases (Phase 0 through Phase 27).
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 43 & Section 60 (Lines 1792-1915, 2324-2387)
  - Declared: 13 development phases (Phase 0 to 12) grouped into 7 releases (Release 0.1 to 1.0).
- **[30-IMPLEMENTATION-ROADMAP.md](file:///docs/30-IMPLEMENTATION-ROADMAP.md):** Build order & Release gates (Lines 6-32)
  - Declared: 11 condensed build stages (Stages 0 to 10) governed by Release Gates G0 to G6.

#### Architectural Impact & Blast Radius
Confusion among developers and auditors regarding sprint planning, progress tracking, and exit criteria.

#### Root Cause Analysis
Each document represented project progression at a different zoom level: execution sprints (28 phases), development milestones (13 phases), release packaging (7 releases), and architectural gates (7 gates).

#### Recommended Resolution & Architecture Decision
Formalize the 3-tier planning hierarchy in ADR-0007: Release Milestones (v0.1 to v1.0) contain Condensed Build Stages (0 to 10 with Gates G0 to G6), which decompose into 28 Granular Execution Sprints (Phases 0 to 27). Phase 0 (current) covers Specification and Engineering Contracts.

#### Verification & Test Strategy
Phase exit criteria audit against Gate G0 and Phase 0 acceptance requirements.

---

### CONFL-008: AI Agent Tool Execution Boundaries and Shell Access Prohibition

- **Severity:** `P1` | **Category:** AI Safety & Tool Boundaries | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0002-standardized-agent-taxonomy.md`](../decisions/ADR-0002-standardized-agent-taxonomy.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 22 (Tool Security) (Lines 1113-1126)
  - Declared: States 'No free-form shell tool in production. If shell access is ever required in the lab, use: isolated container, non-root user, command allowlist...'.
- **[10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md):** Tool-use controls (Line 28)
  - Declared: States 'No unrestricted shell, arbitrary URL fetch, generic database access, or dynamic code execution.'
- **[22-AI-SAFETY-CONTROLS.md](file:///docs/22-AI-SAFETY-CONTROLS.md):** Tool governance (Lines 15-20)
  - Declared: Explicitly restricts agent tool calling to typed REST/JSON endpoints.

#### Architectural Impact & Blast Radius
Allowing shell execution introduces high-severity remote code execution and prompt injection risks into the agent runtime.

#### Root Cause Analysis
Master spec included theoretical laboratory isolation provisions for future offensive/defensive simulations, creating ambiguity regarding whether agents could execute shell commands.

#### Recommended Resolution & Architecture Decision
Reaffirm in ADR-0002 and ADR-0006 that CyberSentinel AI core services and agents NEVER have shell access in any environment (production, staging, or development). All agent capabilities are strictly mediated via typed JSON tool contracts over explicit microservice APIs with rigid input validation.

#### Verification & Test Strategy
Tool registry unit test (TEST-FR-014) asserting zero shell execution tools exist in the tool registry.

---

### CONFL-009: Two-Stage Telemetry Redaction and External AI Model Privacy Boundaries

- **Severity:** `P2` | **Category:** Data Privacy & Redaction Pipeline | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`ADR-0005-canonical-event-schema-standards.md`](../decisions/ADR-0005-canonical-event-schema-standards.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 30 (Privacy) (Lines 1377-1408)
  - Declared: Raw Event -> Classification -> Redaction -> Policy Check -> Allowed? -> Model.
- **[23-DATA-PRIVACY.md](file:///docs/23-DATA-PRIVACY.md):** Redaction pipeline (Lines 10-25)
  - Declared: Pre-storage redaction and pre-model tokenization.

#### Architectural Impact & Blast Radius
Sending unredacted customer logs to external LLM providers constitutes a severe privacy and compliance violation (GDPR, HIPAA, SOC 2).

#### Root Cause Analysis
Documents differed on whether redaction occurs prior to storage (which could impair raw forensic preservation) or immediately prior to model dispatch.

#### Recommended Resolution & Architecture Decision
Ratify a two-stage redaction protocol: Stage 1 (Storage Gate: raw telemetry is encrypted at rest in quarantined storage with strict access controls; searchable index masks passwords, API tokens, and known credentials); Stage 2 (LLM Gateway: before any prompt or context is sent to an external model, personal identifiers and proprietary IP are redacted/tokenized, and tenant AI policy is checked).

#### Verification & Test Strategy
Data privacy redaction test suite (TEST-FR-004, TEST-FR-027) verifying credential masking and prompt redaction.

---

### CONFL-010: Requirements Traceability to Automated Test Suite Identifiers

- **Severity:** `P1` | **Category:** Verification & Quality Assurance | **Status:** `RESOLVED_BY_ADR`
- **Governing Resolution:** [`TRACEABILITY_MATRIX.md`](../decisions/TRACEABILITY_MATRIX.md)

#### Conflicting Sources & Exact Citations
- **[00-MASTER-REQUIREMENTS-SPECIFICATION.md](file:///docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md):** Section 8 (Functional Requirements) (Lines 351-563)
  - Declared: 30 Functional Requirements (FR-001 through FR-030).
- **[24-TESTING-STRATEGY.md](file:///docs/24-TESTING-STRATEGY.md):** Test pyramid & Test gates (Lines 3-25)
  - Declared: General test categories (Unit, Contract, Integration, E2E, Security, Resilience) without explicit mapping to FR-001..FR-030.

#### Architectural Impact & Blast Radius
Lack of 1-to-1 requirement-to-test mapping makes it impossible to verify automated test coverage or satisfy Phase 0 exit acceptance criteria.

#### Root Cause Analysis
The testing strategy document focused on test methodology rather than maintaining a granular verification traceability matrix.

#### Recommended Resolution & Architecture Decision
Construct a comprehensive Requirements Traceability Matrix in `docs/audit/TRACEABILITY_MATRIX.md` establishing a direct 1-to-1 mapping from each FR-001 through FR-030 to concrete automated test suite identifiers (`TEST-FR-001` through `TEST-FR-030`), target services, verification methods, and acceptance thresholds.

#### Verification & Test Strategy
Automated matrix completeness verification script confirming 100% of FRs map to test IDs and acceptance criteria.

---

