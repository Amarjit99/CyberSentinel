# CyberSentinel AI — Requirements Traceability Matrix (RTM)

**Audit Phase:** Phase 0 — Pre-Implementation Baseline  
**Date of Verification:** October 16, 2026  
**Status:** 100% Coverage (30/30 Functional Requirements Mapped)  
**Governing Authority:** `docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md` §8 & `docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md`  

---

## 1. Overview & Verification Strategy

The Requirements Traceability Matrix (RTM) guarantees end-to-end traceability from each formal functional requirement (FR-001 through FR-030) defined in the master specification to:
1. **Target Subsystem / Microservice** responsible for implementation.
2. **Authoritative Relational Database Entities** and storage domains.
3. **Automated Test Identifier (Test ID)** required for continuous integration gate validation.
4. **Primary Companion Specification** containing granular architectural requirements.
5. **Implementation Phase Sprint** defined in the 28-phase master build plan.

Every requirement must have a passing automated test suite before the corresponding Phase exit gate can be approved.

---

## 2. Complete Traceability Matrix

| Req ID | Requirement Name | Automated Test ID | Target Service | Authoritative Entities | Acceptance Criteria Summary | Companion Document | Build Phase |
|:---:|---|:---:|---|---|---|---|:---:|
| **FR-001** | Telemetry Ingestion | `TEST-FR-001` | Ingestion Service / Adapters | `events, connectors` | Ingest Windows, Sysmon, Linux, Suricata, Zeek & TI | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 4 |
| **FR-002** | Raw Event Preservation | `TEST-FR-002` | Ingestion / Storage Service | `raw_events, Object Storage` | Byte-level payload & SHA-256 integrity preserved | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 4 |
| **FR-003** | Event Normalization | `TEST-FR-003` | Normalization Service | `canonical_events (OpenSearch)` | Conform to CanonicalEvent Pydantic v2 schema | [09-DATA-ARCHITECTURE.md](file:///docs/09-DATA-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 5 |
| **FR-004** | Event Validation & Quarantine | `TEST-FR-004` | Ingestion / Validator | `quarantine_events` | Invalid events routed to quarantine without pipeline crash | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 5 |
| **FR-005** | Event Enrichment | `TEST-FR-005` | Enrichment Service | `assets, identities, iocs` | Contextual metadata (GeoIP, Asset, Identity) attached | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 5 |
| **FR-006** | Detection Rules (Sigma) | `TEST-FR-006` | Detection Engine | `rules, rule_versions` | Sigma YAML syntax parsed, validated, and versioned | [14-SIGMA-DETECTION-ARCHITECTURE.md](file:///docs/14-SIGMA-DETECTION-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 7 |
| **FR-007** | Detection Execution | `TEST-FR-007` | Detection Engine | `OpenSearch Query DSL` | Rules execute deterministically over normalized events | [14-SIGMA-DETECTION-ARCHITECTURE.md](file:///docs/14-SIGMA-DETECTION-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 7 |
| **FR-008** | Finding Generation | `TEST-FR-008` | Detection Engine | `detections, detection_events` | Structured detection finding created with event links | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 7 |
| **FR-009** | Alert Management | `TEST-FR-009` | Alert Service | `alerts, alert_events` | Analyst ACK, assign, suppress, escalate, close lifecycle | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 8 |
| **FR-010** | Event Correlation | `TEST-FR-010` | Correlation Engine | `incident_events, incident_entities` | Multi-event correlation by time, host, user, IP & technique | [20-INCIDENT-LIFECYCLE.md](file:///docs/20-INCIDENT-LIFECYCLE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 9 |
| **FR-011** | Incident Creation & States | `TEST-FR-011` | Incident Service | `incidents, incident_assignments` | Incident state machine transitions per ADR-0001 | [20-INCIDENT-LIFECYCLE.md](file:///docs/20-INCIDENT-LIFECYCLE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 10 |
| **FR-012** | Incident Timeline | `TEST-FR-012` | Incident / UI Service | `incident_timeline` | Chronological evidence timeline with sub-second ordering | [20-INCIDENT-LIFECYCLE.md](file:///docs/20-INCIDENT-LIFECYCLE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 10 |
| **FR-013** | AI Triage Agent | `TEST-FR-013` | Triage Agent Service | `agent_runs, agent_findings` | Structured triage output, confidence & explainability | [10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 15 |
| **FR-014** | AI Investigation Agent | `TEST-FR-014` | Investigation Agent Service | `investigations, agent_tool_calls` | Bounded investigation plan executed via approved tools | [10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 17 |
| **FR-015** | Evidence Engine | `TEST-FR-015` | Evidence Subsystem | `evidence, evidence_relationships` | Immutable evidence linking source event IDs to claims | [10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 11 |
| **FR-016** | Threat Intel Enrichment | `TEST-FR-016` | Threat Intel Agent | `iocs, threat_intelligence` | STIX 2.1 IOC lookup with confidence and expiry tracking | [15-THREAT-INTELLIGENCE.md](file:///docs/15-THREAT-INTELLIGENCE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 13 |
| **FR-017** | Threat Hunting | `TEST-FR-017` | Threat Hunting Agent | `OpenSearch Search API` | Read-only hypothesis-driven historical query execution | [10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 18 |
| **FR-018** | Query Translation | `TEST-FR-018` | Query Translation Service | `DSL Validator` | Natural language translated to validated read-only Query DSL | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 18 |
| **FR-019** | MITRE ATT&CK Mapping | `TEST-FR-019` | ATT&CK Service | `attack_mappings, tactics, techniques` | Tactics, techniques, sub-techniques & detection strategies | [13-MITRE-ATTCK-MAPPING.md](file:///docs/13-MITRE-ATTCK-MAPPING.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 12 |
| **FR-020** | Risk Calculation | `TEST-FR-020` | Deterministic Risk Engine | `risk_scores, risk_factors` | Explainable mathematical risk score (0-100) with factor weights | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 14 |
| **FR-021** | Attack Graph Visualizer | `TEST-FR-021` | Graph Service | `incident_entities, graph_edges` | Directed graph rendering entity relationships over time | [20-INCIDENT-LIFECYCLE.md](file:///docs/20-INCIDENT-LIFECYCLE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 10 |
| **FR-022** | Response Planning | `TEST-FR-022` | Response Agent Service | `response_proposals, playbooks` | Playbook proposal generation with exact action payload hash | [21-RESPONSE-PLAYBOOKS.md](file:///docs/21-RESPONSE-PLAYBOOKS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 20 |
| **FR-023** | Human Approval Workflow | `TEST-FR-023` | Approval Service | `approvals, security_policies` | Strict approval gate enforcement per ADR-0006 risk tiers | [21-RESPONSE-PLAYBOOKS.md](file:///docs/21-RESPONSE-PLAYBOOKS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 20 |
| **FR-024** | Versioned Playbooks | `TEST-FR-024` | Playbook Registry | `playbooks, playbook_versions` | Declarative YAML playbook schema parsing and version control | [21-RESPONSE-PLAYBOOKS.md](file:///docs/21-RESPONSE-PLAYBOOKS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 20 |
| **FR-025** | Controlled Action Execution | `TEST-FR-025` | Response Adapter Service | `response_actions` | Idempotent lab response execution with pre/post verification | [21-RESPONSE-PLAYBOOKS.md](file:///docs/21-RESPONSE-PLAYBOOKS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 20 |
| **FR-026** | Audit Logging Subsystem | `TEST-FR-026` | Audit Service | `audit_events` | Tamper-resistant audit trail for all security-sensitive actions | [11-SECURITY-ARCHITECTURE.md](file:///docs/11-SECURITY-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 3 |
| **FR-027** | Agent Execution Audit | `TEST-FR-027` | Agent Orchestrator | `agent_runs, agent_tool_calls` | Full execution audit: prompt version, tools, tokens, budget | [10-AGENT-ARCHITECTURE.md](file:///docs/10-AGENT-ARCHITECTURE.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 16 |
| **FR-028** | Incident Reporting | `TEST-FR-028` | Reporting Service | `incident_reports, Object Storage` | Exportable incident reports distinguishing facts from AI inferences | [06-FUNCTIONAL-REQUIREMENTS.md](file:///docs/06-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 24 |
| **FR-029** | SOC Performance Metrics | `TEST-FR-029` | Analytics & Metrics Engine | `soc_metrics, prometheus` | Automated tracking of MTTD, MTTA, MTTR, precision, recall | [07-NON-FUNCTIONAL-REQUIREMENTS.md](file:///docs/07-NON-FUNCTIONAL-REQUIREMENTS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 25 |
| **FR-030** | Benchmarking Laboratory | `TEST-FR-030` | Benchmark Evaluation Harness | `experiments, ground_truth` | Automated replay of 14 lab attack scenarios vs ground truth | [25-ATTACK-SCENARIOS.md](file:///docs/25-ATTACK-SCENARIOS.md) | docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md #Phase 22 |

---

## 3. Test ID Taxonomy & Verification Gates

- **Unit & Normalization Tests (`TEST-FR-001` to `TEST-FR-005`):** Executed on every pull request. Asserts JSON schema validation, Pydantic type conversions, quaternion isolation, and zero unhandled exceptions on malformed payloads.
- **Deterministic Detection & Correlation Tests (`TEST-FR-006` to `TEST-FR-012`):** Validates Sigma rule parsing, query translation, and temporal multi-entity incident clustering.
- **AI Agent Security & Tool Boundary Tests (`TEST-FR-013` to `TEST-FR-021`, `TEST-FR-027`):** Runs automated prompt injection fixtures, negative tool authorization tests, token budget cutoffs, and evidence citation grounding checks.
- **Governance & Approval Gating Tests (`TEST-FR-022` to `TEST-FR-026`):** Asserts that Tier 2 actions cannot execute without signed single-analyst approval, Tier 3 actions require dual-authorization, and audit records are immutably persisted.
- **Benchmark & Metrics Tests (`TEST-FR-028` to `TEST-FR-030`):** Automated harness replaying synthetic datasets and 14 lab scenarios against ground-truth baselines to calculate precision, recall, MTTD, and MTTR.

---

## 4. Traceability Sign-off

- **Coverage Rate:** 100.0% (30 of 30 Functional Requirements Mapped).
- **Orphaned Requirements:** 0.
- **Unverified Components:** 0.
- **Phase 0 Audit Status:** **PASSED VERIFICATION GATE**.
