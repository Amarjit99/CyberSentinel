# CyberSentinel AI — Authoritative Baseline & Naming Conventions

**Document Type:** Architecture Baseline & Engineering Standards  
**Status:** Single Source of Truth for Engineering Nomenclature  
**Date:** October 16, 2026  
**Governing Documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` & `docs/decisions/`  

---

## 1. Naming & Case Conventions

To prevent cross-service serialization errors, database migration bugs, and routing mismatches, all components must adhere to the following case standards:

| Entity Type | Case Standard | Example | Context |
|---|---|---|---|
| **PostgreSQL Tables & Columns** | `snake_case` (lowercase) | `incident_detections`, `event_time` | Database DDL & SQL migrations |
| **Pydantic & TypeScript Models** | `PascalCase` | `CanonicalEvent`, `IncidentRecord` | Schemas & Object types |
| **Python Variables & Functions** | `snake_case` | `normalize_event()`, `calculate_risk()` | Backend Python services |
| **REST API Route Paths** | `kebab-case` (lowercase) | `/api/v1/incident-events`, `/api/v1/playbooks` | HTTP API endpoints |
| **Agent Identifiers** | `kebab-case` (lowercase) | `triage-agent`, `investigation-agent` | Agent registry & workload identity |
| **RBAC System Roles** | `SCREAMING_SNAKE_CASE` | `SOC_ANALYST`, `DETECTION_ENGINEER` | JWT claims & access tokens |
| **Lifecycle State Machine** | `SCREAMING_SNAKE_CASE` | `NEW`, `TRIAGE`, `AWAITING_APPROVAL` | Incident & proposal state enums |
| **Response Action Risk Tiers** | `PascalCase` / Tiered | `Tier 0`, `Tier 1`, `Tier 2`, `Tier 3` | Policy engine risk levels |
| **Environment Configuration** | `SCREAMING_SNAKE_CASE` | `OPENSEARCH_URL`, `POSTGRES_PASSWORD` | Docker `.env` & secret manager |
| **OpenSearch Indices** | `snake_case` with date pattern | `canonical_events-2026.10`, `detections-2026.10` | Elasticsearch / OpenSearch index |

---

## 2. Authoritative Incident Lifecycle State Machine

As ratified in [ADR-0001](decisions/ADR-0001-unified-incident-lifecycle.md):

```text
NEW -> TRIAGE -> INVESTIGATING -> [ CONFIRMED | BENIGN ]
  │
  └── (if CONFIRMED and Response Proposed)
        └── AWAITING_APPROVAL -> CONTAINMENT -> ERADICATION -> RECOVERY -> CLOSED
                                                                             ├── LESSONS_LEARNED
                                                                             └── REOPENED (if recurred)
```

**State Enum:** `NEW`, `TRIAGE`, `INVESTIGATING`, `CONFIRMED`, `BENIGN`, `AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `CLOSED`, `LESSONS_LEARNED`, `REOPENED`.

---

## 3. Authoritative Multi-Agent Registry

As ratified in [ADR-0002](decisions/ADR-0002-standardized-agent-taxonomy.md):

1. `triage-agent`: Initial alert classification, enrichment, priority scoring & draft reporting.
2. `investigation-agent`: Investigation plan generation, graph traversal, timeline correlation & hypothesis formulation.
3. `threat-intel-agent`: STIX 2.1 query, reputation assessment, IOC matching & campaign attribution.
4. `threat-hunting-agent`: Structured read-only query construction & historical anomaly searching.
5. `evidence-agent`: Immutable evidence collection, hash verification & provenance graph creation.
6. `attack-mapping-agent`: MITRE ATT&CK Enterprise technique & detection strategy linking.
7. `risk-agent`: Multi-factor explainable risk score calculation (0-100) & uncertainty estimation.
8. `response-agent`: Playbook recommendation & exact action payload generation (Approval-Gated).

**Absolute Boundary:** No agent has shell access or arbitrary code execution tools. All agent operations are bounded REST tool calls.

---

## 4. Authoritative RBAC System Roles

As ratified in [ADR-0004](decisions/ADR-0004-rbac-roles-and-permissions.md):

1. `SOC_ANALYST`
2. `THREAT_HUNTER`
3. `DETECTION_ENGINEER`
4. `SOC_MANAGER`
5. `SECURITY_ENGINEER`
6. `ADMIN`
7. `RESEARCHER`
8. `VIEWER`

---

## 5. Authoritative Response Risk Tiers

As ratified in [ADR-0006](decisions/ADR-0006-response-action-risk-tiering.md):

- **Tier 0 (Autonomous / Read-Only):** Automatic execution. No human gate.
- **Tier 1 (Lab-Safe / Low Risk):** Reversible lab simulation actions. Lab policy check.
- **Tier 2 (Disruptive Containment):** Single human analyst approval bound to SHA-256 payload hash.
- **Tier 3 (Consequential / High-Impact):** Dual-human authorization (Analyst + SOC Manager).
- **Execution Mode:** Live response actions remain disabled during Phase 0 and Phase 1; all executions run in simulated/dry-run mode.

---

## 6. Authoritative Canonical Event Model

As ratified in [ADR-0005](decisions/ADR-0005-canonical-event-schema-standards.md):

- Required fields: `event_id` (UUIDv4), `timestamp` (UTC ISO-8601), `ingest_timestamp` (UTC ISO-8601), `source_type`, `source_name`, `event_type`, `severity`, `raw_ref`.
- Entity fields: `host_id`, `hostname`, `user_id`, `username`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `process_name`, `process_id`, `parent_process`, `command_line`, `hash_sha256`, `domain`, `url`.
- Extensible metadata: `entities` (JSON dict).
