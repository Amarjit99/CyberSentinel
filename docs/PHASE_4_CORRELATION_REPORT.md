# CyberSentinel AI — Phase 4 Implementation Report
## Stateful Correlation Engine, Incident Lifecycle & Security Case Management

**Task ID:** CSAI-P4-CORRELATION  
**Gate:** G4 — Correlation, Incident Creation & Case Management  
**Date:** 2026-10-16  
**Status:** COMPLETE  
**Security Invariant:** `LIVE_RESPONSE_DISABLED=true` (STRICTLY ENFORCED)

---

## 1. Executive Summary & Gate Decision

Phase 4 delivers an enterprise-grade, stateful correlation engine and incident case management layer for CyberSentinel AI. The engine correlates streaming Sigma detections and canonical events across configurable event-time sliding windows, extracts normalized entities, identifies multi-stage threat patterns (such as brute force authentication bursts, reconnaissance-to-execution sequences, and multi-high-severity host alerts), deduplicates and creates/updates security incidents in PostgreSQL, and enforces the authoritative 11-state incident lifecycle with optimistic concurrency and complete audit tracking.

### Gate G4 Status: COMPLETE
- **Stateful Correlation Engine:** Complete (YAML-defined correlation rules, threshold counts, ordered multi-stage sequence matching, and entity group-by keys).
- **Temporal Sliding Windows:** Complete (event-time ordering, 1-hour late-arrival cut-off, bounded 2,000-event per-window buffer, and cooldown period suppression).
- **Entity Extraction & Association:** Complete (`EntityExtractor` extracts host, user, IP, domain, process, and file hash entities from `CanonicalEvent`; associates them idempotently in `incident_entities`).
- **Authoritative Incident Lifecycle:** Complete (enforces the full 11-state transition matrix from ADR-0001: `NEW`, `TRIAGE`, `INVESTIGATING`, `CONFIRMED`, `BENIGN`, `AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `CLOSED`, `LESSONS_LEARNED`, `REOPENED`).
- **Optimistic Concurrency & Audit Trail:** Complete (version-checked incident updates preventing lost updates, transactional `AuditEvent` generation).
- **Incident Deduplication & Escalation:** Complete (deterministic SHA-256 incident hashing on `corr_rule_id:group_key`, updating active incidents, auto-escalating severity to highest detection severity).
- **Analyst Notes & Secret Redaction:** Complete (regex sanitization redacting API tokens, passwords, private keys, and authorization headers as `[REDACTED_SECRET]`).
- **Unified Chronological Timeline:** Complete (assembles creation, detection links, entity associations, evidence attachments, notes, and audit events into a single unified timeline).
- **Streaming Worker & Pipeline:** Complete (`StreamingCorrelationWorker` consuming from Redis Streams consumer group `cybersentinel_correlation_workers` with commit-before-ack delivery).
- **Incident Management REST APIs & RBAC:** Complete (`/api/v1/incidents`, `/api/v1/incidents/{id}`, `/api/v1/incidents/{id}/transition`, `/api/v1/incidents/{id}/notes`, `/api/v1/incidents/{id}/timeline`, `/api/v1/correlation/rules`, `/api/v1/correlation/rules/reload` with `secops_viewer`, `secops_analyst`, `secops_lead`, and `admin` roles).
- **Live Response Invariant:** Maintained (`LIVE_RESPONSE_DISABLED=true`; moving an incident to `CONTAINMENT` strictly updates workflow state and never triggers automated endpoint isolation, firewall blocking, or script execution).
- **Automated Verification:** 100% Passed (133/133 tests passed, zero ruff lint errors, zero mypy type issues).

---

## 2. Repository Baseline & Git State

- **Repository Path:** `d:/TEST/CyberSentinel`
- **Git State:** Standalone working directory without `.git` (preserving all user documentation packs, specifications, schemas, and prior phase reports).
- **Python Environment:** Python 3.13.1 virtual environment (`.venv`).
- **Architecture:** Modular monolith strictly preserving domain boundaries:
  - `services/correlation`: Correlation rule definitions, entity extraction, sliding window aggregation, engine, and streaming worker.
  - `services/incidents`: Lifecycle state machine, incident case manager, timeline generator, and note redaction.
  - `services/detection`: Phase 3 Sigma detection engine and persistence.
  - `services/ingestion`: Phase 2 canonical normalization and ingestion pipeline.
  - `services/persistence`: SQLAlchemy PostgreSQL models and session management.
  - `packages/auth`: JWT authentication, password hashing, and role permissions.
  - `packages/observability`: Prometheus metrics and structured logging.
- **Active Infrastructure:**
  - **Redis 127.0.0.1:6379:** Active, stream `cybersentinel_events`, consumer group `cybersentinel_correlation_workers`.
  - **PostgreSQL 127.0.0.1:5432:** Database `cybersentinel_db`, migration `0001_initial_schema`.

---

## 3. Existing Lifecycle and Schema Findings

Inspection of the PostgreSQL database and migration `0001_initial_schema` revealed that the database schema already had complete, fully-defined tables for incident case management:
- `incidents`: Contains `id`, `title`, `status`, `severity`, `confidence`, `first_seen`, `last_seen`, `owner_id`, `version`, `created_at`, `updated_at`. Contains SQL check constraint `chk_incident_status_valid` checking for the exact 11 states: `NEW`, `TRIAGE`, `INVESTIGATING`, `CONFIRMED`, `BENIGN`, `AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `CLOSED`, `LESSONS_LEARNED`, `REOPENED`.
- `incident_detections`: Association table mapping `incident_id` to `detection_id` with `link_reason`, `linked_by`, `linked_at`.
- `incident_entities`: Association table tracking `incident_id`, `entity_type`, `entity_key`, `relation`, `first_seen`, `last_seen`.
- `evidence`: Table tracking `id`, `incident_id`, `evidence_type`, `source_ref`, `checksum`, `provenance_json`, `classification`, `collected_at`, `created_by`.
- `incident_notes`: Table tracking `id`, `incident_id`, `author_id`, `body_redacted`, `created_at`, `updated_at`.
- `audit_events`: Table tracking `id`, `actor_type`, `actor_id`, `action`, `object_type`, `object_id`, `request_id`, `outcome`, `reason_code`, `occurred_at`, `metadata_redacted`.

**Conclusion:** Zero database migrations or schema alterations were needed. All models aligned with ADR-0001 and ADR-0003.

---

## 4. Files Created and Modified

### Created Files:
1. `services/correlation/__init__.py`: Package entrypoint exporting models, engine, window, extractor, and worker.
2. `services/correlation/models.py`: Pydantic models for `CorrelationRule`, `SequenceStep`, `CorrelationMatch`, and domain exceptions.
3. `services/correlation/entity_extractor.py`: `EntityExtractor` and `ExtractedEntity` extracting host, user, IP, domain, process, and file hash.
4. `services/correlation/window.py`: `SlidingEventWindow` implementing temporal aggregation, event-time sorting, threshold matching, and multi-stage sequence matching.
5. `services/correlation/engine.py`: Thread-safe `CorrelationEngine` managing rule registries and entity window states.
6. `services/correlation/worker.py`: `StreamingCorrelationWorker` consuming from Redis Streams with commit-before-ack delivery.
7. `rules/correlation/corr_brute_force_auth.yml`: Rule detecting 5+ failed auth attempts within 5 minutes for the same user.
8. `rules/correlation/corr_recon_to_execution.yml`: Multi-stage sequence rule detecting host reconnaissance followed by suspicious process execution within 15 minutes.
9. `rules/correlation/corr_multi_high_severity_host.yml`: Rule detecting multiple high/critical severity alerts on the same host within 10 minutes.
10. `tests/unit/test_correlation_rules.py`: 7 tests validating rule YAML loading, sequence validation, negative windows, and unsupported fields.
11. `tests/unit/test_sliding_window.py`: 7 tests validating window ordering, deduplication, late arrivals, capacity bounds, and cooldowns.
12. `tests/unit/test_entity_extractor.py`: 3 tests validating entity extraction and canonical mapping from `CanonicalEvent`.
13. `tests/unit/test_incident_lifecycle.py`: 6 tests validating the 11-state machine, invalid transitions, sensitive role requirements, and optimistic locking.
14. `tests/integration/test_incident_persistence.py`: 2 integration tests validating PostgreSQL incident creation, deduplication, and detection linking.
15. `tests/integration/test_incident_api.py`: 5 integration tests testing FastAPI incident endpoints, transitions, notes, and timeline.
16. `tests/integration/test_correlation_worker.py`: 1 integration test validating Redis Streams streaming correlation worker.
17. `tests/security/test_incident_security.py`: 6 security tests validating RBAC restrictions, secret redaction, and `LIVE_RESPONSE_DISABLED=true` enforcement.
18. `docs/PHASE_4_CORRELATION_REPORT.md`: This comprehensive implementation report.

### Modified Files:
1. `services/incidents/__init__.py`: Added `IncidentTransitionRequest` and updated `BaseIncidentManager` with full types.
2. `services/incidents/lifecycle.py`: Implemented full 11-state transition graph, optimistic version checking, `AuditEvent` logging, and role guards.
3. `services/incidents/manager.py`: Implemented `IncidentManager` with deterministic incident hashing, auto-escalation, secret redaction, and timeline assembly.
4. `packages/observability/metrics.py`: Added metrics for correlation evaluations, matches, incident creations, updates, suppressions, and transitions.
5. `apps/api/main.py`: Registered correlation engine in lifespan and implemented all incident and correlation REST API endpoints.
6. `tests/contract/test_api_contracts.py`: Updated contract test asserting `/api/v1/incidents` is available and future endpoints remain unadvertised.

---

## 5. Correlation Rule Capabilities and Limitations

### Capabilities:
- **YAML Format:** Standard declarative YAML schema loaded safely via `yaml.safe_load()`.
- **Validation:** Enforced via Pydantic v2. Rejects rules with negative windows, thresholds < 1, sequence steps < 2, or unsupported `group_by` fields.
- **Rule Types Supported:**
  - `threshold`: Triggers when matching detections meet or exceed a count within the time window.
  - `sequence`: Triggers when distinct detection rules match in strict chronological order within the time window on the same entity.
- **Security Scenarios Covered:**
  - Brute Force Authentication (threshold).
  - Reconnaissance followed by Execution (ordered multi-stage sequence).
  - Multi-High-Severity Alert Correlation (host aggregation).
- **Execution Safety:** Zero dynamic code execution (`eval`, `exec`, or shell invocations).

### Limitations:
- Maximum window duration capped at 86,400 seconds (24 hours) to prevent unbounded memory growth.
- Per-window event capacity capped at 2,000 entries.
- Sequence matching currently requires distinct stages; intra-stage loops are modeled as thresholds.

---

## 6. Window, Ordering, Deduplication, and State-Recovery Semantics

### Semantics:
- **Event-Time Primary:** Window evaluation is governed strictly by detection `last_seen` or event `timestamp` in UTC, ensuring historical replays evaluate identically to real-time events.
- **Late Arrivals:** Events older than 1 hour past the window's latest event are discarded to prevent state corruption.
- **Out-of-Order Handling:** Entries are inserted into the sliding window and sorted chronologically on every evaluation.
- **Deduplication:** Repeated arrivals of the same `detection_id` are ignored and not counted multiple times toward thresholds or sequences.
- **Cooldown Suppression:** Configurable rule cooldown prevents alert fatigue by suppressing duplicate matches for the same entity within the cooldown duration.
- **Memory Bounding:** Old entries falling outside `(newest_event - window_seconds)` are evicted automatically. Total entries per entity window are hard-capped at 2,000.

---

## 7. Incident Creation, Update, and Lifecycle Behavior

### Creation and Deduplication:
- **Deterministic ID Generation:** Incident IDs are computed deterministically as `inc-<sha256(rule_id:group_key)[:16]>`.
- **Active Incident Update:** If an incident with the computed ID already exists and is in an active state (`NEW`, `TRIAGE`, `INVESTIGATING`, `CONFIRMED`, `AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `REOPENED`), new detections and entities are linked directly to it rather than creating a duplicate ticket.
- **Reopened Handling:** If an incident was previously `CLOSED` or in `LESSONS_LEARNED`, recurring suspicious activity triggers the transition to `REOPENED` with audit attribution.
- **Severity Auto-Escalation:** An incident's severity automatically upgrades if a new associated detection has a higher severity (e.g. from `medium` to `high` or `critical`), never downgrading active incidents.

### Lifecycle State Machine (ADR-0001):
The full 11-state machine is strictly enforced:
- `NEW` → `TRIAGE`, `CLOSED`
- `TRIAGE` → `INVESTIGATING`, `BENIGN`, `CLOSED`
- `INVESTIGATING` → `CONFIRMED`, `BENIGN`, `AWAITING_APPROVAL`, `CONTAINMENT`, `CLOSED`
- `CONFIRMED` → `AWAITING_APPROVAL`, `CONTAINMENT`, `INVESTIGATING`, `CLOSED`
- `AWAITING_APPROVAL` → `CONTAINMENT`, `INVESTIGATING`, `CLOSED`
- `CONTAINMENT` → `ERADICATION`, `INVESTIGATING`, `CLOSED`
- `ERADICATION` → `RECOVERY`, `INVESTIGATING`, `CLOSED`
- `RECOVERY` → `CLOSED`, `INVESTIGATING`
- `BENIGN` → `CLOSED`, `REOPENED`
- `CLOSED` → `LESSONS_LEARNED`, `REOPENED`
- `LESSONS_LEARNED` → `CLOSED`, `REOPENED`
- `REOPENED` → `TRIAGE`, `INVESTIGATING`

### Role-Based Transition Permissions:
- Regular transitions (`NEW` → `TRIAGE`, `TRIAGE` → `INVESTIGATING`): Allowed for `secops_analyst`, `secops_lead`, and `admin`.
- Sensitive transitions (`AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `CLOSED`): Require `secops_lead` or `admin`. Unauthorized attempts raise HTTP 403 / `PermissionError`.
- Concurrency Control: Optimistic locking checks `expected_version == incident.version`. Mismatches raise HTTP 409 / `ValueError`.

---

## 8. Entity and Evidence Association Results

### Entity Extraction:
The `EntityExtractor` maps raw canonical events to strongly typed entities:
- **Host / Device:** From `device.hostname` or `device.asset_id`.
- **User / Identity:** From `actor.user.user_name` or `actor.user.email_addr`.
- **IP Address:** From `network.client.ip_str` and `network.server.ip_str` (distinguished as `client_ip` and `server_ip`).
- **Domain:** From `network.dns.query_name` or `network.http.host`.
- **Process:** From `process.executable.file_path`.
- **File Hash:** From `process.executable.sha256_hash` or `process.executable.md5_hash`.

### Persistence & Association:
- Detections are linked to incidents via `incident_detections` with deduplication (`PRIMARY KEY (incident_id, detection_id)`).
- Extracted entities are linked via `incident_entities` with `PRIMARY KEY (incident_id, entity_type, entity_key)`.
- Re-linking existing entities updates `last_seen` idempotently.
- Evidence records are referenced via `evidence` foreign key to `incidents.id`.

---

## 9. RBAC and Audit Verification

### RBAC Enforcement:
- `GET /api/v1/incidents`: Requires `secops_viewer`, `secops_analyst`, `secops_lead`, or `admin`.
- `POST /api/v1/incidents/{id}/notes`: Requires `secops_analyst`, `secops_lead`, or `admin`.
- `POST /api/v1/incidents/{id}/transition`: Validated per transition sensitivity. Sensitive states require `secops_lead` or `admin`.
- `POST /api/v1/correlation/rules/reload`: Requires `admin`.

### Audit Logging:
Every lifecycle state transition generates a persistent `AuditEvent` record containing:
- `actor_type`: `user`
- `actor_id`: Authenticated user ID.
- `action`: `incident.transition`
- `object_type`: `incident`
- `object_id`: Incident ID.
- `outcome`: `SUCCESS`
- `metadata_redacted`: Details including old status, new status, version, and reason.

### Data Sanitization:
Analyst notes submitted to `POST /api/v1/incidents/{id}/notes` are sanitized against regex patterns matching Bearer tokens, private keys, passwords, and API keys, replacing them with `[REDACTED_SECRET]` before storage in `body_redacted`.

---

## 10. Redis and PostgreSQL Integration Evidence

- **Redis Streaming Integration:**
  `StreamingCorrelationWorker` connects to Redis Streams on `127.0.0.1:6379`. Detections published to `cybersentinel_detections` or raw events from `cybersentinel_events` are consumed via group `cybersentinel_correlation_workers`.
  - **Commit-before-Ack:** The worker persists correlation matches, updates/creates incidents, attaches entities, and commits the PostgreSQL transaction before acknowledging the Redis message (`XACK`).
  - **Error Isolation:** Poison pills or malformed detection payloads are logged and captured in dead-letter metrics without crashing the stream consumer.
- **PostgreSQL Transaction Integration:**
  All incident updates, detection links, entity associations, and audit events execute within atomic SQLAlchemy sessions. On any failure, the session rolls back cleanly, leaving zero orphaned records.

---

## 11. Exact Test Commands, Counts, Warnings, Failures, and Blocked Checks

All verification checks were run directly in the environment:

### Unified Verification Suite:
```bash
python scripts/run_checks.py
```
**Results:**
1. **Ruff Linter:**
   - Command: `python -m ruff check .`
   - Exit Code: `0`
   - Violations: `0`
2. **Mypy Type Checker:**
   - Command: `python -m mypy schemas apps services packages`
   - Exit Code: `0`
   - Files Checked: `50`
   - Errors: `0`
3. **Pytest Test Suite:**
   - Command: `python -m pytest -v`
   - Exit Code: `0`
   - Total Tests: **133**
   - Passed: **133**
   - Failures: **0**
   - Warnings: **4** (Pydantic v2 `utcnow()` deprecation warnings in schemas and mock Redis transport deprecation, zero functional failures)
4. **Alembic Offline Migration SQL Check:**
   - Command: `python -m alembic -c infrastructure/alembic.ini upgrade head --sql`
   - Exit Code: `0`

---

## 12. Migration Details

- **Database Migrations Added:** None.
- **Assessment:** Existing migration `0001_initial_schema` already defines all 17 authoritative tables, indices, and the full 11-state SQL check constraint on `incidents.status`. Zero database changes were necessary, preserving total backwards compatibility.

---

## 13. Known Limitations and Operational Risks

1. **State Persistence Across Restarts:** The correlation engine's sliding event windows currently maintain state in memory during active processing. In high-availability multi-instance setups, state should be backed by Redis sorted sets or persistent PostgreSQL window tables.
2. **Event-Time Clock Skew:** Window evaluations assume UTC timestamps. Significant server clock skew on log forwarders could cause events to be marked as late arrivals.
3. **Live Response Invariant:** While the incident lifecycle contains `CONTAINMENT`, all automated live response operations remain disabled (`LIVE_RESPONSE_DISABLED=true`). Analysts must carry out remediation through manual, approved out-of-band procedures.

---

## 14. Readiness Assessment for Phase 5 (Investigation & Triage Agents)

The CyberSentinel AI platform is fully prepared for Phase 5 (AI Agent Swarm & Autonomous Triage):
- **Stable Incident ID Contracts:** Phase 5 agents can reference deterministic incident IDs (`inc-<hash>`).
- **Unified Timeline Available:** `/api/v1/incidents/{id}/timeline` provides structured context for LLM agent reasoning.
- **Entity Graph Associations:** Agents can query host, user, IP, and process entities directly from `incident_entities`.
- **State Transition Guardrails:** Agents can propose or trigger lifecycle transitions (`TRIAGE` → `INVESTIGATING` → `AWAITING_APPROVAL`) while strictly adhering to RBAC and optimistic concurrency.
- **Tables Pre-Configured:** PostgreSQL tables `agent_runs` and `agent_findings` already exist in the database, ready for Phase 5 agent orchestration.

**Gate G4 Decision:** **APPROVED — COMPLETE**
