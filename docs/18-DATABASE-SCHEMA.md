# 18 — Database Schema

## Storage split
PostgreSQL is authoritative for transactional application state. OpenSearch supports event search and analytics. Redis is ephemeral. Large artifacts may use encrypted object storage. Do not store approval state only in a cache or search index.

## Core relational entities
- `users(id, external_subject, display_name, status, created_at, updated_at)`
- `roles(id, name, description)` and `user_roles(user_id, role_id, granted_by, granted_at)`
- `connectors(id, name, type, status, config_ref, created_at, updated_at)` — secrets referenced, never stored as plaintext config.
- `events(id, source_id, event_time, received_at, schema_version, raw_ref, checksum, classification, created_at)` — metadata/reference; high-volume body may be indexed externally.
- `detections(id, rule_id, rule_version, severity, first_seen, last_seen, status, created_at)`
- `detection_events(detection_id, event_id, relation_type)`
- `incidents(id, title, status, severity, confidence, first_seen, last_seen, owner_id, version, created_at, updated_at)`
- `incident_detections(incident_id, detection_id, link_reason, linked_by, linked_at)`
- `incident_entities(incident_id, entity_type, entity_key, relation, first_seen, last_seen)`
- `evidence(id, incident_id, evidence_type, source_ref, checksum, provenance_json, classification, collected_at, created_by)`
- `incident_notes(id, incident_id, author_id, body_redacted, created_at, updated_at)`
- `agent_runs(id, incident_id, task_type, state, model_ref, template_version, budget_json, started_at, finished_at, failure_code)`
- `agent_findings(id, run_id, finding_type, claim, confidence, evidence_refs_json, limitations, created_at)`
- `response_proposals(id, incident_id, action_type, action_payload_hash, risk, state, created_by, created_at, expires_at)`
- `approvals(id, proposal_id, approver_id, decision, policy_version, action_payload_hash, reason, decided_at)`
- `response_actions(id, proposal_id, idempotency_key, state, result_redacted, started_at, finished_at, verified_at)`
- `audit_events(id, actor_type, actor_id, action, object_type, object_id, request_id, outcome, reason_code, occurred_at, metadata_redacted)`

## Integrity and constraints
Use foreign keys, unique constraints, check constraints for enums/states, optimistic concurrency (`version`) for incident updates, and idempotency uniqueness for action requests. Store UTC timestamps. Apply indexes to common lookup paths (incident status/severity/time, event source/time, detection rule/time, audit actor/time) based on measured query patterns.

## Migrations
Use Alembic migrations; no manual production schema edits. Test fresh install and upgrade from the prior release, rollback/forward recovery, index creation impact, and backup restore. Use expand/contract migrations for incompatible changes.

## Data minimization
Avoid duplicating raw telemetry in multiple stores unnecessarily. Restrict note/evidence access, redact secrets and personal data, define retention by table/data class, and document deletion propagation to search/object stores and backups.

## ERD and implementation gate
Create an ERD from the actual migration-managed schema before release. The table list here is a logical starting point, not a substitute for executable migrations, data types, indexes, and foreign-key tests.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
