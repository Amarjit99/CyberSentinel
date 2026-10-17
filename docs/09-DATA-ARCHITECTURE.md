# 09 — Data Architecture

## Data domains
1. **Raw telemetry:** original payload or immutable object reference, source, received time, event time, checksum, access label, retention class.
2. **Canonical events:** normalized timestamp, event category/action/outcome, source product, host/user/process/network/cloud entities, raw reference, schema version, parser version.
3. **Detections:** rule ID/version, matched event IDs, reason, severity, ATT&CK mappings, execution metadata.
4. **Incidents:** lifecycle, severity, confidence, entities, detection links, timeline, analyst disposition.
5. **Evidence:** evidence ID/type, source reference, checksum where feasible, provenance, collection time, access classification, annotations/version.
6. **Intelligence:** indicator/object, source, confidence, validity interval, handling marking, retrieval time, expiry/review date.
7. **Agent runs:** task, model/provider/version, prompt/template version, allowed tools, steps, outputs, token/cost metadata, evidence citations, failure/stop reason.
8. **Approvals/actions:** policy version, action hash, approver, decision, execution result, verification, rollback/compensation record.
9. **Audit/observability:** actor, action, object, timestamp, request/correlation ID, outcome, reason; sensitive content minimized.

## Storage placement
- PostgreSQL: transactional state, access policy, incidents, approvals, workflows, rule metadata, and audit metadata.
- OpenSearch: high-volume normalized event indexing and search; do not treat it as the sole authoritative record for approvals.
- Object storage: optional large artifacts and raw payloads where required, with encryption and retention controls.
- Redis: ephemeral cache/coordination only; never the sole store for evidence or approval decisions.
- Vector retrieval: optional later and limited to approved knowledge; vector matches are context, not authority.

## Data lifecycle
Receive → authenticate → validate → persist raw → normalize → index → detect/correlate → retain evidence → investigate → close/disposition → expire/archive/delete according to policy. Each transformation records source and version. Reprocessing must be idempotent and traceable.

## Quality and governance
Define schema versioning, required fields, timestamp semantics (UTC storage with source timezone retained where needed), entity normalization rules, duplicate detection, late-arriving event policy, clock-skew handling, deletion propagation, access labels, and retention per data class.

## Integrity and lineage
Use checksums or immutable object references for critical artifacts where feasible. Store parser/rule/model/template versions and transformation timestamps. Never silently overwrite raw source evidence. Corrections should be additive and attributable.

## Capacity planning
Estimate daily ingest volume from events/sec × average bytes/event × 86,400, then add index/replica overhead and retention. Benchmark realistic distributions rather than relying on a single average. Establish lifecycle policies and storage alerts before enabling high-volume connectors.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
