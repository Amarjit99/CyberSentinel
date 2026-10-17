# 24 — Testing Strategy

## Test pyramid
- Unit: normalizers, rule logic, correlation scoring, policy decisions, schemas, risk calculation.
- Contract: API/OpenAPI, event schema, connector adapter contracts, model output schemas.
- Integration: PostgreSQL migrations, OpenSearch indexing, Redis queues, evidence persistence, audit events.
- End-to-end: ingest fixture → normalize → detect → correlate → incident → investigate → propose response → approval simulation.
- Security: RBAC bypass, object-scope access, injection, SSRF, secret leakage, replay, privilege escalation.
- Resilience: provider outage, queue backlog, database failover, retry storms, partial adapter failure.
- Usability/accessibility: keyboard navigation, responsive layouts, error and empty states.
- Performance: representative ingest/search/incident workloads with reproducible configuration.

## Required test data
Synthetic, deterministic scenarios with ground-truth labels; benign lookalikes; missing fields; out-of-order timestamps; duplicate/replayed events; expired intelligence; conflicting evidence; prompt-injection payloads; and unauthorized-action attempts. Do not use real sensitive telemetry without approval and controls.

## Test gates
1. Static checks, formatting, lint, type checks.
2. Unit and schema tests.
3. Migration and contract tests.
4. Integration tests.
5. Security and adversarial tests.
6. End-to-end scenarios.
7. Performance and reliability checks for release profile.
8. Manual review of evidence quality and human approval UX.

## Reporting
Every run records commit/build ID, dependency lockfile, configuration, dataset/scenario version, environment, test command, pass/fail, skipped tests with reason, logs/artifacts, and known limitations.

## Release-blocking failures
Unauthorized data access; unauthorized response; secret leakage; evidence provenance loss; data corruption; unhandled high-severity security defect; broken migrations; false success status; or failure of core deterministic workflows under AI outage.

## Quality metrics
Track coverage but do not use line coverage alone as a quality proxy. Measure rule precision/recall, correlation quality, evidence completeness, citation correctness, latency, cost, availability, and analyst correction rate.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
