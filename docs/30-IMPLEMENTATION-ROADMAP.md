# 30 — Implementation Roadmap

## Governing roadmap
The complete phase-by-phase task list, dependencies, and acceptance criteria live in `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`. This document summarizes sequencing and release gates; it does not replace that plan.

## Build order
1. **Phase 0 — Governance and repository foundation:** scope, ADRs, threat model, coding standards, CI, environment templates.
2. **Phase 1 — Contracts and persistence:** canonical event schema, API contracts, PostgreSQL migrations, audit model.
3. **Phase 2 — Ingestion and normalization:** source adapters, raw preservation, validation, quarantine, replay.
4. **Phase 3 — Search and deterministic detection:** event search, rule registry, Sigma validation/adapter, detection provenance.
5. **Phase 4 — Correlation and incidents:** explainable grouping, lifecycle, analyst workspace, evidence timeline.
6. **Phase 5 — Identity, RBAC, audit hardening:** object-level authorization and negative tests.
7. **Phase 6 — Threat-intelligence enrichment:** source allowlists, provenance, freshness, conflict handling.
8. **Phase 7 — Bounded AI investigation:** read-only tools, structured output, budgets, grounding, fallback.
9. **Phase 8 — Risk and response proposals:** explainable risk and dry-run playbooks.
10. **Phase 9 — Approval-gated response adapters:** only after separate security and operational approval.
11. **Phase 10 — Benchmarking, reliability, deployment hardening:** held-out scenarios, performance, restore, pilot readiness.

This condensed order is subordinate to the numbered phases and dependencies in the master implementation plan.

## MVP definition
A usable MVP can ingest synthetic events, preserve raw references, normalize/validate, execute deterministic rules, create correlated incidents, display evidence timelines, enforce RBAC, record audit events, and pass reproducible end-to-end tests. AI and live response are not prerequisites for the first MVP.

## Release gates
- **G0:** requirements, threat model, architecture, and scope approved.
- **G1:** contracts and migrations stable.
- **G2:** ingestion/search/detection deterministic path passes.
- **G3:** incidents, evidence, RBAC, and audit pass.
- **G4:** AI passes grounding, injection, budget, and outage tests.
- **G5:** response dry-run and approval workflow pass.
- **G6:** controlled pilot security, privacy, recovery, and operational reviews pass.

## Definition of done
Code merged; review completed; tests pass; authorization and negative paths tested; logs/metrics exist; docs updated; migration/rollback understood; no secrets committed; limitations recorded; acceptance evidence attached.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
