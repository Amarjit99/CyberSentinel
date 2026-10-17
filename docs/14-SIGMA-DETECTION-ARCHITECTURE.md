# 14 — Sigma Detection Architecture

## Purpose
Use Sigma as a portable detection-rule authoring format where suitable, with explicit adapters and backend-specific validation. Sigma rules are not automatically portable without checking log-source mappings and backend capabilities.

## Rule lifecycle
Draft → schema validation → metadata review → fixture tests → false-positive review → backend translation/compatibility test → peer approval → versioned release → monitoring → tune/retire.

## Required metadata
Rule ID, title, description, author/owner, status, date, modified date, log source, detection logic, condition, severity/level, tags, ATT&CK references, references, false-positive notes, expected fields, test fixtures, version, and review status.

## Execution architecture
- Store canonical rule source in version control.
- Validate syntax and required metadata in CI.
- Test positive, negative, edge, missing-field, and noisy-event fixtures.
- Translate rules through a controlled backend adapter.
- Record exact rule version and backend/translation version in every detection.
- Keep source rule and translated query linked for auditability.

## Detection quality
Measure precision, recall, false-positive rate, detection latency, event coverage, runtime cost, and operational noise. Evaluate rules against held-out fixtures and avoid tuning on the same set used for final reporting.

## Safety and reliability
Rules must not trigger response actions directly. A detection creates evidence and workflow events; response policy is evaluated separately. Rule deployments require review and rollback. Malformed or incompatible rules fail closed and do not replace the last known-good version.

## Rule testing example categories
- Known-positive sequence.
- Similar benign sequence.
- Missing or null field.
- Case/encoding variations.
- Clock skew and out-of-order events.
- Duplicate/replayed event.
- High-volume stress case.
- ATT&CK mapping validation.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
