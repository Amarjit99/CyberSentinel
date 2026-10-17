# 20 — Incident Lifecycle

## Lifecycle
`NEW → TRIAGE → INVESTIGATING → AWAITING_APPROVAL → CONTAINMENT → RECOVERY → CLOSED`, with `REOPENED` available from closed when new evidence arrives. Not every incident must traverse every state; transition policy defines allowed paths.

## Entry and transition rules
- `NEW`: created from a detection, connector alert, or analyst report; initial evidence references attached.
- `TRIAGE`: validate signal quality, scope, affected assets, and urgency.
- `INVESTIGATING`: collect and review evidence, enrich context, document hypotheses and gaps.
- `AWAITING_APPROVAL`: a response proposal exists and requires designated approver decision.
- `CONTAINMENT`: approved containment action is underway or verified; record exact scope and result.
- `RECOVERY`: remediation/recovery and monitoring tasks are tracked.
- `CLOSED`: disposition, evidence summary, lessons learned, and closure rationale required.
- `REOPENED`: preserve prior closure and append new reason/evidence; never erase history.

## Severity and confidence
Keep severity (potential impact/urgency) separate from confidence (strength of evidence). Define organization-specific severity criteria and response SLAs; do not hard-code universal impact assumptions.

## Required audit events
Creation, severity changes, owner assignment, state transitions, evidence additions, manual correlation/split/merge, AI-run start/stop, approval decision, action execution, verification, closure, and reopening.

## Deduplication and correlation
Use stable event/detection IDs, idempotency keys, entity/time/context similarity, and analyst review for ambiguous merges. Every automated grouping must explain its reasons. Preserve the ability to split false groupings without changing source evidence.

## Closure checklist
- Disposition selected with rationale.
- Key claims link to evidence.
- ATT&CK mapping reviewed or explicitly left unmapped.
- Response outcome and verification recorded where applicable.
- Outstanding risks and missing telemetry noted.
- Detection feedback captured for tuning.
- Required retention and notification actions completed.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
