# 19 — UI/UX Specification

## Experience goals
A responsive analyst workspace that prioritizes triage, evidence, traceability, and safe action. Avoid decorative dashboards that hide uncertainty or imply unsupported AI certainty.

## Primary navigation
- Overview
- Events
- Detections
- Incidents
- Investigations
- Threat Intelligence
- Detection Rules
- Response Playbooks
- Reports
- Administration (permission-gated)

## Core screens
1. **Overview:** event/alert trends, open incidents by severity, connector health, queue lag, unresolved approvals, and system status. Every chart has time range, timezone, data source, and empty/error state.
2. **Event explorer:** filters for time, source, entity, category, severity, and event ID; raw/normalized toggle; parser/schema provenance.
3. **Detection detail:** rule title/version, match rationale, input event links, ATT&CK mapping, false-positive notes, and test status.
4. **Incident workspace:** summary, severity/confidence, timeline, entities, evidence, related detections, analyst notes, investigation runs, recommended next steps, and full audit history.
5. **Investigation run:** plan, tool calls, budgets, state, findings, evidence citations, missing evidence, errors, and cancellation control.
6. **Response proposal:** exact scope, expected effect, risks, prerequisites, rollback, dry-run output, approval status, and execution verification.
7. **Administration:** users/roles, connector status, rules, retention, model configuration references, and audit access.

## Interaction and safety
- Separate observed facts, AI-generated hypotheses, and analyst-confirmed conclusions visually and semantically.
- Never use color alone for severity/status.
- Destructive or disruptive actions require explicit confirmation showing exact target and impact.
- Approval controls must show action payload/scope and expiry; approval is not a generic “approve incident” button.
- Show provenance and confidence next to AI findings; provide “insufficient evidence” and “not applicable” states.
- Disable unavailable actions with a clear reason; do not present mock buttons as working functionality.

## Accessibility and responsive behavior
Keyboard-first operation, visible focus, semantic headings/labels, screen-reader status updates, sufficient contrast, reduced-motion support, and usable narrow-screen tables via stacked details or horizontal scroll.

## UX acceptance tests
Test loading, empty, error, permission-denied, stale-data, large-result, keyboard-only, narrow viewport, cancellation, concurrent update, and approval-expiry states. All visible controls must have implemented behavior or be explicitly marked as non-functional design placeholders during early mockups.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
