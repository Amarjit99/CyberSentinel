# 06 — Functional Requirements

## Event pipeline
1. Receive event with source identity, timestamp, schema version, and idempotency/deduplication key where available.
2. Authenticate the source and validate allowed connector configuration.
3. Persist raw event or privacy-approved immutable reference before destructive normalization.
4. Normalize to canonical event format; preserve original fields and transformation metadata.
5. Route invalid events to quarantine with error codes; do not silently discard.
6. Emit processing metrics and trace correlation IDs.

## Detection and correlation
- Rules are versioned, testable, reviewable, and have owner, severity, references, ATT&CK mapping, and false-positive guidance.
- Rule execution records input event IDs, rule version, match reason, and execution time.
- Correlation explains why two or more records are grouped, including entity/time-window/context criteria.
- Analysts can split or merge incidents; manual changes are audited and do not rewrite source events.

## Incident management
Required incident fields: stable ID, title, status, severity, confidence, first/last seen, affected entities, detection references, evidence references, assigned owner, timeline, tags, ATT&CK mappings, risk explanation, response proposals, and audit history.
Lifecycle states: `NEW`, `TRIAGE`, `INVESTIGATING`, `AWAITING_APPROVAL`, `CONTAINMENT`, `RECOVERY`, `CLOSED`, `REOPENED`. State transitions must be policy-validated and timestamped.

## Investigation and evidence
- Agent tasks have a declared purpose, input scope, allowed tools, maximum steps/time/cost, and stop conditions.
- Findings must include claim, supporting evidence IDs, source provenance, confidence, counter-evidence/limitations, and timestamp.
- Evidence is immutable by default; corrections create new versions or annotations.
- AI-generated hypotheses remain visibly marked as hypotheses until analyst confirmation.

## Response and approvals
- Generate recommendations with expected effect, scope, risk, prerequisites, rollback/compensation, and verification steps.
- Approval records identify approver, policy version, exact action payload/hash, scope, time, and decision.
- Re-check authorization and policy immediately before execution; expired or changed approvals are invalid.
- Support dry-run mode and simulated adapters before any live integration.

## Administration
Manage users/roles, connectors, detection rules, retention settings, approved intelligence sources, model-provider configuration via server-side secrets, and audit access. Never expose API secrets in browser-delivered configuration or logs.

## Search, reporting, and exports
Search must enforce access controls before returning results. Exports should include timestamps, source references, schema/version information, and redaction. Reports distinguish observed facts, model-generated interpretations, and analyst decisions.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
