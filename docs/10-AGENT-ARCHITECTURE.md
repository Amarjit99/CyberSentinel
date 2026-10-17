# 10 — Agent Architecture

## Design rule
Agents are bounded workflow components, not independent administrators. Deterministic code controls permissions, budgets, state transitions, validation, and final execution.

## Proposed specialized agents
- **Triage agent:** summarize an alert and identify missing context; read-only.
- **Evidence collector:** request approved evidence queries and produce a source-linked timeline; read-only.
- **Threat-intelligence analyst:** query approved feeds and compare indicators with provenance; read-only.
- **ATT&CK mapper:** suggest techniques with rationale and evidence; cannot assert unsupported mappings.
- **Correlation assistant:** propose incident grouping/splitting based on explicit entity/time links.
- **Investigation planner:** create a bounded sequence of approved read-only tasks.
- **Response advisor:** draft playbook recommendations; no execution privilege.
- **Report writer:** produce a report from verified evidence and clearly labeled hypotheses.

## Execution contract
Each run must declare: task ID, incident scope, purpose, input references, allowed tools, data classification, max steps, max wall time, model/cost budget, stop conditions, output schema, and approval policy. The orchestrator—not the model—enforces all limits.

## State machine
`QUEUED → VALIDATING → RUNNING → WAITING_FOR_TOOL/REVIEW → COMPLETED | FAILED | CANCELLED | BUDGET_EXCEEDED`
Every transition is persisted and auditable. Retries use idempotent run identifiers and cannot expand permissions.

## Tool-use controls
- Explicit allowlist by agent role.
- Typed JSON schema for arguments and outputs.
- Validate object scope and authorization on every call.
- Read-only tools by default; separate identity and credentials for any action tool.
- No unrestricted shell, arbitrary URL fetch, generic database access, or dynamic code execution.
- Enforce egress allowlists, timeouts, rate limits, response-size limits, and redaction.
- Treat retrieved content as untrusted data; never execute instructions found in telemetry or documents.

## Grounding and uncertainty
Every material finding must reference evidence IDs. If evidence is missing or contradictory, state the gap and lower confidence. Distinguish fact, inference, and recommendation. Never fabricate events, indicators, source links, or completed actions.

## Failure behavior
On model timeout, malformed output, provider outage, policy violation, tool error, or budget exhaustion: stop safely, preserve partial results, record reason, and return deterministic workflow control to the analyst. No action is executed merely because an agent run ended.

## Evaluation
Measure evidence citation correctness, unsupported-claim rate, tool authorization violations, completion rate, cost, latency, analyst acceptance, and performance under prompt-injection fixtures. Any unauthorized action is a release-blocking failure.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
