# 07 — Non-Functional Requirements

## Security
- Enforce authentication on every non-public API and authorization at object/action level.
- Use least-privilege service identities and separate read, investigate, approve, and execute capabilities.
- Store secrets in environment/secret-manager configuration; redact them from logs, traces, prompts, and error messages.
- Pin and scan dependencies; generate an SBOM for releases.
- Validate all external input, including event payloads, file uploads, search strings, and tool arguments.
- Treat event content, tickets, threat feeds, and retrieved documents as untrusted data.

## Reliability and recoverability
- Use idempotent ingestion and response requests where supported.
- Bound retries and queue growth; define dead-letter/quarantine behavior.
- Make partial failure visible and recoverable.
- Use expand/contract database migrations and backup/restore tests.
- AI provider outages must not stop deterministic ingestion, detection, or incident operations.

## Performance and scale
Do not specify untested throughput claims. Define a workload model covering event rate, event size, retention, concurrent analysts, search range, number of rules, and investigation fan-out. Benchmark p50/p95/p99 latency, throughput, queue lag, error rate, and cost. Establish target SLOs after measuring a baseline.

## Observability
Every request/job should carry a correlation ID. Collect structured logs, service metrics, traces, queue lag, connector health, detection counts, model latency/error/cost, agent tool-call counts, approval wait time, and response outcomes. Avoid logging sensitive payloads by default.

## Maintainability and compatibility
Use typed API/event contracts, migration-managed schemas, adapter interfaces, code ownership, formatting/linting, unit/integration/contract tests, and explicit deprecation policies.

## Usability and accessibility
Provide keyboard navigation, visible focus, semantic labels, responsive layouts, understandable severity and confidence, evidence links, actionable error messages, and confirmation for consequential actions.

## Privacy
Collect the minimum data needed, define purpose and retention, support deletion/retention enforcement where legally applicable, restrict exports, and document model-provider data handling. Do not send customer telemetry to external models unless explicitly configured and approved.

## Verification
Each NFR requires a measurable test method, environment, dataset, threshold or baseline, and result artifact. An unmeasured aspiration is not acceptance evidence.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
