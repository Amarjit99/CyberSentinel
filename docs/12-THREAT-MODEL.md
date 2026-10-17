# 12 — Threat Model

## Method
Use a lightweight STRIDE-style review for services and data flows, plus AI-agent-specific abuse cases. Revisit at each major architecture change and before any live response integration.

## Assets
- Raw telemetry and normalized events.
- Evidence artifacts, incident records, and analyst notes.
- Credentials, API tokens, model-provider keys, and service identities.
- Detection rules, playbooks, policy configuration, and approvals.
- Agent prompts, tool contracts, retrieval corpora, and run outputs.
- Audit logs, backups, and deployment configuration.

## Trust boundaries
1. Browser ↔ public API.
2. Connector/source ↔ ingestion edge.
3. Ingestion ↔ queue/storage.
4. Internal services ↔ PostgreSQL/OpenSearch/Redis/object storage.
5. Agent orchestrator ↔ model provider.
6. Agent ↔ tool gateway.
7. Approval service ↔ response adapter/target environment.
8. Admin plane ↔ production data plane.

## Principal threats and controls
- Spoofed connector/event → source authentication, schema validation, rate limits, source provenance.
- Tampered evidence → immutable raw references, checksums, access controls, audit trails.
- Cross-user/object access → object-level authorization tests and negative test cases.
- Prompt injection in logs/tickets/intelligence → treat as untrusted data, isolate instructions from evidence, tool allowlists, policy enforcement outside model.
- Tool argument abuse/SSRF → typed schemas, host/URL allowlists, network egress controls, DNS/IP validation, no generic fetch tool.
- Secret leakage → server-side secret storage, redaction, context minimization, canary-secret tests.
- Agent privilege escalation → per-agent capabilities, short-lived scoped credentials, no inherited admin context.
- Unauthorized response → explicit approval bound to exact action hash/scope, reauthorization before execution, dry-run.
- Replay/duplicate action → idempotency keys, action ledger, state checks.
- Queue/storage exhaustion → quotas, payload limits, backpressure, retention, rate limiting.
- Malicious dependency/build → lockfiles, SBOM, scanning, provenance, review.
- Insider misuse → separation of duties, audit alerts, controlled exports.
- Model outage or invalid output → deterministic fallback, schema validation, bounded retries.

## Risk scoring
Rate likelihood and impact using a documented scale (e.g. 1–5) and record rationale, existing controls, residual risk, owner, due date, and verification evidence. Do not use numerical risk scores without defining the scale.

## Release blockers
Any demonstrated unauthorized response action, cross-tenant data access, secret leakage, evidence tampering without detection, or agent tool permission bypass blocks release until fixed and regression-tested.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
