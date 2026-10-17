# 08 — System Architecture

## Logical architecture
`Sources/Connectors → Ingestion API/Workers → Raw Event Store → Normalization & Validation → Event Search Index → Detection Engine → Correlation Service → Incident Service → Enrichment/Evidence → Bounded Agent Orchestrator → Risk/Response Recommendation → Approval Service → Response Adapters`

Cross-cutting services: identity/RBAC, audit, configuration, secrets, observability, retention, and feature flags.

## Initial technology baseline
- Web: React + TypeScript; accessible component system; ECharts or Recharts for visualizations.
- API: Python + FastAPI + Pydantic; OpenAPI-generated contract; Alembic migrations.
- Relational state: PostgreSQL for users, policies, incidents, approvals, workflows, and audit metadata.
- Search: OpenSearch for event search and analytics.
- Cache/coordination: Redis for short-lived coordination, rate limits, and bounded queues where appropriate.
- Deployment: Docker Compose for local development; Kubernetes only when operational needs justify it.
- Integrations: adapters for Sysmon/Windows events, Wazuh, Sigma, Suricata/Zeek, ATT&CK, and STIX/TAXII as phased scope permits.

## Service boundaries
- Ingestion owns connector auth, receipt, idempotency, raw references, and queue publication.
- Normalization owns schema mapping and quarantine.
- Detection owns rule execution and detection provenance.
- Correlation owns grouping explanations and incident candidate generation.
- Incident service owns lifecycle and analyst workflow.
- Evidence service owns immutable evidence references and provenance.
- Agent service owns planning, tool authorization, bounded execution, and model-provider adapters.
- Response service owns approval checks, dry-run, execution adapters, verification, and rollback metadata.

## Data flow and failure behavior
Persist before acknowledging when the connector contract requires durable receipt. Use outbox or equivalent transaction-safe publication when relational state and queues must remain consistent. Apply retry with jitter, idempotency keys, dead-letter queues, and replay controls. Never allow retries to bypass authorization or duplicate high-impact actions.

## Trust boundaries
Separate browser, public API edge, internal services, data stores, model provider, connectors, and response-capable infrastructure. Model providers are external trust boundaries even when hosted internally. All boundaries require authenticated identity, scoped authorization, validated data, and auditable access.

## Deployment profiles
1. Developer: Compose, synthetic fixtures, mock integrations, no live response.
2. Evaluation: isolated lab data, reproducible scenarios, pinned configuration, metrics collection.
3. Controlled pilot: approved connectors, documented SLOs, backup/restore, incident runbooks, change control, and human approval.
4. Production: separate security review, tenant isolation validation if relevant, DR exercises, on-call, vulnerability management, and formal change/release controls.

## Architecture decisions
Record significant choices in ADRs: context, options, decision, consequences, migration path, and review date. Avoid premature microservices where a modular service is easier to test; preserve clean interfaces for later extraction.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
