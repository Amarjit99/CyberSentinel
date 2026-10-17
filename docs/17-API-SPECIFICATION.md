# 17 — API Specification

## API conventions
Base path: `/api/v1`. Use JSON request/response bodies, UTC ISO-8601 timestamps, stable opaque IDs, pagination for collections, explicit schema versions, and consistent error objects. Publish OpenAPI from the FastAPI application and contract-test it in CI.

## Authentication and authorization
All non-public endpoints require authenticated identity. Enforce role and object-level authorization server-side. Suggested roles: `analyst`, `detection_engineer`, `approver`, `security_admin`, and `response_executor`; a user may hold multiple roles only when explicitly granted. High-impact actions require approval independent of role membership.

## Initial endpoint groups
- `GET /health/live`, `GET /health/ready` — operational probes; do not expose secrets or detailed internals.
- `POST /api/v1/events` — receive authorized events; validate source identity, size, schema, and idempotency.
- `GET /api/v1/events` and `GET /api/v1/events/{event_id}` — authorized search/details.
- `GET /api/v1/detections`, `GET /api/v1/detections/{id}` — search detections and provenance.
- `GET /api/v1/incidents`, `POST /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `PATCH /api/v1/incidents/{id}` — incident workflow with transition validation.
- `GET /api/v1/incidents/{id}/evidence`, `POST /api/v1/incidents/{id}/notes` — evidence and analyst annotations.
- `POST /api/v1/incidents/{id}/investigations` — queue a bounded investigation; return run ID, not a fabricated synchronous result.
- `GET /api/v1/investigations/{run_id}` — state, budget, findings, and failures.
- `POST /api/v1/response-proposals` — create recommendation, not execute it.
- `POST /api/v1/approvals/{proposal_id}` — approve/reject exact action payload.
- `POST /api/v1/response-actions/{proposal_id}/execute` — separate permission, valid approval, policy re-check, dry-run/live mode.
- `GET /api/v1/audit` — tightly restricted, paginated audit search.

## Error envelope
Return a stable shape: `code`, `message`, `request_id`, and optional field-level `details`. Never return stack traces, credentials, internal prompts, or raw sensitive payloads. Use appropriate HTTP status codes and consistent validation errors.

## Safety requirements
Enforce request-size and rate limits, idempotency for retryable writes, pagination limits, query timeouts, output redaction, and explicit timeout behavior. Do not expose generic shell, SQL, URL-fetch, or model-provider proxy endpoints.

## Versioning and compatibility
Use additive changes where possible; deprecate with notice and a documented sunset. Contract tests must cover valid requests, malformed payloads, missing authentication, insufficient permissions, object-scope violations, replay, and concurrent state changes. Exact request/response schemas must be generated from code and included in the repository before implementation is called complete.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
