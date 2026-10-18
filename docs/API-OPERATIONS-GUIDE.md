# CyberSentinel AI API Operations Guide

## Base URL and authentication

The local API is normally available at `http://localhost:8000`. The API version prefix is
`/api/v1`. Use an `Authorization: Bearer <token>` header for protected routes. Do not place
tokens in query strings, logs, screenshots, or issue reports.

## Public probes

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness and service metadata |
| GET | `/ready` | Dependency/readiness status |
| GET | `/docs` | Local OpenAPI UI |
| GET | `/openapi.json` | Generated API contract |

Health responses must not be treated as proof that the database, queue, or search backend is
safe for production traffic; readiness and operational metrics must also be reviewed.

## Core endpoint groups

| Capability | Endpoints |
|---|---|
| Event ingestion/search | `POST /api/v1/events`, `GET /api/v1/events`, `GET /api/v1/events/{id}` |
| Threat intelligence | `/api/v1/threat-intel/*`, `GET /api/v1/events/{id}/threat-intel` |
| Incidents/evidence | `/api/v1/incidents/*`, `/api/v1/evidence/{id}` |
| Investigations | `POST /api/v1/incidents/{id}/investigations`, `GET /api/v1/investigations/{id}` |
| ATT&CK | `GET /api/v1/attack/catalog` |
| Risk policy administration | `GET /api/v1/risk/policy`, `GET /api/v1/risk/policy/history`, `PUT /api/v1/risk/policy`, `POST /api/v1/risk/policy/{version}/rollback` |
| Response governance | `/api/v1/response-proposals/*`, `/api/v1/approvals/*`, `/api/v1/response-actions/*` |
| Authentication | `POST /api/v1/auth/revoke` |

The generated OpenAPI document is the authoritative request and response schema. The
companion API specification describes intent and safety rules; it is not a replacement for
the generated contract.

Risk policy updates are restricted to security engineers and administrators. Each accepted
version is immutable, the active version is loaded from the database at startup, and
rollback activates an existing historical version rather than deleting or rewriting it.
Review policy history before changing production scoring, and verify all workers have loaded
the intended active version after deployment.

Threat-source administration is available through `PATCH /api/v1/threat-intel/sources/{source_id}`
for security engineers and administrators. It supports reliability, description, endpoint URL,
enabled state, and a bounded polling interval (5 minutes to 7 days). Endpoint URLs are metadata
only; this API does not fetch remote feeds or persist credentials. Source health reports enabled
state and freshness separately so a disabled source is not mistaken for a healthy feed.

## Request and error rules

- Send JSON with UTC ISO-8601 timestamps.
- Use bounded pagination and time windows.
- Preserve idempotency keys on retryable writes.
- Treat `4xx` responses as caller/actionable validation or authorization failures.
- Treat `5xx` responses as service failures; do not convert them into empty intelligence.
- Record the response `request_id` when escalating an error.
- Never return or persist raw secrets, provider credentials, model prompts, or unredacted
  sensitive payloads in support material.

## Response workflow

Creating a response proposal does not execute an action. Execution requires a valid approval
bound to the exact action payload and target, policy re-evaluation, idempotency protection,
and dry-run/lab safety checks. A stale, altered, duplicated, or target-drifted request must
fail visibly.

## Minimal smoke check

```powershell
Invoke-WebRequest http://localhost:8000/health
Invoke-WebRequest http://localhost:8000/ready
Invoke-WebRequest http://localhost:8000/openapi.json
```

Use the release gate and integration tests for authenticated behavior; a health probe alone
does not validate authorization or object-level isolation.

ATT&CK coverage responses include `coverage_basis=active_rule_mappings`. This measures
techniques that active detection rules can map to in the pinned catalog; it does not claim
that those techniques were observed in telemetry. Valid, deprecated, and unresolved mapping
counts are included to distinguish capability coverage from rule-authoring or catalog gaps.

Alert assignment and status changes create persistent in-app notifications for the assigned
analyst. Use `GET /api/v1/notifications` to retrieve notifications and
`PATCH /api/v1/notifications/{notification_id}/read` to acknowledge one. Notifications are
recipient-scoped; they do not expose another analyst's assignments.
