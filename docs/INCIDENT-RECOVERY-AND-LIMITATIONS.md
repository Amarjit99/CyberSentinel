# Incident Recovery and Known Limitations

## Recovery sequence

1. Declare the incident and preserve the request ID, audit records, and current deployment
   configuration.
2. Stop or isolate unsafe workers without deleting evidence or database state.
3. Keep `LIVE_RESPONSE_DISABLED=true`.
4. Verify `/health` and `/ready`, database connectivity, queue/quarantine/DLQ metrics, and
   threat-intelligence freshness.
5. Restore only into an isolated environment first.
6. Validate migration compatibility, evidence relationships, audit integrity, and event
   counts before any controlled cutover.
7. Replay only authorized, deduplicated telemetry.
8. Reconcile incidents and response proposals; do not replay consequential actions.
9. Document residual gaps and obtain an explicit go/no-go decision.

## Backup and restore

Backups must be encrypted and access-controlled by the deployment platform. A backup is not
considered verified until an isolated restore drill confirms schema compatibility, evidence
relationships, audit records, and application startup. OpenSearch snapshots are explicit
operations and require a mounted repository; relational metadata remains authoritative.

## Known limitations

- Docker/Trivy and live TLS/container validation are deployment-specific and were not run on
  the development host.
- JWT revocation is process-local; multiple API workers need a shared durable revocation store.
- Risk-policy versions are persisted and rollbackable; deployment rollout coordination still
  requires operators to ensure all workers reload the active version.
- Alert assignment and lifecycle changes are persisted as recipient-scoped in-app
  notifications. External delivery channels are intentionally not configured until a
  notification provider and delivery policy are selected.
- Ingestion HMAC authentication currently uses a global configured secret rather than a
  per-connector secret registry.
- Threat-intelligence event matching is bounded to supported canonical event fields.
- Live response is disabled and response adapters remain dry-run/lab-only.
- Browser accessibility/E2E validation and independent production security review remain
  release prerequisites.
- The application is research-grade; passing automated tests is not production authorization.
