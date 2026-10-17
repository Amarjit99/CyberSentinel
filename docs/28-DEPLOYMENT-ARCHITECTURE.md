# 28 — Deployment Architecture

## Profiles
- **Local development:** Docker Compose, synthetic data, mock connectors, local credentials via ignored environment file, response adapters disabled.
- **Research evaluation:** isolated network, pinned images, reproducible datasets, controlled egress, metrics capture, no production credentials.
- **Controlled pilot:** approved sources, managed secrets, TLS, backup/restore, access review, on-call ownership, change control, explicit response approvals.
- **Production:** formal threat model, security/privacy approval, high availability as justified, tested disaster recovery, vulnerability management, monitoring, and documented operational support.

## Network zones
Separate public ingress, application services, data stores, model-provider egress, and response-capable infrastructure. Databases and queues should not be directly internet-accessible. Restrict egress to approved providers and integrations.

## Configuration and secrets
Use `.env.example` with placeholders only. Keep `.env` out of version control. Production secrets belong in a secret manager or platform-native secret mechanism. Separate dev/test/staging/production credentials and rotate them.

## Containers
Use pinned image versions, non-root users, minimal base images, health checks, read-only filesystem where feasible, resource limits, and vulnerability scanning. Do not mount the host Docker socket into agent-facing services.

## Availability and recovery
Define RPO/RTO per deployment profile. Back up PostgreSQL and required object data; document OpenSearch rebuild/recovery and Redis ephemeral semantics. Perform restore drills. Make migrations and reprocessing procedures explicit.

### Recovery baseline

- **Local development:** RPO 24 hours, RTO 4 hours. PostgreSQL backups are created with `python scripts/database_recovery.py backup <path>`; Redis is disposable and can be rebuilt.
- **Research evaluation:** RPO 24 hours, RTO 4 hours. Restore is exercised against an isolated database before a dataset is reused.
- **Controlled pilot:** RPO 1 hour, RTO 2 hours. PostgreSQL custom-format backups are retained outside the application host and restore access is tested at least monthly.
- **Production target:** RPO 15 minutes, RTO 1 hour, subject to the selected managed PostgreSQL service and object-store durability guarantees.

The recovery helper refuses destructive restores unless `--overwrite` is supplied. SQLite backups are verified by opening the backup and checking that it contains tables. PostgreSQL backups use `pg_dump --format=custom` and are restored with `pg_restore --clean --if-exists`; the restore drill must run against an isolated target, never the active production database.

## Observability
Expose liveness/readiness probes, structured logs, metrics, traces, connector health, queue lag, index health, model provider status, and response adapter status. Do not expose sensitive diagnostics publicly.

## Go-live gate
Verify secure configuration, least privilege, backup restoration, incident runbooks, access review, dependency/image scan, load test, privacy review, security test, and rollback plan. Live response remains disabled until the response-specific gate is approved.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
