# CyberSentinel AI User and Administrator Guide

## Scope

CyberSentinel is a research-grade SOC platform. Deterministic ingestion, normalization,
detection, investigation, evidence, and audit workflows are available for authorized lab
and staging use. Live response remains disabled by default and must not be enabled without a
separate production safety review.

## Analyst workflow

1. Check `/health` and `/ready` before investigating.
2. Ingest or replay authorized telemetry through `POST /api/v1/events`.
3. Search events using bounded time windows, source, host, IP, and pagination filters.
4. Review detections and related incidents.
5. Add evidence and analyst notes; treat raw telemetry and intelligence as untrusted data.
6. Start a bounded investigation when additional read-only context is needed.
7. Review risk, ATT&CK, and threat-intelligence provenance separately.
8. Create a response proposal only when the evidence supports a concrete action.
9. Keep proposals in dry-run mode and obtain human approval before any consequential action.

## Administrator responsibilities

- Keep `LIVE_RESPONSE_DISABLED=true` and `DRY_RUN_DEFAULT=true`.
- Supply secrets through environment or deployment secret management only.
- Configure source authentication before accepting production telemetry.
- Review audit events, rate-limit behavior, queue health, and threat-intelligence freshness.
- Apply database migrations through the documented Alembic process.
- Verify backups with an isolated restore exercise.
- Review the security gate and release checklist before each deployment.
- Restrict administrative and approval roles using least privilege and separation of duties.

## Authentication and roles

Bearer-token authentication is authoritative. Development headers and mock credentials must
remain disabled outside explicitly configured development/test environments. Revoking a token
blocks it until expiration in the current process; multi-worker deployments require a shared
revocation store.

Administrative, approval, and response permissions are separate concerns. Possessing an
analyst role does not authorize response execution, rule activation, or administrative changes.

## Operational checks

```text
GET /health
GET /ready
python scripts/security_gate.py --mode dev
python scripts/run_release_gate.py --mode conditional
```

The conditional release gate is appropriate when Docker/Trivy is unavailable. It is not a
substitute for container scanning before production use.

## Incident safety

Do not infer that no attack occurred when a telemetry source is stale or unavailable. Preserve
evidence before changing incident state. Never retry a failed response action blindly; inspect
the action ledger and target state first.
