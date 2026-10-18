# Changelog

## [1.0.0] - 2026-10-17

This release packages the verified CyberSentinel AI research-grade platform baseline.

### Added

- Searchable event investigation APIs with bounded filters and pagination.
- Incident evidence collection, retrieval, completeness, export, merge, and split workflows.
- ATT&CK catalog integrity validation for the pinned v15.1 dataset.
- Threat-intelligence freshness, IOC matching, handling metadata, TAXII transport, and reliability-aware lookup.
- JWT revocation, authentication-specific rate limiting, and optional HMAC-authenticated telemetry ingestion.
- Compose resource limits and an opt-in TLS profile with offline security-gate validation.
- Offline secret, SAST, dependency, SBOM, and TLS release-gate checks.

### Verification

- 598 backend tests pass.
- The alert lifecycle API and analyst alert workflow are available in the 1.0.0 baseline.
- Ruff and Mypy pass.
- Frontend tests and production build pass.
- Alembic offline migration generation passes.
- Docker/Trivy scanning and live TLS/container validation remain deployment-specific and were not run on this host.

### Safety and limitations

- `LIVE_RESPONSE_DISABLED=true` remains required.
- Response actions remain dry-run/lab-only.
- JWT revocation is process-local; shared multi-worker revocation requires a deployment-backed store.
- This is a research-grade release, not a production authorization.
