# CyberSentinel AI release checklist

## Required before a release candidate

- [x] Version and changelog updated (`1.0.0`; see `CHANGELOG.md`).
- [ ] `pytest -q` passes.
- [ ] Ruff and Mypy pass.
- [ ] Frontend `npm ci && npm run build` passes.
- [ ] Alembic offline SQL generation passes.
- [ ] `python scripts/security_gate.py` passes.
- [ ] Supply-chain gate passes, including dependency audit and SBOM generation.
- [ ] Docker and Trivy container scan passes, or a documented risk acceptance exists.
- [ ] Compose resource limits are reviewed against the target host and workload.
- [ ] TLS profile is tested with deployment-managed certificates when HTTPS is required.
- [ ] Database backup and isolated restore drill completed.
- [ ] Migration upgrade and rollback procedure reviewed.
- [ ] Threat model and known limitations reviewed.
- [ ] Authentication, authorization, and response safety tests pass.
- [ ] Independent security review completed before production use.

## Release artifacts

- Application source and lockfiles
- Backend and frontend SBOMs
- Migration SQL or migration release notes
- Backup/restore evidence
- Test and security-gate output
- Known limitations and accepted risks
- Rollback procedure

The current application remains a research-grade deployment. `LIVE_RESPONSE_DISABLED=true`
is a release invariant for local, staging, and lab profiles.
