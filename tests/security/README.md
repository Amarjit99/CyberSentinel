# Security Tests (`tests/security`)

## Purpose
Automated verification of non-negotiable security invariants:
- `LIVE_RESPONSE_DISABLED=true` enforcement across all configs and code.
- Verification that no free-form shell execution tools exist.
- Verification that no unredacted credentials or keys appear in error responses or logs.
- RBAC authorization checks.
