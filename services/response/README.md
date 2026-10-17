# Response Service (`services/response`)

## Responsibility
Manages mitigation proposals, human approval tracking, and response action records.

## Security Invariants
- **`LIVE_RESPONSE_DISABLED=true`:** Strictly enforced in configuration and runtime.
- **Dual Authorization:** Tier 3 actions require two distinct human approvers (ADR-0006).
- **Idempotency:** Every approved action requires a unique idempotency key before queueing.
