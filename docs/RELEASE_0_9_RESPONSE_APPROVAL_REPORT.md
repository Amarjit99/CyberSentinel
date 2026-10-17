# RELEASE 0.9: RESPONSE APPROVAL & CONTROLLED EXECUTION (SPRINT 20) REPORT

**Task ID:** `CSAI-R0.9-RESPONSE-APPROVAL`  
**Scope:** Sprint 20 — Response Approval & Controlled Execution (Phase 5: AI Investigation)  
**Date:** 2026-10-17  
**Status:** COMPLETE  

---

## 1. Preflight Findings

1. **Response Architecture Baseline:**
   - Preflight inspection confirmed that database models (`ResponseProposal`, `Approval`, `ResponseAction`, and `AuditEvent`) were established in `services/persistence/models.py` with corresponding tables defined in Alembic migrations (`0001_initial_schema`).
   - The platform possessed an ADR-0006 risk tier policy engine (`packages/policy/__init__.py`), a response action catalogue (`services/response/catalogue.py`), and foundational proposal models (`services/response/models.py`).
   - However, prior to Sprint 20, execution dispatch was either dry-run or stubbed, lacking an isolated execution adapter, cryptographic payload tampering protection at dispatch, dual-approval concurrency locking, explicit idempotency suppression, and comprehensive lab target allowlisting.
2. **Safety & Policy Boundary Invariants:**
   - `LIVE_RESPONSE_DISABLED=true` is strictly enforced platform-wide. Real production containment adapters (EDR, live firewall mutation, active cloud API shutdown) are non-existent and strictly prohibited in this phase.
   - AI models, automated heuristics, and risk scores are strictly prohibited from approving response proposals. Every state-advancing approval decision requires explicit, authenticated human responder authorization.
   - Separation of duties is mandatory: the creator/author of a proposal is prohibited from approving their own proposal.
   - Tier 3 actions require dual approval by two distinct authorized human operators (`SOC_MANAGER` or `ADMIN`).
3. **Database & Schema Integrity:**
   - Existing schema models compile cleanly. No destructive migrations, table recreations, drops, or volume resets were required or performed.
   - Offline migration verification via `python -m alembic -c infrastructure/alembic.ini upgrade head --sql` completed successfully with zero schema conflicts.

---

## 2. Existing Response Architecture Reused

The implementation directly preserved and extended the existing modular response subsystem rather than replacing it:

- **`ResponseProposal`, `Approval`, `ResponseAction`, and `AuditEvent` (`services/persistence/models.py`):** Reused without schema changes or table drops. Added foreign key lookups and explicit ORM queries for lifecycle execution records.
- **`ResponseManager` (`services/response/manager.py`):** Extended existing orchestrator to implement deterministic payload drift verification, idempotency checking, bounded lab simulation dispatch, and transaction-safe approval.
- **`evaluate_action_policy` (`packages/policy/__init__.py`):** Reused authoritative ADR-0006 risk evaluation for determining required approvals (Tier 0: 0, Tier 1: 1, Tier 2: 1, Tier 3: 2) and authorized roles.
- **`RESPONSE_ACTION_CATALOGUE` (`services/response/catalogue.py`):** Reused all 10 predefined action templates (`isolate_host`, `block_ip`, `sinkhole_domain`, `quarantine_file`, `disable_user_account`, `revoke_user_session`, `reset_privileged_credentials`, `modify_firewall_rule`, `isolate_lab_container`, `route_to_honeypot`).
- **`compute_payload_hash` (`services/response/policy.py`):** Reused deterministic canonical JSON SHA-256 hashing for cryptographic approval binding.
- **FastAPI Core (`apps/api/main.py`):** Reused existing response router routes, extending them with execution aliases, history queries, and detailed action retrieval.

---

## 3. Proposal Lifecycle and Policy Enforcement

The response proposal lifecycle was hardened into an explicit state machine:

```
[Create Proposal Request]
          │
          ▼
   (Policy Engine Check)
   - Template validation
   - Target entity presence
   - Required parameters check
   - Evidence grounding (Tier 2/3)
   - Canonical payload SHA-256 computation
          │
          ├─────────────────────────┐
          │ (Deny)                  │ (Pass)
          ▼                         ▼
  [Proposal Rejected]       [State: PENDING]
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼ (Approver Decision)     ▼ (Expiry Check)          ▼ (Operator Revoke)
    [Submit Approval]         [State: EXPIRED]          [State: REVOKED]
    - Separation of duties     (Current UTC > expires_at) (Authenticated cancel)
    - Role entitlement check
    - Duplicate check
    - Quorum tracking
          │
          ├─────────────────────────┐
          │ (Decision = REJECTED)   │ (Decision = APPROVED & Quorum Reached)
          ▼                         ▼
   [State: REJECTED]        [State: APPROVED]
                                    │
                                    ▼
                         [Execute Action Dispatch]
                         - Idempotency key lookup
                         - State verification (must be APPROVED)
                         - Expiry revalidation
                         - Payload drift SHA-256 verification
                         - Target allowlist validation
                         - Safety switch enforcement
                                    │
             ┌──────────────────────┴──────────────────────┐
             ▼ (Production target OR live mode)            ▼ (Lab target & dry_run=True)
   [State: BLOCKED_SAFETY]                       [LabResponseAdapter Dispatch]
   (Live execution blocked by safety switch)               │
                                              ┌────────────┴────────────┐
                                              ▼                         ▼
                                     [State: SIMULATED]        [State: FAILED]
                                    (Deterministic simulation) (Execution error)
```

### Allowed Lifecycle Transitions

| Source State | Target State | Trigger / Condition |
| :--- | :--- | :--- |
| *None* | `PENDING` | Valid proposal created; policy requires 1 or 2 human approvals. |
| *None* | `APPROVED` | Valid Tier 0 proposal created (automated execution permitted, 0 approvals required). |
| `PENDING` | `APPROVED` | Sufficient authorized distinct human approvals received (`current_approvals == required_approvals`). |
| `PENDING` | `REJECTED` | Authorized approver submits explicit rejection decision. |
| `PENDING` | `EXPIRED` | System or evaluation notices `now > expires_at`. |
| `PENDING` | `REVOKED` | Authorized operator explicitly revokes active proposal. |
| `APPROVED` | `SIMULATED` | Dispatched to `LabResponseAdapter` with synthetic target allowlist passed. |
| `APPROVED` | `BLOCKED_SAFETY` | Live response requested (`dry_run=False` or `target_environment="production"`) while `LIVE_RESPONSE_DISABLED=true`. |
| `APPROVED` | `FAILED` | Dispatched action failed (e.g. invalid target or execution exception). |

---

## 4. Payload Binding and Approval Semantics

Approvals are deterministically and cryptographically bound to the exact action proposal:

1. **Canonical Payload Serialization:**
   - Payloads are normalized using UTF-8 JSON serialization with strictly sorted dictionary keys (`json.dumps(payload, sort_keys=True, separators=(',', ':'))`).
   - Order differences in dictionary keys produce identical SHA-256 hashes (`test_payload_hash_canonicalization_is_order_invariant`).
2. **Material Modification Invalidation:**
   - Any modification to payload parameters (e.g. changing IP address, duration, or isolation flags) generates a completely different SHA-256 hash.
   - At dispatch time, `ExecuteActionRequest.action_payload` is re-hashed. If the dispatched hash does not match `proposal.action_payload_hash`, dispatch is aborted immediately with `ActionExecutionBlockedError` (`PAYLOAD_DRIFT_DETECTED`).
3. **Approval Scope Invariants:**
   - Approvals record: `proposal_id`, `approver_id`, `decision`, `policy_version`, `action_payload_hash`, `reason`, and `decided_at`.
   - An approval cannot be reused across different proposals, incidents, targets, or modified payloads.

---

## 5. Dual-Approval Concurrency Behavior

For high-impact Tier 3 response actions (e.g. `disable_user_account`, `isolate_lab_container`), the platform enforces dual authorization:

1. **Two Distinct Human Operators:**
   - Quorum requires two separate human identities possessing `SOC_MANAGER` or `ADMIN` roles.
   - A single operator cannot approve twice, even across concurrent asynchronous requests (`test_concurrent_dual_approvals_require_two_distinct_identities`).
2. **Transactional Concurrency Protection:**
   - In PostgreSQL / SQLite, `ResponseProposal` is retrieved and locked (`with_for_update()`) to prevent race conditions during concurrent approval submissions.
   - Existing approvals are counted within the active transaction before accepting an additional approval.
   - Concurrency tests (`test_concurrent_approvals_by_two_distinct_identities_reach_quorum`) verified that concurrent approvals from distinct identities increment the approval count accurately and transition the proposal to `APPROVED` only when the second distinct approval commits.
3. **Separation of Duties:**
   - The creator of a proposal (`proposal.created_by`) is strictly forbidden from approving their own proposal (`test_self_approval_is_strictly_forbidden`).

---

## 6. Lab-Only Execution Adapter

The new `LabResponseAdapter` (`services/response/lab_adapter.py`) enforces strict isolation boundaries for safe response testing:

1. **Target Allowlist Enforcement (`LabTargetAllowlist`):**
   - **Lab Hosts:** Evaluated against regex patterns matching lab naming conventions (e.g. `.*-(lab|sandbox|test|synth|sim)$`, `WORKSTATION-.*-LAB`).
   - **Lab IP CIDRs:** Restricted exclusively to isolated lab subnets:
     - `192.168.100.0/24` (Lab Subnet A)
     - `10.99.0.0/16` (Synthetic Testing Subnet)
     - `172.16.99.0/24` (Isolated Security Lab)
     - `127.0.0.0/8` (Local Loopback)
     - `198.51.100.0/24`, `192.0.2.0/24`, `203.0.113.0/24` (RFC 5737 Benchmark / Test-Net)
   - **Lab Containers:** Evaluated against regex matching `.*-(lab|sandbox|synth|sim)$`.
   - **Lab Domains:** Restricted to `.internal`, `.local`, `.lab`, `.sandbox`, `.synth`, `.example`.
   - **Lab Users:** Restricted to synthetic accounts (e.g. `lab_user_.*`, `synth_.*`, `test_.*`).
   - **Sandbox File Paths:** Restricted to safe sandbox paths (e.g. `/tmp/sandbox/.*`, `/var/lab/.*`, `C:\\Sandbox\\.*`).
2. **Explicit Production Target Rejection:**
   - Explicitly rejects targets containing production indicators: `prod`, `corp`, `finance`, `dc01`, `dc02`, `payroll`, `root@`, `administrator@`.
   - Attempts to target production entities immediately raise `LabTargetNotPermittedError`.
3. **Deterministic Simulation & Zero Production Mutation:**
   - Generates structured `LabExecutionResult` documenting:
     - `status`: `SIMULATED_SUCCESS`
     - `simulated_actions`: Explicit sequence of mock containment steps that would have been executed.
     - `rollback_plan`: Concrete rollback steps to revert the action in a lab environment.
     - `duration_ms`: Bounded simulated execution time.
     - `safety_barrier`: Confirmation that no real network or endpoint mutations were dispatched.

---

## 7. Safety-Switch Verification

The master safety switch `LIVE_RESPONSE_DISABLED=true` is strictly enforced:

1. **Safety Gate Hierarchy:**
   - If `dry_run is False` or `target_environment == "production"`, `ResponseManager.execute_action` immediately aborts live dispatch before invoking any adapter.
   - The proposal execution is recorded as `BLOCKED_SAFETY` in `ResponseAction`, and an audit event with reason code `SAFETY_SWITCH_BLOCKED_LIVE_EXECUTION` is emitted.
2. **Tamper-Resistant Defaults:**
   - Missing or unconfigured environment variables default to safe mode (`live_response_disabled=True`).
   - Neither API parameters, request bodies, nor agent tool calls can override `LIVE_RESPONSE_DISABLED=true`.
   - Dual Tier 3 approval does not bypass the safety switch: even a fully approved Tier 3 proposal cannot execute live actions while the safety switch is active.

---

## 8. API, Persistence, and Migration Changes

### API Endpoints (`apps/api/main.py`)

- `POST /api/v1/incidents/{incident_id}/proposals`: Submits a new response action proposal.
- `GET /api/v1/proposals/{proposal_id}`: Retrieves proposal details and current approval status.
- `POST /api/v1/proposals/{proposal_id}/approve`: Submits human approval/rejection decision.
- `POST /api/v1/proposals/{proposal_id}/revoke`: Revokes a pending proposal.
- `POST /api/v1/response-actions/{proposal_id}/execute`: Primary execution dispatch endpoint.
- `POST /api/v1/proposals/{proposal_id}/execute`: Alias execution dispatch endpoint.
- `GET /api/v1/response-actions/{action_id}`: Retrieves detailed action execution output.
- `GET /api/v1/incidents/{incident_id}/response-history`: Bounded pagination of incident response actions.

### Persistence & Schema

- No destructive migrations or table structure changes.
- Models reused: `ResponseProposal`, `Approval`, `ResponseAction`, `AuditEvent`.
- Extended `ProposalStateEnum` and `ActionExecutionStateEnum` with `SUCCEEDED` and `FAILED` for explicit outcome differentiation.

---

## 9. Exact Test Commands and Results

### Sprint 20 Specific Test Suite

```bash
.venv\Scripts\python -m pytest tests/unit/test_lab_adapter.py tests/unit/test_response_approval_lifecycle.py tests/integration/test_response_approval_api.py tests/security/test_response_approval_security.py -v
```

**Result:**
```
============================== test session starts ==============================
collected 35 items

tests/unit/test_lab_adapter.py::test_allowlist_permits_valid_lab_hosts PASSED [  2%]
tests/unit/test_lab_adapter.py::test_allowlist_permits_valid_lab_ips PASSED [  5%]
tests/unit/test_lab_adapter.py::test_allowlist_permits_valid_lab_users_and_domains PASSED [  8%]
tests/unit/test_lab_adapter.py::test_allowlist_rejects_production_targets PASSED [ 11%]
tests/unit/test_lab_adapter.py::test_simulate_isolate_host PASSED        [ 14%]
tests/unit/test_lab_adapter.py::test_simulate_block_ip PASSED            [ 17%]
tests/unit/test_lab_adapter.py::test_simulate_sinkhole_domain PASSED     [ 20%]
tests/unit/test_lab_adapter.py::test_simulate_quarantine_file PASSED     [ 22%]
tests/unit/test_lab_adapter.py::test_simulate_disable_user_account PASSED [ 25%]
tests/unit/test_lab_adapter.py::test_simulate_revoke_user_session PASSED [ 28%]
tests/unit/test_lab_adapter.py::test_simulate_reset_privileged_credentials PASSED [ 31%]
tests/unit/test_lab_adapter.py::test_simulate_modify_firewall_rule PASSED [ 34%]
tests/unit/test_lab_adapter.py::test_simulate_isolate_lab_container PASSED [ 37%]
tests/unit/test_lab_adapter.py::test_simulate_route_to_honeypot PASSED   [ 40%]
tests/unit/test_lab_adapter.py::test_simulate_tier_0_read_only_action PASSED [ 42%]
tests/unit/test_lab_adapter.py::test_reject_production_target_raises_error PASSED [ 45%]
tests/unit/test_lab_adapter.py::test_reject_unknown_action_type PASSED   [ 48%]
tests/unit/test_response_approval_lifecycle.py::test_payload_hash_canonicalization_is_order_invariant PASSED [ 51%]
tests/unit/test_response_approval_lifecycle.py::test_payload_hash_changes_on_material_modification PASSED [ 54%]
tests/unit/test_response_approval_lifecycle.py::test_lifecycle_pending_to_approved_to_simulated PASSED [ 57%]
tests/unit/test_response_approval_lifecycle.py::test_lifecycle_pending_to_rejected PASSED [ 60%]
tests/unit/test_response_approval_lifecycle.py::test_lifecycle_pending_to_revoked PASSED [ 62%]
tests/unit/test_response_approval_lifecycle.py::test_self_approval_is_strictly_forbidden PASSED [ 65%]
tests/unit/test_response_approval_lifecycle.py::test_tier_3_requires_two_distinct_human_approvers PASSED [ 68%]
tests/unit/test_response_approval_lifecycle.py::test_expired_proposal_cannot_be_approved_or_executed PASSED [ 71%]
tests/unit/test_response_approval_lifecycle.py::test_payload_tampering_at_dispatch_is_blocked PASSED [ 74%]
tests/integration/test_response_approval_api.py::test_api_full_response_proposal_and_lab_execution_flow PASSED [ 77%]
tests/integration/test_response_approval_api.py::test_api_execute_proposal_alias_endpoint PASSED [ 80%]
tests/integration/test_response_approval_api.py::test_api_idempotency_suppresses_duplicate_execution PASSED [ 82%]
tests/integration/test_response_approval_api.py::test_api_production_target_rejected_in_lab_execution PASSED [ 85%]
tests/security/test_response_approval_security.py::test_concurrent_dual_approvals_require_two_distinct_identities PASSED [ 88%]
tests/security/test_response_approval_security.py::test_concurrent_approvals_by_two_distinct_identities_reach_quorum PASSED [ 91%]
tests/security/test_response_approval_security.py::test_payload_tampering_at_dispatch_time_is_detected_and_blocked PASSED [ 94%]
tests/security/test_response_approval_security.py::test_unauthorized_roles_cannot_approve_or_execute PASSED [ 97%]
tests/security/test_response_approval_security.py::test_secrets_redacted_in_proposal_audit_and_results PASSED [100%]

======================== 35 passed, 1 warning in 1.12s ========================
```

### Full Repository Regression Test Suite

```bash
.venv\Scripts\python -m pytest
```

**Result:**
```
====================== 395 passed, 11 warnings in 10.71s ======================
```

### Code Quality Verification

```bash
.venv\Scripts\ruff check services/ apps/ packages/
```
**Result:** `All checks passed!`

```bash
.venv\Scripts\mypy services/response packages/auth apps/api
```
**Result:** `Success: no issues found in 10 source files`

```bash
.venv\Scripts\python -m alembic -c infrastructure/alembic.ini upgrade head --sql
```
**Result:** Clean SQL migration script generation across all 4 migration revisions with zero errors.

---

## 10. Mocked vs. Lab vs. Real Infrastructure Verification

| Component / Layer | Verification Mechanism | Real Infrastructure Touched? |
| :--- | :--- | :--- |
| **Response Proposal Engine** | In-memory SQLite session with full ORM constraints | No |
| **Separation of Duties** | Unit & Security tests with distinct mocked principals | No |
| **Dual Approval Concurrency** | In-memory threaded execution with row locking | No |
| **Payload Hash Binding** | Cryptographic SHA-256 canonicalization unit tests | No |
| **Lab Execution Adapter** | Deterministic simulation against synthetic allowlists | No |
| **Production EDR / Firewall** | Blocked by safety switch `LIVE_RESPONSE_DISABLED=true` | Absolutely No (Zero network packets sent) |
| **Audit Event Persistence** | In-memory database persistence with redaction validation | No |

---

## 11. Known Limitations and Deferred Work

1. **Deferred Production Adapters (Sprint 21+):**
   - Real production containment adapters (CrowdStrike Falcon, Microsoft Defender for Endpoint, Palo Alto PAN-OS, AWS IAM containment) remain strictly deferred to subsequent phases after full live response safety review.
2. **Simulated State Persistence:**
   - The lab adapter provides deterministic simulation outputs without persisting synthetic state across process restarts. Synthetic state persistence for multi-step containment drill tracking is deferred to Phase 6.
3. **Idempotency Key Time-To-Live:**
   - Idempotency keys are enforced via database unique constraints on `ResponseAction.idempotency_key`. A dedicated Redis-backed sliding TTL for distributed idempotency keys is scheduled for Phase 6.

---

## 12. Acceptance Decision

**Final Sprint 20 Decision: COMPLETE**

- Human response approval is cryptographically and deterministically bound to the proposal and payload hash.
- Server-side authorization and separation of duties strictly prevent self-approval.
- Tier 3 dual-human approval requires two distinct authorized operators and is resilient against race conditions.
- The `LabResponseAdapter` operates exclusively against synthetic allowlisted targets and strictly rejects production targets.
- The `LIVE_RESPONSE_DISABLED=true` safety switch is unconditionally enforced across all code paths, dispatches, and retries.
- Zero live external containment commands or shell scripts are executed.
- All 395 repository tests, Ruff, Mypy, and Alembic checks pass with zero regressions.
