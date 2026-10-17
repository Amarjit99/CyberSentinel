# ADR-0001: Unified Incident Lifecycle State Machine

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Senior Software Architect, Cybersecurity Architect, QA Lead  
**Governing Conflict:** [CONFL-001](../audit/CONFLICT_REGISTER.md#confl-001-incident-lifecycle-states-and-state-machine-transitions-contradiction)  

---

## 1. Context & Problem Statement

`00-MASTER-REQUIREMENTS-SPECIFICATION.md` §27 specified a 10-state incident lifecycle (`NEW -> TRIAGED -> INVESTIGATING -> CONFIRMED / BENIGN -> CONTAINMENT_PENDING -> CONTAINED -> ERADICATION -> RECOVERY -> CLOSED -> LESSONS_LEARNED`). However, companion documents `06-FUNCTIONAL-REQUIREMENTS.md` and `20-INCIDENT-LIFECYCLE.md` defined an 8-state operational lifecycle (`NEW, TRIAGE, INVESTIGATING, AWAITING_APPROVAL, CONTAINMENT, RECOVERY, CLOSED, REOPENED`).

This discrepancy creates database constraint mismatches, frontend state ambiguity, and broken playbook approval triggers.

## 2. Decision

We establish an authoritative, unified **11-State Incident Lifecycle State Machine** combining forensic rigor with operational human-in-the-loop approval workflows:

```text
       ┌───────────┐
       │    NEW    │
       └─────┬─────┘
             │ (Alert correlation / initial ingest)
             ▼
       ┌───────────┐
       │  TRIAGE   │ ◄───────────────────────────────────┐
       └─────┬─────┘                                     │
             │ (Analyst or Triage Agent assignment)      │
             ▼                                           │
       ┌───────────────┐                                 │
       │ INVESTIGATING │                                 │
       └─────┬─────────┘                                 │
             │                                           │
     ┌───────┴──────────────────┐                        │
     ▼                          ▼                        │
┌───────────┐             ┌───────────┐                  │
│  BENIGN   │             │ CONFIRMED │                  │
│ (False +) │             └─────┬─────┘                  │
└─────┬─────┘                   │ (Playbook proposed)    │
      │                         ▼                        │
      │                ┌───────────────────┐             │
      │                │ AWAITING_APPROVAL │             │
      │                └────────┬──────────┘             │
      │                         │ (Approved)             │
      │                         ▼                        │
      │                ┌───────────────────┐             │
      │                │    CONTAINMENT    │             │
      │                └────────┬──────────┘             │
      │                         │ (Threat neutralized)   │
      │                         ▼                        │
      │                ┌───────────────────┐             │
      │                │    ERADICATION    │             │
      │                └────────┬──────────┘             │
      │                         │ (Restoration complete) │
      │                         ▼                        │
      │                ┌───────────────────┐             │
      │                │     RECOVERY      │             │
      │                └────────┬──────────┘             │
      │                         │                        │
      └────────────┬────────────┘                        │
                   ▼                                     │
             ┌───────────┐                               │
             │  CLOSED   │                               │
             └─────┬─────┘                               │
                   │                                     │
          ┌────────┴────────┐                            │
          ▼                 ▼                            │
  ┌─────────────────┐ ┌──────────┐                       │
  │ LESSONS_LEARNED │ │ REOPENED ├───────────────────────┘
  └─────────────────┘ └──────────┘ (New telemetry observed)
```

### Authoritative State Enum
`NEW`, `TRIAGE`, `INVESTIGATING`, `CONFIRMED`, `BENIGN`, `AWAITING_APPROVAL`, `CONTAINMENT`, `ERADICATION`, `RECOVERY`, `CLOSED`, `LESSONS_LEARNED`, `REOPENED`.

### Transition Rules
1. Every state transition requires: `actor_id`, `actor_type` (`USER` or `AGENT`), `timestamp` (UTC), `previous_state`, `new_state`, and `reason`.
2. Transition to `AWAITING_APPROVAL` occurs automatically when a Tier 2 or Tier 3 response action is proposed.
3. Transition to `CONTAINMENT` strictly requires a cryptographically valid approval record (`approvals` table).
4. `CLOSED` incidents can transition to `LESSONS_LEARNED` (for post-mortem documentation) or `REOPENED` (if related anomalous telemetry recurs within the incident correlation window).

## 3. Consequences

### Positive
- Reconciles all companion documents with the master specification.
- Full compliance with NIST SP 800-61 Rev 2 incident handling phases and modern SOC approval gating.
- Single source of truth for PostgreSQL `CHECK` constraints and Pydantic enums.

### Negative / Trade-offs
- Requires UI and API state engines to handle 11 distinct states rather than a simplified 5-state pipeline.
