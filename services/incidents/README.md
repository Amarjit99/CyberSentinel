# Incident Service (`services/incidents`)

## Responsibility
Orchestrates the 11-state incident lifecycle defined by **ADR-0001**:
`NEW` -> `TRIAGE` -> `INVESTIGATING` -> `CONFIRMED` / `BENIGN` -> `AWAITING_APPROVAL` -> `CONTAINMENT` -> `ERADICATION` -> `RECOVERY` -> `CLOSED` -> `LESSONS_LEARNED` (with optional `REOPENED`).

## Enforcement
Every transition is validated against state machine constraints and recorded in `audit_events`.
