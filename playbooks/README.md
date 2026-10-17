# Response Playbooks (`playbooks`)

## Purpose
Declarative response playbooks and containment workflows executed under human-in-the-loop governance.

## Governance & Safety
- Governed by `docs/21-RESPONSE-PLAYBOOKS.md` and **ADR-0006**.
- Every step is tagged with its risk tier (`Tier 0` through `Tier 3`).
- In Phase 1 and 2, all automated response execution remains disabled (`LIVE_RESPONSE_DISABLED=true`); playbooks operate in proposal/dry-run mode only.
