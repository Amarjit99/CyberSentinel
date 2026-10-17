# ADR-0007: Implementation Phasing Hierarchy and Roadmap Harmonization

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Lead Architect, Technical Program Manager, QA Lead  
**Governing Conflict:** [CONFL-007](../audit/CONFLICT_REGISTER.md#confl-007-implementation-phase-numbering-and-milestone-structure-reconciliation)  

---

## 1. Context & Problem Statement

Three distinct project structures existed: 28 execution phases in `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`, 13 development phases / 7 releases in the master spec, and 11 build stages / 7 release gates in `docs/30-IMPLEMENTATION-ROADMAP.md`.

## 2. Decision

We establish an authoritative **3-Tier Planning Hierarchy**:

```text
TIER 1: 7 RELEASE MILESTONES (v0.1 -> v1.0)
  └── TIER 2: 11 CONDENSED BUILD STAGES & RELEASE GATES (Stage 0..10 / Gates G0..G6)
        └── TIER 3: 28 GRANULAR EXECUTION SPRINTS (Phase 0..27)
```

### Mapping Structure
- **Release 0.1 (Foundation & Deterministic Core):**
  - Stage 0 (Governance & Architecture) -> **Gate G0** -> Phase 0 (Current Baseline).
  - Stage 1 (Persistence & Contracts) -> **Gate G1** -> Phases 1, 2, 3.
  - Stage 2 (Ingestion & Normalization) -> **Gate G2** -> Phases 4, 5.
  - Stage 3 (Search & Deterministic Detection) -> **Gate G2** -> Phases 6, 7.
  - Stage 4 (Correlation & Incidents) -> **Gate G3** -> Phases 8, 9, 10, 11.
- **Release 0.2 (Context & Intelligence):**
  - Phases 12 (MITRE ATT&CK), 13 (Threat Intel), 14 (Deterministic Risk).
- **Release 0.3 (Specialized AI Agents):**
  - Stage 7 (Bounded AI Investigation) -> **Gate G4** -> Phases 15 (Triage Agent), 16 (Tool Registry), 17 (Investigation Agent).
- **Release 0.4 (Orchestration & Threat Hunting):**
  - Phases 18 (Multi-Agent RAG & Hunting), 19 (Detection Engineering).
- **Release 0.5 (Response & Governance):**
  - Stage 8 & 9 (Response & Approvals) -> **Gate G5** -> Phase 20 (Response & Approval Workflow).
- **Release 0.6 (AI Security & Hardening):**
  - Phase 21 (AI Security & Agent Identity Hardening).
- **Release 1.0 (Evaluation & Production Baseline):**
  - Stage 10 (Benchmarking & Pilot Readiness) -> **Gate G6** -> Phases 22 (Attack Lab), 23 (Benchmarks), 24 (UI), 25 (Reliability), 26 (Security Tests), 27 (Documentation & Release).

## 3. Consequences

### Positive
- Seamless alignment across granular sprint planning, architecture gates, and executive release milestones.
- Clear entrance and exit criteria for every phase.
