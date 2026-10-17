# ADR-0006: Response Action Risk Tiering and Human Approval Policy

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Cybersecurity Architect, AI Safety Officer, Senior Software Architect  
**Governing Conflict:** [CONFL-006](../audit/CONFLICT_REGISTER.md#confl-006-response-action-risk-tiering-and-approval-classification-nomenclature)  

---

## 1. Context & Problem Statement

The master specification described a 3-tier risk policy (Low, Medium, High), while `docs/21-RESPONSE-PLAYBOOKS.md` utilized a 4-tier model (Tier 0 to Tier 3). Alignment is required to prevent accidental autonomous execution of consequential containment actions.

## 2. Decision

We establish an authoritative **4-Tier Unified Response Action Hierarchy**:

| Tier | Risk Classification | Description & Permitted Actions | Approval Requirement | Execution Mode |
|---|---|---|---|---|
| **Tier 0** | **Autonomous / Read-Only** | Enrichment, ticket creation, metadata tagging, report generation, IOC lookup | Autonomous (No human gate required) | Production & Lab |
| **Tier 1** | **Lab-Safe / Low Risk** | Reversible state changes executed strictly within isolated simulation environments | Pre-approved lab policy | Lab Only (Blocked in Prod) |
| **Tier 2** | **Disruptive Containment** | Host isolation, IP blocking, domain sinkholing, file quarantine, session revocation | **Single Human Analyst Approval** bound to payload hash | Production & Lab |
| **Tier 3** | **Consequential / High-Impact** | Account disablement, privileged credential reset, firewall rule modification, data deletion | **Dual-Human Authorization** (Analyst + SOC Manager) | Production & Lab |

### Safety Rules
- **Live Response Disabled:** All Tier 2 and Tier 3 actions operate in simulated/dry-run mode during Phase 0 and Phase 1.
- **Payload Hash Binding:** Approvals are cryptographically bound to the SHA-256 hash of the exact action payload. Any drift in payload parameters invalidates the approval.
- **Execution Time Expiry:** Approvals expire automatically after 15 minutes if not executed.

## 3. Consequences

### Positive
- Prevents approval fatigue for harmless enrichment while enforcing strict dual-authorization for high-impact containment.
- Protects production environments from autonomous AI hallucination or prompt injection attacks.
