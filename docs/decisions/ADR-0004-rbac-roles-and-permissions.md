# ADR-0004: Role-Based Access Control (RBAC) System Taxonomy

**Status:** Accepted  
**Date:** 2026-10-16  
**Deciders:** Cybersecurity Architect, Senior Software Architect, QA Lead  
**Governing Conflict:** [CONFL-004](../audit/CONFLICT_REGISTER.md#confl-004-role-based-access-control-system-role-taxonomy-alignment)  

---

## 1. Context & Problem Statement

The master specification defined 8 formal uppercase roles (`SOC_ANALYST`, `THREAT_HUNTER`, `DETECTION_ENGINEER`, `SOC_MANAGER`, `SECURITY_ENGINEER`, `ADMIN`, `RESEARCHER`, `VIEWER`), whereas companion documents used informal personas (`SOC lead`, `Platform administrator`, `Researcher/evaluator`).

## 2. Decision

We establish an authoritative **8-Role System RBAC Enum** for token issuance, JWT claims, and endpoint authorization:

| System Role Enum | Description | Key Permissions | Target Persona |
|---|---|---|---|
| `SOC_ANALYST` | Frontline incident triage, investigation & response proposal | Read telemetry, update incidents, request approvals, add notes | SOC Analyst / Tier 1-2 |
| `THREAT_HUNTER` | Proactive hypothesis-driven search & anomaly hunting | Read-only access to all historical telemetry indices | Threat Hunter |
| `DETECTION_ENGINEER` | Detection authoring, rule testing, Sigma deployment | Author rules, deploy detections, run rule backtests | Detection Engineer |
| `SOC_MANAGER` | Incident escalation, workflow review, response approval | Authorize Tier 2/3 response actions, assign incidents, view metrics | SOC Lead / Manager |
| `SECURITY_ENGINEER` | Connector management, ingestion health, platform tuning | Configure connectors, manage storage policies, view logs | Security Engineer |
| `ADMIN` | Identity management, RBAC configuration, audit review | Manage users, assign roles, configure global policies | Platform Administrator |
| `RESEARCHER` | Benchmarking, experiment replay, lab scenario evaluation | Replay scenarios, run benchmark harness, export metrics | Academic / Evaluator |
| `VIEWER` | Read-only executive dashboard and compliance review | View aggregated dashboards and reports (no raw search) | Auditor / Executive |

## 3. Consequences

### Positive
- Explicit mapping between business personas and machine-enforceable permissions.
- Prevents authorization bypass and role confusion in API route decorators.
