# CyberSentinel AI — Architecture Decision Log

**Audit Phase:** Phase 0 Baseline  
**Date of Record:** October 16, 2026  
**Status:** 7 Authoritative ADRs Accepted to Resolve Baseline Conflicts  

---

## Architecture Decision Records (ADRs)

| ADR ID | Title | Date | Status | Primary Conflict Addressed | Summary |
|---|---|:---:|:---:|---|---|
| [`ADR-0001`](ADR-0001-unified-incident-lifecycle.md) | **Unified Incident Lifecycle State Machine** | 2026-10-16 | `Accepted` | CONFL-001 | Codifies authoritative 11-state incident lifecycle combining forensic stages with approval gating |
| [`ADR-0002`](ADR-0002-standardized-agent-taxonomy.md) | **Standardized Multi-Agent Taxonomy & Bounded Tool Governance** | 2026-10-16 | `Accepted` | CONFL-002, CONFL-008 | Standardizes 8 core specialized agents and enforces absolute shell execution prohibition |
| [`ADR-0003`](ADR-0003-storage-tiering-and-database-entities.md) | **Storage Tiering and Database Entity Architecture** | 2026-10-16 | `Accepted` | CONFL-003 | Ratifies 17 PostgreSQL transactional tables, OpenSearch event indexing & S3 object storage |
| [`ADR-0004`](ADR-0004-rbac-roles-and-permissions.md) | **Role-Based Access Control (RBAC) System Taxonomy** | 2026-10-16 | `Accepted` | CONFL-004 | Establishes 8 system role enum values and maps human user personas to machine permissions |
| [`ADR-0005`](ADR-0005-canonical-event-schema-standards.md) | **Canonical Event Schema and Redaction Standards** | 2026-10-16 | `Accepted` | CONFL-005, CONFL-009 | Standardizes 23-field Pydantic schema and establishes two-stage pre-storage / pre-LLM redaction |
| [`ADR-0006`](ADR-0006-response-action-risk-tiering.md) | **Response Action Risk Tiering and Human Approval Policy** | 2026-10-16 | `Accepted` | CONFL-006 | Formalizes Tier 0 (read-only) to Tier 3 (dual-authorization) action hierarchy with dry-run default |
| [`ADR-0007`](ADR-0007-implementation-phase-reconciliation.md) | **Implementation Phasing Hierarchy and Roadmap Harmonization** | 2026-10-16 | `Accepted` | CONFL-007 | Harmonizes 7 Releases, 11 Condensed Build Stages (Gates G0-G6) and 28 Granular Execution Sprints |
