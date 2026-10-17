# CyberSentinel AI — Release 0.3 Explainable Incident Risk Engine Report
## Sprint 14 Implementation and Verification

**Task ID:** `CSAI-R0.3-EXPLAINABLE-RISK-ENGINE`  
**Date:** 2026-10-16  
**Roles:** Lead Security Architect, Risk & Decision Engineer, Backend Engineer, and Test Lead  
**Workspace:** `d:/TEST/CyberSentinel`  
**Architecture:** Python/FastAPI Modular Monolith  
**Mandatory Safety Invariant:** `LIVE_RESPONSE_DISABLED=true` (Strictly Enforced)

---

## 1. Executive Summary & Preflight Findings

This report documents the implementation and verification of **Sprint 14: Explainable Incident Risk Engine** (`CSAI-R0.3-EXPLAINABLE-RISK-ENGINE`), transitioning the risk subsystem from a placeholder abstract interface into a production-grade, deterministic, and explainable multi-factor scoring engine.

### 1.1 Preflight Assessment of Verified Dependencies

Before implementation, preflight inspection confirmed the exact status of required dependencies:
1. **Existing Risk Interfaces:** `services/risk/__init__.py` contained only `BaseRiskEngine` and `RiskEvaluationResult` (governed by ADR-0006 for response action risk tiering: Tier 0 to Tier 3). These classes were preserved and extended with the incident-level scoring engine.
2. **Incident & Correlation Data:** `Incident` models in `services/persistence/models.py` provided `severity`, `confidence`, `first_seen`, `last_seen`, `detections` (`IncidentDetection`), and `entities` (`IncidentEntity`). Forensic evidence items (`Evidence`) were attached via `IncidentManager.add_evidence`.
3. **MITRE ATT&CK Foundations (Release 0.2 / Sprint 12):** Verified active and functional. Pinned catalog v15.1 in `attack/` provided 14 tactics, 25 techniques, and verified rule mapping via `AttackMappingService.resolve_tag`.
4. **Threat Intelligence Subsystem (Release 0.2 / Sprint 13):** Verified active and functional. `ThreatIntelService` provided exact, normalized indicator enrichment across IPv4, IPv6, Domain, URL, and Hash indicators with explicit timestamps, freshness, expiry, and conflict retention.
5. **API & RBAC Standards:** Followed established patterns in `packages/auth` (`require_roles`) and `apps/api/main.py`.
6. **Blockers Identified & Resolved:** No blocking dependencies existed. All required detection, correlation, ATT&CK, threat intelligence, and persistence models were verified in working order.

---

## 2. Architecture & File Inventory

### 2.1 Files Created

| Path | Purpose |
|---|---|
| `services/risk/models.py` | Pydantic data schemas: `IncidentRiskBandEnum`, `RiskFactorContribution`, `RiskScoringPolicy`, `IncidentRiskAssessment`, `RiskExplanationResponse` |
| `services/risk/engine.py` | Core `DeterministicRiskEngine` implementing factor decomposition, normalized scoring, and audit event generation |
| `infrastructure/alembic/versions/0003_incident_risk_assessments.py` | Additive Alembic migration creating the `incident_risk_assessments` persistence table with foreign keys and indexes |
| `tests/unit/test_risk_engine.py` | Unit tests covering policies, risk bands, mathematical scoring reproducibility, missing data baselines, and factor scaling (8 tests) |
| `tests/integration/test_risk_api.py` | Integration tests covering risk assessment calculation, history, explanation, 404 handling, and RBAC enforcement (6 tests) |
| `tests/security/test_risk_security.py` | Security tests covering safety invariants, approval policy bypass defense, absence of proof, and agent tool queries (5 tests) |
| `docs/RELEASE_0_3_EXPLAINABLE_RISK_ENGINE_REPORT.md` | This formal release verification report |

### 2.2 Files Modified

| Path | Summary of Changes |
|---|---|
| `services/risk/__init__.py` | Exported `DeterministicRiskEngine`, `IncidentRiskAssessment`, `IncidentRiskBandEnum`, `RiskFactorContribution`, `RiskScoringPolicy`, and `RiskExplanationResponse` while preserving ADR-0006 action risk tiering |
| `services/persistence/models.py` | Added `IncidentRiskAssessmentModel` and established bidirectional relationship `Incident.risk_assessments` |
| `services/agents/tools.py` | Added `get_incident_risk_assessment` to `ReadOnlyInvestigationTools.ALLOWED_TOOLS` and implemented real database/engine query method |
| `apps/api/main.py` | Registered 4 new endpoints under `/api/v1/incidents/{incident_id}/risk-assessment*`, instantiated global `risk_engine`, and added model imports |

---

## 3. Deterministic Risk Scoring Formula & Factor Breakdown

### 3.1 Mathematical Scoring Formula

The overall incident risk score $S \in [0.0, 100.0]$ is computed deterministically as the weighted sum of 7 independent factors:

$$S = \min\left(100.0, \max\left(0.0, \sum_{i=1}^{7} w_i \cdot R_i\right)\right)$$

Where $R_i \in [0.0, 100.0]$ is the raw factor score and $w_i \ge 0$ is the configured weight, satisfying $\sum w_i = 1.0$.

### 3.2 Factor Definitions and Default Weights

| Factor Name ($i$) | Weight ($w_i$) | Description & Evidence Inputs | Scoring Rules & Normalization |
|---|---|---|---|
| **`detection_severity`** | `0.20` | Triggering detections linked to incident (`IncidentDetection` -> `Detection`) | `critical`=95, `high`=75, `medium`=50, `low`=25, `informational`=10. Blends peak severity (70%) with average severity (30%) and scales by incident confidence $C \in [0.2, 1.0]$. |
| **`evidence_strength`** | `0.15` | Forensic evidence items attached to incident (`Evidence`) | Count-based baseline: $\min(80, 30 + 15n)$. Verified 64-char SHA-256 checksums provide +20 integrity bonus. Zero evidence items yields neutral baseline 20.0. |
| **`attack_context`** | `0.20` | MITRE ATT&CK tactics and techniques mapped from triggering rules | Evaluates tactic criticality: `impact`=95, `exfiltration`=90, `command_and_control`=85, `lateral_movement`=80, `credential_access`=75, `privilege_escalation`=75, etc. Adds kill-chain progression bonus (up to +20) when $\ge 2$ distinct tactics are observed. |
| **`threat_intel_context`** | `0.15` | IP, domain, URL, and hash indicators extracted from `IncidentEntity` | Queries `ThreatIntelService`. Matched active indicators score by source reputation $\times$ confidence. Expired intelligence applies discount (50%). Absence of indicators applies neutral baseline (35.0). |
| **`incident_scope`** | `0.10` | Unique entities and blast radius (`IncidentEntity`) | Base score scales with entity count ($1 \to 35$, $2 \to 55$, $3\text{--}4 \to 75$, $\ge 5 \to 90$). High-value asset markers (`admin`, `root`, `dc`, `prod`, `database`) apply +20 critical blast radius modifier. |
| **`temporal_context`** | `0.10` | Duration between `first_seen` and `last_seen` and detection velocity | Automated burst attacks ($\ge 3$ detections in $< 5\text{m}$) score 85. Multi-day persistent dwell scores 75. Multi-hour sustained activity scores 60. Isolated single points score 40. |
| **`correlation_context`** | `0.10` | Corroborating distinct detection rules without double-counting | Multi-rule corroboration scores $50 + 15n$ ($2\text{ rules} \to 75$, $\ge 3\text{ rules} \to 90$). Single correlation rule scores 60. Standalone detection scores 35. |

### 3.3 Authoritative Risk Bands

Every valid numeric score $S$ maps deterministically to exactly one risk band:

| Risk Band | Range | Operational Interpretation |
|---|---|---|
| **`LOW`** | $0.0 \le S < 40.0$ | Routine or low-confidence anomaly; monitor and review in normal queue |
| **`MEDIUM`** | $40.0 \le S < 70.0$ | Corroborated suspicious activity; standard tier triage required |
| **`HIGH`** | $70.0 \le S < 85.0$ | High-severity or multi-tactic attack progression; expedited investigation |
| **`CRITICAL`** | $85.0 \le S \le 100.0$ | Severe threat (C2, Impact, ransomware, or critical asset compromise); immediate SOC escalation |

---

## 4. Missing-Data, Expiry, Conflict, and Uncertainty Handling

1. **Absence of Proof Invariant:**
   An indicator or entity not present in local threat intelligence feeds is **explicitly not treated as proof of benign activity**. In such cases, a neutral baseline ($35.0$) is applied and an uncertainty caveat is recorded: `"Indicators not found in local threat intelligence repository; absence does not confirm benign status"`.
2. **Expired Intelligence Discounting:**
   When an indicator's intelligence record has expired, the normalized reputation score is discounted by $50\%$ (`stale_intel_discount = 0.5`) and an uncertainty flag is attached.
3. **Source Conflicts:**
   If multiple threat feeds disagree on an indicator's classification or score, conflicting observations are flagged in the factor explanation rather than silently averaged or discarded.
4. **Unmapped ATT&CK Context:**
   Rules without verified ATT&CK mappings receive a neutral baseline score ($30.0$) and record: `"Triggering rules do not map to recognized MITRE ATT&CK techniques; neutral baseline applied"`.
5. **Zero Evidence Context:**
   Incidents without attached forensic evidence receive an evidence factor score of $20.0$, reflecting that claims lack verifiable forensic backing.

---

## 5. API Contracts & Authorization

All risk endpoints require valid JWT authentication and RBAC roles: `SOC_ANALYST`, `DETECTION_ENGINEER`, `THREAT_HUNTER`, `SOC_MANAGER`, `SECURITY_ENGINEER`, `ADMIN`.

### 5.1 Endpoints Specification

| Method & Route | Description | Response Model |
|---|---|---|
| `POST /api/v1/incidents/{incident_id}/risk-assessment` | Calculates fresh risk assessment, persists record to DB, logs audit event | Full `IncidentRiskAssessment` payload |
| `GET /api/v1/incidents/{incident_id}/risk-assessment` | Retrieves latest assessment. Supports `auto_calculate=true` to evaluate if none exists | Full `IncidentRiskAssessment` payload |
| `GET /api/v1/incidents/{incident_id}/risk-assessment/history` | Retrieves paginated historical assessments for drift tracking | List of historical assessments with pagination metadata |
| `GET /api/v1/incidents/{incident_id}/risk-assessment/explanation` | Retrieves granular factor breakdown, mathematical weights, and formula description | `RiskExplanationResponse` |

---

## 6. Database Schema & Migration Details

A new additive migration file was created:  
`infrastructure/alembic/versions/0003_incident_risk_assessments.py`  
(Revision ID: `0003_incident_risk_assessments`, Parent: `0002_attack_and_threat_intel`).

### 6.1 Schema Additions (`incident_risk_assessments`)

```sql
CREATE TABLE incident_risk_assessments (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    overall_score FLOAT NOT NULL,
    risk_band VARCHAR(32) NOT NULL,
    policy_version VARCHAR(32) DEFAULT '1.0.0' NOT NULL,
    factors_json JSON NOT NULL,
    primary_drivers_json JSON NOT NULL,
    uncertainties_json JSON NOT NULL,
    limitations_json JSON NOT NULL,
    evidence_refs_json JSON NOT NULL,
    assessed_by VARCHAR(64) DEFAULT 'system:risk_engine' NOT NULL,
    assessed_at DATETIME NOT NULL
);

CREATE INDEX idx_inc_risk_incident_id ON incident_risk_assessments (incident_id);
CREATE INDEX idx_inc_risk_assessed_at ON incident_risk_assessments (assessed_at);
```

---

## 7. Verification Gates & Test Results

### 7.1 Automated Suite Execution

Verification command: `scripts/run_checks.py`

| Check Suite | Tool / Command | Result | Details |
|---|---|---|---|
| **Code Formatting & Linting** | `ruff check .` | **PASSED** | 0 linting errors across workspace |
| **Static Type Checking** | `mypy schemas apps services packages attack` | **PASSED** | 71 source files checked, 0 type errors |
| **Full Pytest Suite** | `pytest -v` | **PASSED** | **245 passed**, 8 warnings in 6.56s |
| **Alembic Offline SQL** | `alembic upgrade head --sql` | **PASSED** | Revisions `0001`, `0002`, `0003` DDL generated cleanly |

### 7.2 Granular Test Breakdown (+19 New Tests)

- **Total Tests:** 245
- **Prior Tests (Phases 0–6 & Release 0.2):** 226
- **New Explainable Risk Tests (Release 0.3 / Sprint 14):** 19
  - `tests/unit/test_risk_engine.py`: 8 passed
    - `test_scoring_policy_validation`
    - `test_risk_band_boundaries`
    - `test_deterministic_scoring_reproducibility`
    - `test_missing_evidence_and_partial_assessments`
    - `test_evidence_strength_scaling`
    - `test_high_value_asset_scope_elevation`
    - `test_correlation_context_multi_rule_corroboration`
    - `test_explain_assessment_response_structure`
  - `tests/integration/test_risk_api.py`: 6 passed
    - `test_calculate_risk_assessment_endpoint`
    - `test_get_current_risk_assessment_endpoint`
    - `test_get_risk_assessment_history_endpoint`
    - `test_get_risk_explanation_endpoint`
    - `test_risk_endpoints_404_for_unknown_incident`
    - `test_risk_endpoints_rbac_enforcement`
  - `tests/security/test_risk_security.py`: 5 passed
    - `test_safety_invariant_live_response_disabled_during_risk_scoring`
    - `test_critical_risk_score_cannot_bypass_approval_policy`
    - `test_missing_intelligence_is_not_treated_as_benign`
    - `test_phase5_agent_tool_retrieves_real_risk_assessment`
    - `test_history_pagination_bounds_enforced`

---

## 8. Security & Safety Invariants

1. **Mandatory Safety Invariant:**  
   `LIVE_RESPONSE_DISABLED=true` remains strictly enforced. Computing an incident risk score never triggers or simulates containment actions.
2. **Approval Policy Bypass Prevention:**  
   Even an incident with a `CRITICAL` risk score ($98.5$) cannot bypass response proposal policies. Tier 2 and Tier 3 containment proposals strictly require explicit human approvals bound to the payload hash (`test_critical_risk_score_cannot_bypass_approval_policy`).
3. **No Automatic State Mutation:**  
   Evaluating risk does not alter incident lifecycle status (`IncidentStateEnum`). Status transitions remain strictly governed by `IncidentLifecycleManager`.
4. **Agent Integration Without Hallucination:**  
   Phase 5 Investigation Agents now query the real database-backed risk assessment via `ReadOnlyInvestigationTools.get_incident_risk_assessment` instead of hallucinating numerical risk values.

---

## 9. Known Limitations & Deferred Items

1. **Asset Inventory Integration (CMDB):**  
   High-value asset identification currently relies on naming conventions (`admin`, `root`, `dc`, `prod`, `database`). Direct synchronization with an enterprise CMDB/Active Directory is scheduled for Phase 7 / Enterprise Integrations.
2. **Dynamic Weight Learning:**  
   In accordance with task constraints, scoring weights are strictly static and deterministic per policy version. Machine learning-based weight optimization remains deferred.

---

## 10. Acceptance Decision

- **Task Status:** **COMPLETE**
- **Sprint 14 (Explainable Incident Risk Engine):** **ACCEPTED**
- **Readiness for Sprint 15 (AI Provider Abstraction & Triage Agent):** **READY**

The deterministic risk engine provides the transparent, evidence-grounded risk scores and factor contributions required by Sprint 15 triage agents to distinguish observed facts from hypotheses.
