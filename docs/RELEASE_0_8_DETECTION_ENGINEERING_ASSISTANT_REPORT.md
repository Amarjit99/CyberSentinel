# RELEASE 0.8: DETECTION ENGINEERING ASSISTANT (SPRINT 19) REPORT

**Task ID:** `CSAI-R0.8-DETECTION-ENGINEERING-ASSISTANT`  
**Scope:** Sprint 19 — Detection Engineering Assistant  
**Date:** 2026-10-17  
**Status:** COMPLETE  

---

## 1. Preflight Findings

1. **Detection Architecture Baseline:**
   - Evaluated `services/detection/compiler.py`, `services/detection/engine.py`, `attack/registry.py`, `services/agents/registry.py`, and `services/agents/executor.py`.
   - The platform possessed an operational single-event Sigma AST compiler (`SigmaCompiler`) and streaming evaluation engine (`SigmaDetectionEngine`), along with MITRE ATT&CK catalog mapping.
   - However, prior to Sprint 19, rule authoring, validation, controlled testing, and rule review/activation workflows were manual or unmanaged. Rules were loaded statically from YAML directory files on disk at startup.
2. **Schema & Telemetry Constraints:**
   - Canonical telemetry mapping (`CANONICAL_FIELD_MAP`) translates Sigma process, network, and file fields into normalized `CanonicalEvent` models.
   - pySigma produces ASTs evaluating boolean logic, modifiers (`contains`, `startswith`, `endswith`, `re`), but does not natively evaluate streaming multi-event aggregations (`count() > 5`) within single-event AST evaluation.
3. **Safety & Policy Invariants:**
   - `LIVE_RESPONSE_DISABLED=true` remains strictly enforced across response and agent subsystems.
   - Automated silent rule deployment is strictly prohibited: AI-generated rules must remain in candidate states (`DRAFT`, `VALIDATION_FAILED`, `VALIDATED`) until authorized human peer review (`APPROVED`).
   - Tools must route centrally through `ToolExecutionService` enforcing RBAC and audit logging.

---

## 2. Existing Functionality Reused

- **`SigmaCompiler` & `CompiledSigmaRule` (`services/detection/compiler.py`):** Reused for in-memory parsing, AST generation, and Python function evaluation against normalized event payloads.
- **`SigmaDetectionEngine` (`services/detection/engine.py`):** Reused for managing active production rules, loading newly approved candidate rules into production, and executing live evaluation.
- **`attack_catalog` & `attack_mapping_service` (`attack/`):** Reused for MITRE ATT&CK technique lookups, tactic alignment, and validation of technique tags.
- **`ToolExecutionService` & `ToolRegistry` (`services/agents/`):** Reused for registering and executing detection engineering tools under RBAC and execution quotas.
- **`INJECTION_HEURISTICS` (`services/agents/investigation.py`):** Reused for neutralizing prompt injection attacks in user-provided detection objectives.
- **`AuditEvent` & Persistence Subsystem (`services/persistence/`):** Reused for immutable auditing of rule creation, review decisions, and activation actions.

---

## 3. Candidate Generation and Validation Architecture

The Detection Engineering Assistant architecture establishes a bounded, controlled pipeline for rule authoring:

```
[Detection Objective]
         │
         ▼ (Prompt Injection Defense)
[Assistant Synthesis] ───► [Candidate Rule YAML]
                                 │
         ┌───────────────────────┴───────────────────────┐
         ▼                                               ▼
[SigmaRuleValidator]                            [SafeRuleTester]
- YAML Syntax & Top-Level Fields                - Synthetic Positive Fixtures
- UUID & Duplicate Rule Check                   - Synthetic Negative Fixtures
- pySigma AST Compilation                       - Historical Telemetry Replay
- Canonical Field Mapping Check                 - In-Memory Evaluation Only
- ATT&CK Technique Validation                   - False-Positive Detection
- Overly Permissive Wildcard Check                      │
         │                                               │
         └───────────────────────┬───────────────────────┘
                                 ▼
                     [Validation & Test Report]
                                 │
                                 ▼
                   Status: VALIDATED / VALIDATION_FAILED
                                 │
                         (Human Peer Review)
                                 │
                                 ▼
                         Status: APPROVED
                                 │
                        (Explicit Activation)
                                 │
                                 ▼
                    Status: ACTIVE in Engine
```

### Key Components

- **`DetectionEngineeringAssistant` (`services/detection/assistant.py`):**
  Orchestrates bounded candidate generation, explanation, review lifecycle, and production engine activation.
- **`SigmaRuleValidator` (`services/detection/validation.py`):**
  Multi-layer static validator evaluating:
  1. YAML syntax and mapping structure.
  2. Mandatory top-level Sigma fields (`title`, `id`, `status`, `level`, `logsource`, `detection`).
  3. Valid UUIDv4 format and collision detection against active rules.
  4. Logsource category and product compatibility.
  5. Condition consistency (verifying referenced identifiers exist in selections, catching unsupported aggregation constructs).
  6. Canonical field mapping warnings for unmapped telemetry fields.
  7. Overly permissive wildcard warnings (e.g. solitary `*`).
  8. MITRE ATT&CK tag verification against the local enterprise catalog.
  9. pySigma AST compilation verification.

---

## 4. Supported Sigma Features and Limitations

| Feature Category | Supported in Sprint 19 | Engine Behavior & Handling |
| :--- | :--- | :--- |
| **Document Structure** | Yes | Validates standard Sigma mapping with `title`, `id`, `status`, `level`, `logsource`, `detection`. |
| **Modifiers** | Yes | Supports `contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `wide`, `utf16le`, `utf16be`. Flags uncommon modifiers with `UNSUPPORTED_MODIFIER`. |
| **Logic Conditions** | Yes | Boolean logic (`and`, `or`, `not`, parentheses), identifier selections, wildcard selections (`selection_*`, `1 of them`). |
| **Logsource Mapping** | Yes | Validates known categories (`process_creation`, `network_connection`, `dns_query`, `authentication`, `file_event`) and products (`windows`, `linux`, `network`). |
| **Field Mapping** | Yes | Checks fields against `CANONICAL_FIELD_MAP` and `CanonicalEvent`. Unmapped fields emit `UNMAPPED_FIELD_NAME` warning. |
| **Wildcard Matching** | Yes | Glob wildcards (`*`, `?`) supported in strings. Solitary `*` emits `OVERLY_PERMISSIVE_WILDCARD` warning. |
| **Multi-Event Aggregation** | **No (Bounded)** | Aggregations (`count()`, `min()`, `max()`) emit explicit `UNSUPPORTED_AGGREGATION` diagnostic rather than failing silently. |
| **Cross-Event Correlation** | **No (Bounded)** | Correlation rules are managed by `CorrelationEngine` (temporal sliding window), not single-event Sigma rules. |

---

## 5. ATT&CK Mapping Behavior

- **Tag Parsing:** Extracts techniques from `tags` with `attack.tXXXX` or `attack.tXXXX.YYY` notation.
- **Catalog Grounding:** Validates extracted technique IDs against `attack_catalog`.
  - Matched techniques populate `detected_attack_ids` with provenance.
  - Unmapped or unrecognized techniques emit `ATTACK_TECHNIQUE_NOT_IN_CATALOG` warnings with suggested remediation.
- **Explainability:** Mappings are explained in analyst-friendly terms detailing tactic, technique name, and detection relevance without asserting that the presence of a rule implies observed malicious execution.

---

## 6. Controlled Testing Methodology

- **`SafeRuleTester` (`services/detection/testing.py`):**
  - Isolates rule execution entirely in-memory using `CompiledSigmaRule.evaluate()`.
  - Built-in synthetic fixture suite includes positive malicious patterns (PowerShell WebClient downloads, credential dumping, whoami reconnaissance, DNS beaconing, brute force auth) and negative benign administrative behaviors (provisioning scripts, benign system tasks, internal DNS, normal logins).
  - Optional bounded replay of historical events from `EventMetadata` with hard upper bounds (`max_events <= 100`).
  - Records distinct metrics: `total_events_evaluated`, `matched_event_ids`, `passed_positive_fixtures`, `passed_negative_fixtures`, `false_positives_detected`, and `coverage_gaps`.
  - Avoids fabricating precision/recall/F1 metrics from synthetic fixtures alone, appending explicit limitation disclosures.

---

## 7. Review and Activation Controls

### Lifecycle State Machine

```
   [Generation] ───► DRAFT / VALIDATION_FAILED / VALIDATED
                            │
                   (Submit for Review)
                            │
                            ▼
                      PENDING_REVIEW
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
            APPROVED                  REJECTED
               │
      (Explicit Activation)
               │
               ▼
             ACTIVE
               │
     (Explicit Deactivation)
               │
               ▼
           DEPRECATED
```

### Safety Invariants

1. **Human Review Gate:** `activate_candidate` strictly raises `ValueError` if candidate status is not `APPROVED`. No agent or automated pipeline can bypass human review.
2. **Role Authorization:** Only `DETECTION_ENGINEER`, `SECURITY_ENGINEER`, and `ADMIN` can generate, test, or review candidates. Only `DETECTION_ENGINEER` and `ADMIN` can activate production rules.
3. **Audit Trail:** Every state change (`generate`, `review`, `activate`, `deactivate`) produces an immutable `AuditEvent`.

---

## 8. APIs, Models, and Migrations

### Database Model (`services/persistence/models.py`)

Table: `detection_rule_candidates` (Table #26 in monolith)
- `id` (VARCHAR(64), Primary Key)
- `rule_id` (VARCHAR(64), Indexed UUID)
- `title` (VARCHAR(255))
- `version` (VARCHAR(32))
- `status` (VARCHAR(32), Indexed)
- `raw_yaml` (TEXT)
- `original_rule_id` (VARCHAR(64), Nullable)
- `author_id` (VARCHAR(64))
- `description` (TEXT)
- `severity` (VARCHAR(32))
- `logsource_json` (JSON)
- `attack_techniques_json` (JSON)
- `validation_diagnostics_json` (JSON)
- `test_results_json` (JSON)
- `review_notes` (TEXT)
- `reviewed_by` (VARCHAR(64))
- `reviewed_at` (TIMESTAMP WITH TIME ZONE)
- `activated_at` (TIMESTAMP WITH TIME ZONE)
- `activated_by` (VARCHAR(64))
- `audit_id` (VARCHAR(64))
- `created_at` (TIMESTAMP WITH TIME ZONE)
- `updated_at` (TIMESTAMP WITH TIME ZONE)

### REST Endpoints (`apps/api/main.py`)

- `POST /api/v1/detection/candidates` — Generate structured candidate rule.
- `GET /api/v1/detection/candidates` — List candidates with status filtering.
- `GET /api/v1/detection/candidates/{candidate_id}` — Get candidate details.
- `POST /api/v1/detection/candidates/{candidate_id}/validate` — Re-validate candidate.
- `POST /api/v1/detection/candidates/{candidate_id}/test` — Safely test candidate.
- `POST /api/v1/detection/candidates/{candidate_id}/review` — Human review (Approve/Reject).
- `POST /api/v1/detection/candidates/{candidate_id}/activate` — Load approved rule into live engine.
- `POST /api/v1/detection/candidates/{candidate_id}/deactivate` — Deactivate rule from engine.
- `POST /api/v1/detection/validate` — Ad-hoc validate Sigma YAML.
- `POST /api/v1/detection/explain` — Ad-hoc explain detection rule.
- `POST /api/v1/detection/test` — Ad-hoc test Sigma YAML against synthetic fixtures.

### Agent Tools (`services/agents/`)

- `generate_candidate_rule` (Tool #12)
- `validate_sigma_rule` (Tool #13)
- `test_candidate_rule` (Tool #14)
- `explain_detection_rule` (Tool #15)

---

## 9. Verification Commands, Test Counts, and Failures

### Test Execution Commands

```bash
# 1. Lint check
.venv\Scripts\ruff check services apps tests
# Output: All checks passed!

# 2. Type checking
.venv\Scripts\mypy services apps tests/unit/test_sigma_validation.py tests/unit/test_detection_assistant.py tests/integration/test_detection_assistant_api.py tests/security/test_detection_assistant_security.py
# Output: Success: no issues found in 76 source files

# 3. Sprint 19 test execution
.venv\Scripts\pytest tests/unit/test_sigma_validation.py tests/unit/test_detection_assistant.py tests/integration/test_detection_assistant_api.py tests/security/test_detection_assistant_security.py -v
# Output: 27 passed, 3 warnings in 1.66s

# 4. Full regression test suite execution
.venv\Scripts\pytest
# Output: 360 passed, 11 warnings in 11.03s
```

### Test Count Breakdown

| Suite | Tests | Status |
| :--- | :--- | :--- |
| `tests/unit/test_sigma_validation.py` | 9 | PASSED |
| `tests/unit/test_detection_assistant.py` | 6 | PASSED |
| `tests/integration/test_detection_assistant_api.py` | 6 | PASSED |
| `tests/security/test_detection_assistant_security.py` | 6 | PASSED |
| Existing Regression Tests (Sprints 1–18) | 333 | PASSED |
| **Total Test Suite** | **360** | **ALL PASSED** |

---

## 10. Mocked versus Live Verification

- **Mocked / In-Memory Components:**
  - Synthetic positive and negative telemetry fixtures (`get_default_sample_fixtures()`).
  - Candidate rule evaluation executes via in-memory compiled AST (`CompiledSigmaRule.evaluate`).
  - Unit tests utilize in-memory SQLite database sessions.
- **Live / Operational Components:**
  - Production `SigmaDetectionEngine` dynamically loads and evaluates newly activated candidate rules.
  - MITRE ATT&CK catalog lookups run against active in-memory enterprise matrix catalog.
  - Central `ToolExecutionService` verifies RBAC, execution quotas, bounding, and audit recording.
  - FastAPI application routing, authentication middleware, and error envelope handling.

---

## 11. Known Limitations and Remaining Roadmap Gaps

1. **Multi-Event Aggregation Limitation:**
   - Single-event Sigma rules cannot perform temporal aggregations (`count() > N within M minutes`).
   - Sprint 19 validator explicitly detects and blocks aggregation constructs (`UNSUPPORTED_AGGREGATION`), directing engineers to write sliding-window correlation rules instead.
2. **Offline MITRE ATT&CK Catalog:**
   - Technique lookups are grounded in the local versioned ATT&CK catalog. Unknown sub-techniques emit warnings rather than silently accepting unvalidated tags.
3. **Synthetic Fixture Coverage:**
   - Synthetic fixtures validate logical syntax, regex correctness, and baseline exclusions. Real-world false-positive rates require continuous operational telemetry baseline observation.

---

## 12. Acceptance Decision

**Decision:** **COMPLETE**

All Sprint 19 acceptance criteria have been met:
- Bounded, authorized `DetectionEngineeringAssistant` implemented.
- Comprehensive multi-layer `SigmaRuleValidator` operational with diagnostic reporting.
- Controlled in-memory `SafeRuleTester` executing against positive and negative fixtures.
- Grounded MITRE ATT&CK mapping and plain-language rule explainability.
- Strict human review invariant enforced before production rule activation.
- Central agent tool integration via `ToolExecutionService` with RBAC and audit logging.
- 27 new unit, integration, and security tests passing; all 360 repository tests green.
- `LIVE_RESPONSE_DISABLED=true` preserved without compromise.
