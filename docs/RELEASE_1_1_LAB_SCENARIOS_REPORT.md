# CYBERSENTINEL AI — RELEASE 1.1 REPORT
## Lab Scenarios & Synthetic Attack Simulation

**Task ID:** `CSAI-R1.1-LAB-SCENARIOS`  
**Workstream:** Phase 5 — AI Investigation  
**Sprint:** 22 — Lab Scenarios & Synthetic Attack Simulation  
**Date:** October 17, 2026  
**Status:** **COMPLETE**  
**Safety Invariant:** `LIVE_RESPONSE_DISABLED=true` strictly enforced across all modules, tests, scenarios, and execution harnesses.

---

## 1. Preflight Findings

A comprehensive architectural and state inspection was conducted across the workspace prior to code modifications, auditing against:
- `docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md` (FR-01 through FR-12, NFR-01 through NFR-08)
- `docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md` (Sprint 22 scope & deliverables)
- `docs/30-IMPLEMENTATION-ROADMAP.md` (Release 1.1 Lab Scenarios)
- `docs/PHASE_ROADMAP_RECONCILIATION_REPORT.md`
- Governing Decisions: ADR-0001 (Microservices & Engine Structure), ADR-0002 (Dual LLM/Deterministic Architecture), ADR-0004 (PostgreSQL/SQLAlchemy Schema), ADR-0005 (Safe Sigma/Correlation Execution), ADR-0006 (Human-in-the-Loop Response Controls).

### Baseline Status:
1. **Existing Test Suite:** 418 tests (Sprint 21 baseline) passed cleanly across unit, integration, contract, and security suites.
2. **Existing Scenarios Directory:** `scenarios/` previously contained only a placeholder `README.md` without data-driven models, validation harnesses, runner engines, or scenario definitions.
3. **Detection Coverage Gaps Identified:**
   - No Sigma detection rule existed for suspicious reverse shell / outbound C2 network connections on non-standard ports (T1071).
   - No Sigma rule covered WMI-based remote process execution (`wmic.exe /node:... process call create`) for lateral movement (T1047).
   - No Sigma rule covered memory dump credential theft (`procdump.exe` / `mimikatz` targeting LSASS) (T1003.001).
4. **Safety Boundaries:**
   - `LIVE_RESPONSE_DISABLED=true` was confirmed strictly enforced in `services/response/manager.py` and `services/response/lab_adapter.py`.
   - Real containment and host isolation actions were safely locked down behind the simulation/dry-run lab adapter.
   - All external network egress remained disabled in tests; all IP addresses adhered to RFC 5737 (e.g., `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918 private subnets.

---

## 2. Scenario Framework Architecture

The scenario framework was designed and implemented as a data-driven, strictly typed, versioned evaluation harness in `scenarios/`:

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           SCENARIO FRAMEWORK ARCHITECTURE                         │
└───────────────────────────────────────────────────────────────────────────────────┘
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   ▼                                             ▼
     ┌───────────────────────────┐                 ┌───────────────────────────┐
     │   scenarios/models.py     │                 │  scenarios/validator.py   │
     │ - ScenarioDefinition      │                 │ - Schema validation       │
     │ - ScenarioRunRecord       │                 │ - Executable code ban     │
     │ - ScenarioSuiteReport     │                 │ - ATT&CK ID validation    │
     │ - ScenarioCategoryEnum    │                 │ - Size & count bounds     │
     └───────────────────────────┘                 └───────────────────────────┘
                   │                                             │
                   └──────────────────────┬──────────────────────┘
                                          ▼
                             ┌───────────────────────────┐
                             │  scenarios/catalogue.py   │
                             │ - Auto-discovers fixtures │
                             │ - Validates upon load     │
                             │ - Filtering by category   │
                             └───────────────────────────┘
                                          │
                                          ▼
                             ┌───────────────────────────┐
                             │   scenarios/runner.py     │
                             │ - End-to-end evaluation   │
                             │ - Stage observation       │
                             │ - Grounding comparison    │
                             │ - Safety enforcement      │
                             └───────────────────────────┘
```

### Core Architecture Components:

1. **Strictly Typed Models (`scenarios/models.py`):**
   - `ScenarioDefinition`: Pydantic V2 model capturing scenario ID, semantic version, defensive objective, required telemetry sources, required canonical fields, MITRE ATT&CK technique IDs, synthetic event payload, expected/unexpected detection rules, expected correlation rules, expected incident severity, expected risk band, expected triage severity, investigation hypotheses, and telemetry gaps.
   - `ScenarioRunRecord`: Comprehensive observational telemetry capturing executed stages, duration, matched rules, correlation matches, incident ID, deterministic risk score, triage summary, investigation findings, evidence citations, prompt-injection quarantine status, and safety switch verification.
   - `ScenarioSuiteReport`: Aggregate statistics across suite runs, compiling lab detection rates, lab false-positive counts, and evidence-grounding fidelity.

2. **Defense-in-Depth Static Validator (`scenarios/validator.py`):**
   - **Inert Data Guarantee:** Scenarios are strictly data files. Any scenario fixture containing executable code or shell tokens (`eval`, `exec`, `__import__`, `subprocess`, `os.system`, `shutil`, `pty`) is rejected prior to ingestion.
   - **Identifier and Version Enforcement:** IDs must conform to `^SCN-(?:[0-9]{2}|NEG-[0-9]{2})-[A-Z0-9_-]+$`; versions must conform to SemVer `^[0-9]+\.[0-9]+\.[0-9]+$`.
   - **Execution Budget Bounds:** Event counts are capped at 100 events per scenario; raw fixture file size is capped at 256 KB.
   - **ATT&CK Catalog Verification:** All declared ATT&CK technique IDs are verified against the authoritative pinned MITRE ATT&CK Enterprise Matrix catalog.

3. **Autonomous Scenario Catalogue (`scenarios/catalogue.py`):**
   - Automatically scans `scenarios/fixtures/` for valid `.json` definitions.
   - Re-validates every fixture upon discovery.
   - Provides safe query APIs to filter scenarios by category (`authentication`, `process_execution`, `lateral_movement`, `c2_network`, `account_takeover`, `multi_stage`, `prompt_injection`, `poisoned_knowledge`, `governance_abuse`, `negative_control`).

4. **Authentic Pipeline Runner (`scenarios/runner.py`):**
   - Feeds synthetic scenario telemetry through the authentic CyberSentinel AI pipeline rather than using mocked test stubs:
     - **Stage 1 (Ingestion & Normalization):** Events validated via `CanonicalEvent.model_validate()`.
     - **Stage 2 (Detection):** Evaluated against compiled Sigma ASTs via `SigmaDetectionEngine.evaluate()`.
     - **Stage 3 (Correlation & Incident Creation):** Evaluated through stateful temporal sliding windows via `CorrelationEngine.process_detection()` and persisted via `IncidentManager.create_or_update_from_correlation()`.
     - **Stage 4 (Risk Assessment):** Evaluated through the 7-factor explainable algorithm via `DeterministicRiskEngine.assess_incident()`.
     - **Stage 5 (Triage):** Triaged via `TriageAgent.triage_incident()` with prompt-injection defense layers.
     - **Stage 6 (Investigation & Grounding):** Investigated via `InvestigationAgent.investigate_incident()`, verifying factual claim citations and telemetry gap identification.
     - **Stage 7 (Specialized Adversarial Defenses):**
       - Prompt-injection directive quarantine (`format_untrusted_context`).
       - RAG delimiter defanging and incident isolation (`RAGEngine.query`).
       - Unregistered arbitrary tool denial (`ToolExecutionService`).
       - `LIVE_RESPONSE_DISABLED=true` containment prevention (`ResponseManager.execute_action`).

---

## 3. Scenario Catalogue and Fixture Versions

The framework ships with 16 authoritative scenario fixtures (12 primary defensive attack simulations + 4 negative control fixtures):

| Scenario ID | Name | Category | Events | ATT&CK Techniques | Expected Detections | Expected Correlation | Expected Severity |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **SCN-01-AUTH-BRUTEFORCE** | Brute-Force Authentication Activity | `authentication` | 4 | T1110 | `auth_root_failed` | `corr_brute_force_auth` | High |
| **SCN-02-SUSPICIOUS-POWERSHELL** | Suspicious PowerShell Download Cradle | `process_execution` | 1 | T1059.001 | `proc_powershell_download` | None (Standalone) | High |
| **SCN-03-UNUSUAL-ADMIN** | Unusual Administrative User Creation | `privilege_escalation` | 1 | T1136.001 | `proc_admin_user_creation` | None (Standalone) | High |
| **SCN-04-CREDENTIAL-MISUSE** | Credential Dumping via LSASS Memory Dump | `credential_access` | 1 | T1003.001 | `proc_credential_dump` | None (Standalone) | High |
| **SCN-05-SUSPICIOUS-DNS** | Suspicious Dynamic DNS Resolution | `c2_network` | 1 | T1071.004 | `net_suspicious_dns` | None (Standalone) | High |
| **SCN-06-LATERAL-MOVEMENT** | Remote Execution via WMI Process Call | `lateral_movement` | 1 | T1047 | `proc_lateral_movement_wmi` | None (Standalone) | High |
| **SCN-07-SUSPICIOUS-OUTBOUND** | Suspicious Outbound C2 Reverse Shell Connection | `c2_network` | 1 | T1071 | `net_suspicious_outbound` | None (Standalone) | High |
| **SCN-08-ACCOUNT-TAKEOVER** | Account Takeover Password Reset & Elevation | `account_takeover` | 2 | T1098, T1078 | `proc_account_takeover_reset` | None (Standalone) | High |
| **SCN-09-MULTI-STAGE-INTRUSION** | Multi-Stage Synthetic Intrusion Timeline | `multi_stage` | 2 | T1033, T1059.001 | `proc_cmd_whoami`, `proc_powershell_download` | `corr_recon_to_execution` | Critical |
| **SCN-10-PROMPT-INJECTION** | Prompt Injection Embedded in Process Telemetry | `prompt_injection` | 1 | T1059 | None (Quarantine Test) | None | Warning/Lead |
| **SCN-11-POISONED-KNOWLEDGE-DOC** | Poisoned Knowledge Document Neutralization | `poisoned_knowledge` | 1 | T1195 | None (RAG Defang Test) | None | Warning/Lead |
| **SCN-12-UNAUTHORIZED-TOOL-CALL** | Unauthorized Tool Call & Response Safety Switch | `governance_abuse` | 1 | T1078 | None (Safety Barrier Test) | None | High |
| **SCN-NEG-01-BENIGN-AUTH** | Negative Control: Benign Authentication Typo | `negative_control` | 1 | T1110 | `auth_root_failed` | None (Below Threshold) | None (Suppressed) |
| **SCN-NEG-02-LEGITIMATE-ADMIN** | Negative Control: Whitelisted Legitimate Admin Script | `negative_control` | 1 | T1059.001 | None (Whitelisted) | None | None (Suppressed) |
| **SCN-NEG-03-BENIGN-DNS** | Negative Control: Legitimate Internal Corporate DNS Query | `negative_control` | 1 | None | None (Benign) | None | None (Suppressed) |
| **SCN-NEG-04-MALFORMED-TELEMETRY** | Negative Control: Malformed Events Missing Telemetry Fields | `negative_control` | 1 | None | None (Normalization Rejection)| None | None (Quarantined) |

---

## 4. Pipeline Stages Exercised Per Scenario

Every scenario exercises an authenticated slice of the CyberSentinel AI SOC pipeline. The table below documents the exact stages verified:

| Scenario | Norm | Sigma | Corr | Inc Mgmt | Risk Eng | Triage | Invest | Safety & Defense Verification |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **SCN-01** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Sliding window threshold (3 attempts) |
| **SCN-02** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | High-severity PowerShell cradle alert |
| **SCN-03** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Privileged account addition alert |
| **SCN-04** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | LSASS memory dump detection |
| **SCN-05** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Dynamic DNS domain pattern alert |
| **SCN-06** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Remote WMI process invocation alert |
| **SCN-07** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Suspicious non-standard TCP port alert |
| **SCN-08** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Password change on disabled user |
| **SCN-09** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Ordered chronological sequence correlation |
| **SCN-10** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `[WARNING: SUSPICIOUS DIRECTIVES QUARANTINED]` |
| **SCN-11** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `[ESCAPED_DOC_DELIMITER]` neutralization |
| **SCN-12** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Tool denial + `BLOCKED_SAFETY` barrier |
| **SCN-NEG-01** | Yes | Yes | Yes | N/A | N/A | N/A | N/A | Suppressed: 1 < 3 threshold (no incident) |
| **SCN-NEG-02** | Yes | Yes | N/A | N/A | N/A | N/A | N/A | Filtered by Sigma `not filter_update` |
| **SCN-NEG-03** | Yes | Yes | N/A | N/A | N/A | N/A | N/A | Zero Sigma matches; no incident created |
| **SCN-NEG-04** | Yes | N/A | N/A | N/A | N/A | N/A | N/A | Pydantic validation rejected corrupt event |

---

## 5. Expected versus Observed Results

| Scenario ID | Expected Sigma Rule | Observed Sigma Rule | Expected Correlation | Observed Correlation | Expected Severity | Observed Severity | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **SCN-01** | `auth_root_failed` | `auth_root_failed` | `corr_brute_force_auth` | `44444444-...` | High | High | **PASS** |
| **SCN-02** | `proc_powershell_download` | `proc_powershell_download` | Standalone | Standalone | High | High | **PASS** |
| **SCN-03** | `proc_admin_user_creation` | `proc_admin_user_creation` | Standalone | Standalone | High | High | **PASS** |
| **SCN-04** | `proc_credential_dump` | `proc_credential_dump` | Standalone | Standalone | High | High | **PASS** |
| **SCN-05** | `net_suspicious_dns` | `net_suspicious_dns` | Standalone | Standalone | High | High | **PASS** |
| **SCN-06** | `proc_lateral_movement_wmi` | `proc_lateral_movement_wmi` | Standalone | Standalone | High | High | **PASS** |
| **SCN-07** | `net_suspicious_outbound` | `net_suspicious_outbound` | Standalone | Standalone | High | High | **PASS** |
| **SCN-08** | `proc_account_takeover_reset` | `proc_account_takeover_reset` | Standalone | Standalone | High | High | **PASS** |
| **SCN-09** | `proc_cmd_whoami`, `proc_powershell_download` | `proc_cmd_whoami`, `proc_powershell_download` | `corr_recon_to_execution` | `55555555-...` | Critical | Critical | **PASS** |
| **SCN-10** | Directive Quarantine | Quarantined | Standalone | Standalone | Warning | Warning | **PASS** |
| **SCN-11** | Delimiter Defanged | Escaped (`[ESCAPED_DOC_DELIMITER]`) | Standalone | Standalone | Warning | Warning | **PASS** |
| **SCN-12** | Deny Exec & Block Safety | Denied & `BLOCKED_SAFETY` | Standalone | Standalone | High | High | **PASS** |
| **SCN-NEG-01** | `auth_root_failed` | `auth_root_failed` | Suppressed (Below threshold) | None | Suppressed | None | **PASS** |
| **SCN-NEG-02** | Suppressed (Whitelist) | Zero matches | None | None | Suppressed | None | **PASS** |
| **SCN-NEG-03** | Zero matches | Zero matches | None | None | Suppressed | None | **PASS** |
| **SCN-NEG-04** | Schema Rejection | Normalization error recorded | None | None | Quarantined | None | **PASS** |

### Lab Evaluation Scoreboard:
- **Total Scenarios Evaluated:** 16
- **Passed Scenarios:** 16 (100.0%)
- **Failed Scenarios:** 0
- **Partial Scenarios:** 0
- **Lab Detection Rate:** 100.0% (across tested fixture set)
- **Lab False Positive Count on Negative Controls:** 0
- **Evidence-Grounding Fidelity:** 1.0 (all claims cited verified incident evidence references)

---

## 6. Security and Isolation Controls

1. **Non-Negotiable Safety Barrier (`LIVE_RESPONSE_DISABLED=true`):**
   - Verified that even after a Tier 2 action (`isolate_host`) was proposed and approved by a SOC Manager, `execute_action()` returned `state="BLOCKED_SAFETY"` and refused live dispatch.
   - Lab actions are strictly redirected to `LabResponseAdapter`, generating dry-run receipts without touching network interfaces or infrastructure.
2. **Deterministic Data-Driven Scenarios:**
   - Fixture files are pure JSON documents.
   - The static validator rejects fixtures with executable code tokens (`eval`, `exec`, `subprocess`, `os.system`, `shutil`, `pty`).
3. **Network Isolation:**
   - All addresses in synthetic telemetry use RFC 5737 test documentation blocks (`198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918 private subnets (`192.168.100.0/24`, `10.0.0.0/8`). No live external endpoints are queried.
4. **Session Isolation & Rollback:**
   - Every scenario run executes against an isolated database session with explicit transactional rollbacks and unique namespace IDs. No production or shared data is modified.
5. **Prompt-Injection Defense Verification:**
   - SCN-10 confirms that jailbreak and system-prompt override directives embedded in command-line arguments are quarantined with `[WARNING: SUSPICIOUS DIRECTIVES QUARANTINED: ...]`.
6. **Poisoned Knowledge Neutralization:**
   - SCN-11 confirms that artificial delimiters in retrieved RAG knowledge are escaped (`[ESCAPED_DOC_DELIMITER]`), preventing attacker-controlled context termination.
7. **Tool Authorization Enforced:**
   - SCN-12 confirms that attempts to invoke unregistered arbitrary system commands (`arbitrary_system_execute`) raise `ToolNotFoundError` and are rejected.

---

## 7. Test Commands and Exact Results

### Scenario-Specific Test Suites:
```bash
.venv\Scripts\python -m pytest tests/unit/test_scenario_framework.py tests/integration/test_scenario_pipeline.py tests/security/test_scenario_security.py -v
```
**Output:**
```
============================= test session starts =============================
platform win32 -- Python 3.13.12, pytest-9.1.1, pluggy-1.7.0
rootdir: D:\TEST\CyberSentinel
configfile: pyproject.toml
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False

tests/unit/test_scenario_framework.py::test_catalogue_loads_all_fixtures PASSED [  5%]
tests/unit/test_scenario_framework.py::test_validator_accepts_valid_scenario_definition PASSED [ 10%]
tests/unit/test_scenario_framework.py::test_validator_rejects_malformed_scenario_id PASSED [ 15%]
tests/unit/test_scenario_framework.py::test_validator_rejects_executable_code_in_metadata PASSED [ 21%]
tests/unit/test_scenario_framework.py::test_validator_rejects_oversized_event_count PASSED [ 26%]
tests/unit/test_scenario_framework.py::test_catalogue_filter_by_category PASSED [ 31%]
tests/integration/test_scenario_pipeline.py::test_pipeline_executes_auth_bruteforce_scenario PASSED [ 36%]
tests/integration/test_scenario_pipeline.py::test_pipeline_executes_suspicious_powershell_scenario PASSED [ 42%]
tests/integration/test_scenario_pipeline.py::test_pipeline_executes_suspicious_dns_scenario PASSED [ 47%]
tests/integration/test_scenario_pipeline.py::test_pipeline_executes_multi_stage_intrusion_scenario PASSED [ 52%]
tests/integration/test_scenario_pipeline.py::test_negative_control_benign_auth_below_threshold PASSED [ 57%]
tests/integration/test_scenario_pipeline.py::test_negative_control_legitimate_admin_whitelisted PASSED [ 63%]
tests/integration/test_scenario_pipeline.py::test_negative_control_benign_dns_traffic PASSED [ 68%]
tests/integration/test_scenario_pipeline.py::test_full_scenario_suite_run_compiles_metrics PASSED [ 73%]
tests/security/test_scenario_security.py::test_scenario_prompt_injection_quarantine PASSED [ 78%]
tests/security/test_scenario_security.py::test_scenario_poisoned_knowledge_doc_delimiter_escaped PASSED [ 84%]
tests/security/test_scenario_security.py::test_scenario_unauthorized_tool_call_and_safety_switch PASSED [ 89%]
tests/security/test_scenario_security.py::test_negative_control_malformed_telemetry_quarantined PASSED [ 94%]
tests/security/test_scenario_security.py::test_scenario_validator_rejects_arbitrary_shell_tokens PASSED [100%]

============================= 19 passed in 2.95s ==============================
```

### Full Repository Test Suite (Regression Free):
```bash
.venv\Scripts\python -m pytest
```
**Output:**
```
====================== 437 passed, 11 warnings in 25.18s ======================
```

### Static Analysis and Type Checking:
```bash
.venv\Scripts\ruff check scenarios/ tests/unit/test_scenario_framework.py tests/integration/test_scenario_pipeline.py tests/security/test_scenario_security.py
All checks passed!

.venv\Scripts\mypy scenarios
Success: no issues found in 5 source files
```

---

## 8. Mocked versus Real Service Verification

To ensure fidelity without creating artificial mock pipelines:
- **Sigma Detection Engine:** Real production `SigmaDetectionEngine` evaluating actual compiled ASTs against rules in `rules/sigma/`. Zero mocks.
- **Correlation Engine:** Real production `CorrelationEngine` and `SlidingEventWindow` evaluating temporal conditions against rules in `rules/correlation/`. Zero mocks.
- **Incident Lifecycle Manager:** Real production `IncidentManager` managing PostgreSQL state transitions, primary affected entities, and audit events.
- **Explainable Risk Engine:** Real production `DeterministicRiskEngine` applying the 7-factor scoring policy and ATT&CK tactic weights.
- **AI Triage Agent:** Real production `TriageAgent` running `DeterministicRuleProvider` with untrusted context formatting.
- **AI Investigation Agent:** Real production `InvestigationAgent` enforcing evidence citation and provenance tracking.
- **RAG Engine:** Real production `RAGEngine` maintaining BM25 index with delimiter sanitization.
- **Response Safety Switch:** Real production `ResponseManager` executing with `live_response_disabled=true`, delegating to `LabResponseAdapter` to strictly simulate actions. Zero live execution.

---

## 9. Known Limitations and Remediation Items

1. **Synthetic Telemetry Volume:** Lab fixtures test up to 100 events per scenario. High-volume stress testing (100k events/sec) belongs to Phase 7 Benchmarking.
2. **Offline Threat Intel Mocking:** In lab environments without external internet access, threat intelligence lookups for synthetic IPs return neutral/absent scores (35.0 default baseline). This is safe and adheres to the rule that "absence of threat intel does not imply benign behavior."
3. **Temporal Acceleration:** Sliding windows in lab scenarios compress chronological time using explicit event timestamps rather than real-time wall-clock delays.

---

## 10. Acceptance Decision

**DECISION: COMPLETE**

Sprint 22 has satisfied all requirements of `CSAI-R1.1-LAB-SCENARIOS`:
- Typed, versioned scenario framework implemented in `scenarios/`.
- 16 validated data-driven fixtures created covering all 12 required defensive scenarios plus 4 negative controls.
- End-to-end pipeline evaluation verified against genuine detection, correlation, risk, triage, investigation, and response components.
- Zero live attack simulations or response executions; `LIVE_RESPONSE_DISABLED=true` strictly verified.
- All 437 test cases across the entire project pass with zero regressions.
- Ruff and Mypy static checks pass cleanly.
