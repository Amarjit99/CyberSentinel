# 26 — Benchmark Design

## Objective
Evaluate whether agent-assisted workflows improve investigation quality or speed over a deterministic baseline without unacceptable increases in false conclusions, cost, latency, or security risk.

## Experimental design
Use identical event fixtures, rule versions, and ground truth across conditions:
- A: deterministic detection and analyst workflow.
- B: deterministic workflow plus evidence retrieval/summarization.
- C: bounded multi-agent investigation.
Randomize scenario order where humans participate. Record analyst experience and avoid training/test leakage.

## Dataset splits
Separate development/tuning, validation, and held-out test scenarios. Keep near-duplicate events from the same base scenario within one split. Publish scenario generation rules and hashes where possible. Use synthetic or properly licensed datasets.

## Metrics
- Detection: precision, recall, F1, false positives per scenario, detection latency.
- Correlation: pairwise grouping precision/recall, incident-level purity/completeness.
- Evidence: citation precision, evidence coverage, unsupported-claim rate.
- Workflow: time to disposition, number of analyst corrections, approval quality.
- Agent: task completion, invalid tool-call rate, budget exhaustion, policy violations.
- Operations: p50/p95/p99 latency, throughput, provider error rate, cost per incident.
- Safety: unauthorized access/action, secret leakage, prompt-injection success.

## Statistical practice
Pre-register primary outcomes and exclusion criteria. Report sample size, confidence intervals, variance, effect sizes, and limitations. Do not claim improvement from anecdotal demonstrations or cherry-picked examples.

## Reproducibility package
Include commit ID, locked dependencies, environment, configuration, dataset/scenario version, model/provider/version, prompt/template version, run commands, raw metric outputs, analysis code, and known deviations.

## Success criteria
Set thresholds before evaluating the held-out test set. A release cannot trade unauthorized actions or sensitive-data exposure for better speed or F1. Security safety gates are hard constraints; utility metrics are evaluated only after those gates pass.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
