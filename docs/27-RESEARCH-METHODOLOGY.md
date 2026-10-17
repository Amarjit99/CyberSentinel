# 27 — Research Methodology

## Research objective
Study the reliability, usefulness, and safety of evidence-grounded AI assistance in security operations using reproducible scenarios and comparison against deterministic baselines.

## Research questions and hypotheses
- **RQ1:** Does evidence-grounded assistance reduce time to a correct disposition? Hypothesis: it may reduce time while maintaining or improving correctness.
- **RQ2:** Does event correlation improve incident grouping? Hypothesis: explicit entity/time/context features improve grouping over independent alert handling.
- **RQ3:** Which tasks benefit from agents? Hypothesis: summarization and context synthesis benefit more than authorization and action execution, which should remain deterministic.
- **RQ4:** How robust is the workflow to malicious evidence and outages? Hypothesis: external policy enforcement and bounded tools reduce, but do not eliminate, failures.

## Method
Use controlled experiments with synthetic or approved datasets, versioned rules, held-out scenarios, documented baselines, and human evaluation where needed. Keep model/provider, prompt, retrieval corpus, and configuration versions fixed within a comparison.

## Variables
Independent variables: workflow condition, retrieval configuration, agent topology, evidence availability, injection condition. Dependent variables: accuracy, time, evidence completeness, false positives, unsupported claims, tool-policy violations, cost, and latency. Control variables: event set, rule version, analyst instructions, environment, and scoring rubric.

## Validity risks
Dataset representativeness, scenario leakage, small sample size, annotator disagreement, model/provider drift, changing threat feeds, subjective time measurement, and researcher bias. Mitigate with blind scoring where practical, independent review, held-out data, and explicit limitations.

## Ethics and data governance
Use authorized data; minimize personal information; obtain institutional or organizational review when applicable; do not expose sensitive telemetry; document provider terms; and ensure experiments cannot trigger live response.

## Reporting
Publish methodology, datasets or generators where licensing permits, configuration, metrics, confidence intervals, negative results, failures, and replication steps. Distinguish measured outcomes from design expectations and proposed future work.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
