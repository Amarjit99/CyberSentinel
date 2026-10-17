# 13 — MITRE ATT&CK Mapping

## Purpose
Use ATT&CK as a behavior taxonomy and detection-engineering reference, not as proof that an adversary performed a technique. Map only where observed behavior and supporting evidence justify the association.

## Mapping record
Required fields: ATT&CK domain/version, technique/sub-technique ID, name, evidence IDs, detection/rule ID and version, rationale, confidence, analyst validation state, source URL, mapping date, and caveats.

## Mapping workflow
1. A rule or analyst identifies behavior from normalized events.
2. The mapping component proposes one or more relevant techniques from a pinned ATT&CK release.
3. It explains the event fields and logic that support each mapping.
4. A validator checks IDs against the selected ATT&CK data snapshot.
5. Analyst review confirms, edits, or rejects mappings where policy requires.
6. Tests verify that invalid/deprecated IDs and unsupported mappings are not silently accepted.

## Detection strategy design
Prefer behavior-oriented detection strategies and analytics over simplistic one-indicator-to-one-technique mapping. Each analytic should state required telemetry, data sources, logic, expected false positives, test fixture, and operational dependencies.

## Confidence semantics
Define a controlled scale such as `LOW`, `MEDIUM`, `HIGH` with explicit criteria. Confidence describes evidence strength for the mapping, not the certainty of actor identity or intent.

## Versioning
Pin the ATT&CK release used for rule tests and mapping validation. When updating ATT&CK, produce a change report for renamed, deprecated, split, or merged techniques and re-run regression tests.

## Evaluation
Measure mapping precision against expert-reviewed ground truth, unsupported mapping rate, coverage of relevant techniques in the scenario corpus, and time required for analyst correction. Do not optimize coverage by assigning a technique to every alert.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
