# 02 — Problem Statement

## Problem
Security teams receive alerts and events from many tools, but data fragmentation, duplicate alerts, inconsistent context, limited analyst capacity, and manual investigation workflows can make it difficult to determine which signals represent a meaningful incident and what evidence supports the conclusion.

## Root causes to validate
- Heterogeneous event formats and inconsistent entity identifiers.
- Weak linkage between alerts, raw events, identities, hosts, network flows, and cloud activity.
- Repeated manual enrichment and timeline construction.
- Detection logic without transparent provenance or reliable regression tests.
- AI-generated summaries that can sound confident without sufficient evidence.
- Response actions that are difficult to govern, approve, roll back, or audit.
- Lack of repeatable benchmarks comparing workflow outcomes.

These are hypotheses for the project, not universal claims about every SOC. Validate them with literature, interviews, and measurable experiments.

## Proposed solution
Provide a common pipeline: ingest → preserve raw source → normalize → validate → detect → correlate → create/update incident → enrich → investigate with bounded agents → attach evidence → calculate explainable risk → recommend response → request approval → execute only through authorized adapters → verify and audit.

## Research questions
1. Does evidence-linked AI assistance reduce analyst investigation time without reducing decision quality?
2. Does event correlation improve incident grouping compared with alert-by-alert triage?
3. Which task types benefit from an LLM, and which are better served by deterministic logic?
4. How do prompt injection, poisoned intelligence, missing telemetry, and model outages affect investigation reliability?
5. What are the precision/recall, latency, cost, and human-override trade-offs of different orchestration strategies?

## Baseline and comparison
Compare the proposed workflow against a deterministic baseline using the same event set, rule set, and ground truth. Record human time, correctness, evidence coverage, false positives/negatives, model calls, token/cost estimate, and operational failures.

## Assumptions and constraints
The first implementation is a research-grade, single-organization platform. It uses authorized lab or explicitly approved telemetry. Production use requires a separate security review, privacy/legal review, operational ownership, disaster recovery, and integration-specific validation.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
