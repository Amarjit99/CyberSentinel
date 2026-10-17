# 01 — Project Vision

## Vision
Build a modular, evidence-centered security operations platform that helps analysts turn high-volume telemetry into explainable detections, correlated incidents, repeatable investigations, and carefully governed response recommendations.

## North-star outcome
An analyst can open an incident, understand why it exists, inspect the underlying events and rule versions, review a reproducible investigation timeline, see ATT&CK mappings with confidence and evidence, and approve or reject a proposed response with a complete audit trail.

## Product principles
1. **Evidence before narrative:** every material claim links to source event IDs, rule results, or cited intelligence.
2. **Deterministic core, bounded AI:** rules and code establish facts; agents summarize, correlate, and propose hypotheses.
3. **Human control:** destructive, disruptive, external, or privileged actions require explicit authorization and approval.
4. **Graceful degradation:** ingest, search, deterministic detections, and incident workflows continue if the model provider is unavailable.
5. **Least privilege:** each service and agent receives only the tools and data required for its task.
6. **Reproducibility:** preserve raw event payloads, normalized records, rule versions, model/provider metadata, prompts/templates, and investigation artifacts where lawful.
7. **Privacy by design:** minimize collected data, restrict access, define retention, and redact secrets.
8. **Interoperability:** use documented schemas and adapters rather than coupling the core to a single vendor.

## Primary users
- SOC analyst: triage, investigate, document, and recommend response.
- Detection engineer: author, test, version, and deploy detection logic.
- SOC lead: prioritize incidents, review workload and outcomes, approve policies.
- Platform/security administrator: manage integrations, RBAC, secrets, retention, and audit.
- Researcher/evaluator: run controlled scenarios and measure precision, recall, latency, cost, and analyst usefulness.

## Scope boundaries
In scope: authorized telemetry collection, event normalization, detection, correlation, threat-intelligence enrichment, evidence management, bounded agent investigations, explainable risk, approval workflows, and controlled lab evaluation.

Out of scope for initial releases: unrestricted autonomous offensive activity, public-target scanning, automatic destructive response, unsupported claims of breach attribution, and training models on customer data without explicit governance.

## Success measures
Track time to triage, time to evidence-backed disposition, alert precision/recall, incident grouping quality, evidence completeness, false-positive rate, analyst override rate, AI failure rate, response approval latency, service availability, and per-investigation cost. Establish baselines before claiming improvement.

## Release path
MVP: synthetic/sample telemetry, deterministic rules, incidents, evidence timeline, RBAC, audit logs, and test suite. Later releases add integrations, enrichment, bounded agents, risk scoring, and approved response adapters.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
