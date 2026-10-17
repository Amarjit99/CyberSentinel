# 03 — Literature Review

## Purpose
Build a traceable review of prior work on SOC automation, SIEM/SOAR, event correlation, threat intelligence, detection engineering, AI-assisted security operations, RAG, agent security, and human factors. This is a review protocol and synthesis scaffold; it must be populated with verified papers and source extracts before being presented as a completed systematic review.

## Review questions
- What are established approaches for alert prioritization and multi-event correlation?
- Where do LLMs improve triage, summarization, query generation, or detection engineering?
- What failure modes arise from hallucination, prompt injection, stale context, data leakage, and tool misuse?
- Which benchmarks and datasets support reproducible evaluation?
- How are human approval, accountability, and auditability implemented in security automation?

## Search strategy
Search scholarly indexes and primary sources: IEEE Xplore, ACM Digital Library, USENIX, arXiv (clearly label preprints), NIST, MITRE, CISA, vendor technical documentation, and reputable incident reports. Record search date, exact query, filters, inclusion/exclusion reason, and duplicate handling.

Example query families:
- `("security operations center" OR SOC) AND (LLM OR "language model" OR agent)`
- `alert correlation AND (SIEM OR security analytics)`
- `RAG AND cybersecurity AND (evaluation OR benchmark)`
- `prompt injection AND tool-using agents AND security`
- `MITRE ATT&CK AND detection engineering AND evaluation`

## Inclusion criteria
Include sources with clear methodology, relevant empirical evidence, authoritative standards, or directly applicable architecture. Record publication date, version, authors/organization, evidence type, limitations, and whether results are independently reproducible.

Exclude unsubstantiated marketing claims from evidence synthesis; they may be included only as product-positioning context. Do not infer causal benefit from a vendor case study without examining its methodology.

## Extraction schema
For each source capture: citation; DOI/URL; publication date; problem; method; dataset; baselines; metrics; results; limitations; threat model; reproducibility artifacts; relevance to CyberSentinel AI; confidence in evidence.

## Synthesis themes
1. Deterministic detections and rule quality.
2. Alert grouping and entity resolution.
3. Threat-intelligence provenance and confidence.
4. LLM/RAG utility and grounding.
5. Agent authorization, identity, and audit.
6. Human factors, explainability, and automation trust.
7. Dataset bias, leakage, and evaluation validity.

## Deliverable and quality gate
Do not claim “systematic review completed” until search logs, screening decisions, and extraction records are included. Every factual statement about prior research must cite a source. Separate peer-reviewed evidence, standards, preprints, vendor documentation, and project hypotheses.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
