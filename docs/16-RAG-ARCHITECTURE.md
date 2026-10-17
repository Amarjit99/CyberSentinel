# 16 — Retrieval-Augmented Generation (RAG) Architecture

## Purpose
RAG may supply approved security knowledge to investigation and reporting tasks. It must not be the source of authorization, policy, or proof that an event occurred.

## Approved corpus
Potential sources: internal runbooks, reviewed detection documentation, versioned ATT&CK snapshots, approved playbooks, platform manuals, and vetted post-incident lessons. Exclude secrets, unapproved personal data, and documents without clear provenance.

## Ingestion pipeline
Source approval → parsing → malware/content scanning where applicable → secret/PII screening → metadata and access labels → chunking → embeddings → index → retrieval tests → periodic refresh/expiry. Keep source ID, version, author/owner, timestamp, classification, and checksum.

## Retrieval controls
Enforce access filters before returning chunks. Use bounded top-k and token limits, freshness constraints, source diversity where useful, and citations to exact source chunks. Treat retrieved text as untrusted content. A document cannot grant tool permissions or override system policy.

## Grounding behavior
The generator must distinguish sourced statements from inference, cite retrieved source IDs, state when evidence is absent or conflicting, and avoid invented citations. Security event facts should cite event/evidence records rather than general RAG documents.

## Prompt-injection defenses
Separate system policy from retrieved data; quote or delimit untrusted passages; do not follow embedded instructions; constrain tools independently; test indirect prompt injection and malicious markup; avoid unrestricted URL fetching.

## Evaluation
Measure retrieval recall/precision, citation correctness, freshness, unauthorized retrieval attempts, injection success rate, answer faithfulness, latency, and cost. Run access-control tests across roles and data classifications before enabling the feature.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
