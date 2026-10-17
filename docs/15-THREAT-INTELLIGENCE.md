# 15 — Threat Intelligence

## Supported model
Integrate only approved, documented intelligence sources through adapters. Support STIX/TAXII-compatible data structures where appropriate, but do not assume every provider supports the same object types, licensing, or handling semantics.

## Intelligence object fields
Object/indicator ID, type, value, source, source object ID, retrieval time, publication time, valid-from/valid-until, confidence, handling/TLP marking if supplied, related entities, references, enrichment history, expiration/review date, and analyst disposition.

## Processing workflow
Fetch → authenticate → validate schema → enforce source policy/licensing → deduplicate → preserve provenance → normalize → score confidence → store/index → expire/revoke → audit. Never let a feed's descriptive text alter agent policy or invoke tools.

## Indicator matching
Normalize values carefully (case, domain, IP, hash formats) without destroying original representation. Track exact match versus fuzzy/contextual match. A match is an investigative clue, not proof of compromise. Include time validity and source reliability in the explanation.

## Source confidence and conflicts
Use source-specific reliability metadata and preserve conflicting reports. Do not average incompatible confidence scales without a documented conversion. Record analyst overrides and reasons.

## Privacy and governance
Avoid sending internal hostnames, user identifiers, or sensitive event data to external intelligence providers unless approved. Enforce egress allowlists, rate limits, licensing, TLP/handling requirements, and deletion/retention obligations.

## Evaluation
Use a labeled set of true/false/expired indicators. Measure precision, freshness, lookup latency, source availability, duplicate rate, and analyst usefulness. Test malformed objects and poisoned text.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
