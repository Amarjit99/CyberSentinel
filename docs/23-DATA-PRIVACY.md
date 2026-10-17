# 23 — Data Privacy

## Principles
Purpose limitation, data minimization, least privilege, transparency, retention limitation, secure processing, and documented accountability. Applicable legal obligations depend on deployment location, data subjects, customer contracts, and data types; obtain qualified review before production use.

## Data inventory
For each data class document: purpose, source, fields, sensitivity, lawful/approved basis, access roles, storage location, processors/subprocessors, retention, deletion behavior, export behavior, and incident owner.

## Minimize and redact
Avoid collecting content not needed for detection. Redact credentials, tokens, session cookies, unnecessary personal identifiers, and sensitive payload fragments before logging or external model calls. Use synthetic or de-identified fixtures for development wherever possible.

## Model-provider controls
Do not send telemetry to an external provider unless the organization has explicitly approved the provider, data class, region, retention/training terms, and transfer mechanism. Keep API keys server-side. Record which data classes can be used for which tasks.

## Retention and deletion
Define retention separately for raw telemetry, normalized events, evidence, incident notes, model outputs, audit records, and backups. Implement expiry jobs with metrics and failure alerts. Document deletion propagation across PostgreSQL, OpenSearch, object storage, vector indexes, caches, exports, and backup expiry.

## Access and data-subject handling
Use role/object-level controls, audited exports, redacted report templates, and documented processes for access/correction/deletion requests where applicable. Avoid exposing one customer's records to another if multi-tenancy is enabled.

## Privacy incident response
Define detection, containment, investigation, notification decision, remediation, evidence preservation, and post-incident review for accidental exposure or unauthorized model transmission.

## Verification
Test redaction with canary secrets, unauthorized search/export, retention expiry, deletion propagation, backup handling, and model-call data minimization. Privacy controls require operational proof, not just policy text.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
