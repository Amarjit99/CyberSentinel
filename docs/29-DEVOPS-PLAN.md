# 29 — DevOps Plan

## Repository workflow
Use protected main branch, short-lived feature branches, reviewed pull requests, CODEOWNERS for security-sensitive areas, conventional commit or equivalent consistent history, and issue-to-test traceability.

## Continuous integration
On every pull request: formatting, linting, type checks, unit tests, schema validation, migration checks, secret scanning, dependency scanning, and build. On protected branches: integration tests, container scan, SBOM generation, and signed/reproducible artifact steps where practical.

## Environments
Maintain separate development, test, evaluation/staging, and production configuration. Never reuse production credentials in tests. Seed environments with synthetic data. Make destructive test targets explicit and isolated.

## Release process
1. Review changes and threat-model impact.
2. Update API/event schema and migration notes.
3. Run all release gates and publish evidence.
4. Generate versioned artifacts and SBOM.
5. Deploy to staging and run smoke/rollback tests.
6. Obtain required approvals.
7. Deploy gradually where supported.
8. Verify health and business/security metrics.
9. Publish release notes and known limitations.

## Observability and incident response
Define service-level indicators for ingestion success, queue lag, detection processing, API availability, model failure, evidence persistence, and response adapter outcomes. Create runbooks for queue backlog, index failure, database exhaustion, secret rotation, provider outage, and suspected platform compromise.

## Dependency and vulnerability management
Pin dependencies, automate update PRs, triage vulnerabilities by exploitability and exposure, set remediation deadlines, and document accepted risk with owner and expiry. Generate an SBOM for release artifacts.

## Change and rollback
Use feature flags for risky capabilities. Keep response execution disabled by default. Database rollback must be planned; when schema rollback is unsafe, use forward-fix and restore strategy. Never roll back a release in a way that silently duplicates response actions.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
