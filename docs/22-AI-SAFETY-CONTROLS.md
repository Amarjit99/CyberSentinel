# 22 — AI Safety Controls

## Control hierarchy
The application policy engine, authorization service, schemas, budgets, and approval workflow are authoritative. Model output is untrusted input and cannot grant itself permissions.

## Required controls
- Task-specific system instructions and versioned templates.
- Strict structured output schemas with rejection and bounded retry on invalid output.
- Per-agent tool allowlists and least-privilege service identities.
- Maximum steps, time, tokens/cost, tool calls, and output size.
- Evidence references required for material claims.
- Separate observed facts, hypotheses, recommendations, and analyst decisions.
- Prompt-injection defenses for logs, tickets, documents, and intelligence.
- Sensitive-data minimization and redaction before model calls.
- Provider allowlist, configuration controls, and documented retention/training policy.
- Circuit breaker, timeout, cancellation, and deterministic fallback.
- Audit record for model/provider/version, template version, tools, outputs, errors, and reviewer disposition.

## Prohibited behavior
Agents must not execute arbitrary shell/code, query arbitrary URLs, change their own permissions, access unrestricted databases, retrieve secrets, disable controls, execute response actions without authorization, or treat text in evidence as higher-priority instructions.

## Human review
Require human approval for high-impact response, uncertain or conflicting findings with material consequence, policy exceptions, and any externally visible action. Show the exact scope and consequences before approval.

## Testing
Maintain adversarial fixtures for direct and indirect prompt injection, poisoned retrieved content, malformed JSON, hallucinated evidence IDs, secret extraction, tool argument injection, repeated tool loops, budget exhaustion, provider outage, and conflicting evidence.

## Release-blocking thresholds
Zero unauthorized tool/action calls in the release test suite; zero unredacted canary-secret disclosures; all material findings schema-valid and evidence-linked or explicitly marked ungrounded; deterministic workflows remain functional during model outage.

## Document control
- **Project:** CyberSentinel AI — Agentic Security Operations & Threat Investigation Platform
- **Status:** Proposed engineering baseline; implementation and operational readiness must be demonstrated by tests.
- **Research baseline:** September 2026 (verify source freshness and dependency versions before implementation).
- **Governing documents:** `00-MASTER-REQUIREMENTS-SPECIFICATION.md` and `00-PHASE-WISE-IMPLEMENTATION-PLAN.md`.
- **Core safety principle:** deterministic controls establish facts; AI assists investigation; humans retain authority over consequential actions.

## Normative language
**MUST** denotes a release-blocking requirement; **SHOULD** denotes a strong default with documented exceptions; **MAY** denotes an optional capability. This document describes intended behavior, not a claim that the feature already exists.
