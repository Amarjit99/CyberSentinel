# Deterministic Policy Evaluation (`packages/policy`)

## Purpose
Enforces non-negotiable policy constraints, approval gating, and response risk rules deterministically.

## Architecture
- Conforms to **ADR-0006** (Response Risk Tiering & Dual Authorization).
- No AI model is permitted to bypass or relax policy rules.
- Computes required approver roles and approval counts based on evaluated risk tiers:
  - **Tier 0:** Automated execution allowed (read-only/enrichment).
  - **Tier 1:** Single responder approval.
  - **Tier 2:** SOC Lead / Security Engineer approval.
  - **Tier 3:** Dual authorization required.
