# Canonical Shared Schemas (`packages/schemas`)

## Purpose
This package provides the canonical data contracts across all CyberSentinel AI modular services and API endpoints.

## Structure & Architecture
- **Single Source of Truth:** Core Pydantic v2 schemas are maintained in `schemas/` as defined in Phase 1 (ADR-0005).
- **Package Access:** Domain modules and future service extractions can import contracts via `packages.schemas` or `schemas`.
- **Validation Rules:**
  - 23 core fields conforming to ADR-0005.
  - Strict UTC timestamp normalization.
  - Strict field rejection (`extra="forbid"`).
  - PII and credential sanitization via `CanonicalEvent.to_redacted_dict()`.
