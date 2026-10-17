# Authentication & Authorization (`packages/auth`)

## Purpose
Provides interfaces and models for identity verification, JWT validation, and Role-Based Access Control (RBAC).

## Architecture & Guarantees
- Conforms to **ADR-0004** (Unified 8-Role RBAC Model).
- Enforces strict least privilege across human analysts, security engineers, auditors, and autonomous agents.
- Defines `Principal` and `AuthorizationContext` abstractions without coupling domain logic to web frameworks.
