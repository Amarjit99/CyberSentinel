# Observability & Structured Logging (`packages/observability`)

## Purpose
Defines shared tracing, correlation ID, metrics, and structured logging interfaces.

## Guarantees
- Uniform request tracking via `CorrelationContext` (`request_id`, `trace_id`).
- Sanitized log outputs preventing raw token or credential leaks.
- Zero external runtime overhead in core domain logic.
