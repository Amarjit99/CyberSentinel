# Normalization Service (`services/normalization`)

## Responsibility
Transforms heterogeneous security telemetry into the strict, 23-field Pydantic v2 `CanonicalEvent` contract defined by **ADR-0005**.

## Validation & Dead Letter Queue (DLQ)
- Normalizers enforce UTC normalization, type coercions, and checksum verification.
- Any event failing canonical validation is routed to the Dead Letter Queue (DLQ) without crashing the pipeline.
