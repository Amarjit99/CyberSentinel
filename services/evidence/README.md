# Evidence Management Service (`services/evidence`)

## Responsibility
Provides verifiable, immutable chain-of-custody tracking for forensic artifacts and investigation evidence.

## Guarantees
- Every evidence item must record a SHA-256 checksum and immutable provenance record.
- Corresponds to the `evidence` entity in PostgreSQL.
