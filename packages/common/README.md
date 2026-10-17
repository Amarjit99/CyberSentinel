# Common Shared Utilities (`packages/common`)

## Purpose
Provides zero-dependency or lightweight core utilities across CyberSentinel AI.

## Utilities Provided
- `utc_now()`: Canonical timezone-aware current UTC time generator.
- `compute_sha256()`: Cryptographic hashing for evidence checksums and payload lineage.
- `compute_payload_hash()`: Deterministic JSON serialization and hashing for action idempotency keys and approvals.
