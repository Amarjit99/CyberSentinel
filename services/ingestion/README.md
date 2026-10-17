# Ingestion Service (`services/ingestion`)

## Responsibility
Manages connector lifecycle, raw telemetry ingestion, rate limiting, and raw payload forwarding to buffer queues.

## Ownership & Architecture
- **Phase 2 Scope (`CSAI-P2-INGESTION`):** High-throughput log consumers (Syslog, CloudTrail, CrowdStrike, Zeek).
- **Invariants:** Raw payloads must be cryptographically hashed upon ingest; incoming traffic is strictly unauthenticated and untrusted until validated.
