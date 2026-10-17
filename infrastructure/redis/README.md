# Redis Infrastructure (`infrastructure/redis`)

## Purpose
Redis 7 cluster configuration for ephemeral pub/sub messaging, stream buffering, rate limiting, and distributed locks.

## Storage Role (ADR-0003)
Tier 3 ephemeral coordination and fast buffer for incoming raw ingestion events before normalization and persistence.
