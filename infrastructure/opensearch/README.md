# OpenSearch Infrastructure (`infrastructure/opensearch`)

## Purpose
OpenSearch 2.x cluster definitions, index templates, lifecycle management (ILM), and neural search vector index mappings.

## Storage Role (ADR-0003)
Tier 2 indexing for high-volume logs, full-text telemetry search, and vector embeddings for semantic investigation. PostgreSQL remains the transactional source of truth.

## Local bootstrap

After starting Compose, install the event mapping with:

```powershell
.venv\Scripts\python.exe scripts\bootstrap_opensearch.py
```

The template intentionally uses one local shard and no replicas. Production
deployments must set shard/replica counts, authentication, TLS, retention, and
snapshot repositories according to the deployment profile.
