# CyberSentinel AI environment reference

Copy `.env.example` to `.env` for local development. Never use the development
credentials in a deployed environment.

| Variable | Required | Purpose |
|---|---:|---|
| `ENVIRONMENT` | yes | Runtime profile such as `development`, `staging`, or `production` |
| `SECRET_KEY` | yes | Signing key for access tokens; use a secret manager outside local development |
| `DATABASE_URL` | yes | SQLAlchemy database URL |
| `POSTGRES_*` | Compose | PostgreSQL bootstrap credentials |
| `REDIS_URL` | recommended | Redis Streams, rate limits, and coordination |
| `OPENSEARCH_HOST` / `OPENSEARCH_PORT` | optional | Search scale-out configuration; relational event metadata remains authoritative |
| `OPENSEARCH_SNAPSHOT_LOCATION` | snapshot profile | Filesystem repository path mounted into OpenSearch for snapshot backups |
| `OPENSEARCH_SNAPSHOT_REPOSITORY` | snapshot profile | Snapshot repository name; defaults to `cybersentinel` |
| `OPENSEARCH_SNAPSHOT_NAME` | snapshot profile | Snapshot name used by the snapshot/restore CLI |
| `LLM_CACHE_ENABLED` | `false` | Explicit opt-in for bounded, in-memory model-response caching |
| `LLM_CACHE_MAX_ENTRIES` | `128` | Maximum cached model responses per API process |
| `LLM_CACHE_TTL_SECONDS` | `30` | Maximum model-response cache lifetime |
| `ALLOW_DEV_TOKENS` | local only | Enables development token fixtures; set `false` outside local development |
| `ALLOW_DEV_OPERATOR_ROLE` | local only | Enables the development role header; set `false` outside local development |
| `LIVE_RESPONSE_DISABLED` | `true` | Safety invariant; must remain true until a separately approved release gate |
| `DRY_RUN_DEFAULT` | `true` | Makes response proposals non-live by default |

Production deployment must provide distinct credentials, TLS, secret rotation,
network restrictions, and an approved authentication provider. Do not expose
database, Redis, or OpenSearch ports publicly.
