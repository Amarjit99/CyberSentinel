# CyberSentinel AI — Documentation Pack

This pack contains 31 separate companion documents plus the two governing baseline documents carried forward from the existing project.

## Start here
1. `docs/00-MASTER-REQUIREMENTS-SPECIFICATION.md` — governing product, research, architecture, security, and requirements baseline.
2. `docs/00-PHASE-WISE-IMPLEMENTATION-PLAN.md` — authoritative phase-by-phase build order and acceptance criteria.
3. `docs/05-REQUIREMENTS-SPECIFICATION.md` — requirements index.
4. `docs/08-SYSTEM-ARCHITECTURE.md` — system boundaries and data flow.
5. `docs/12-THREAT-MODEL.md` — threat model and release blockers.
6. `docs/30-IMPLEMENTATION-ROADMAP.md` — condensed build sequence.

## Document list
- `docs/01-PROJECT-VISION.md`
- `docs/02-PROBLEM-STATEMENT.md`
- `docs/03-LITERATURE-REVIEW.md`
- `docs/04-THREAT-LANDSCAPE-2026.md`
- `docs/05-REQUIREMENTS-SPECIFICATION.md`
- `docs/06-FUNCTIONAL-REQUIREMENTS.md`
- `docs/07-NON-FUNCTIONAL-REQUIREMENTS.md`
- `docs/08-SYSTEM-ARCHITECTURE.md`
- `docs/09-DATA-ARCHITECTURE.md`
- `docs/10-AGENT-ARCHITECTURE.md`
- `docs/11-SECURITY-ARCHITECTURE.md`
- `docs/12-THREAT-MODEL.md`
- `docs/13-MITRE-ATTCK-MAPPING.md`
- `docs/14-SIGMA-DETECTION-ARCHITECTURE.md`
- `docs/15-THREAT-INTELLIGENCE.md`
- `docs/16-RAG-ARCHITECTURE.md`
- `docs/17-API-SPECIFICATION.md`
- `docs/18-DATABASE-SCHEMA.md`
- `docs/19-UI-UX-SPECIFICATION.md`
- `docs/20-INCIDENT-LIFECYCLE.md`
- `docs/21-RESPONSE-PLAYBOOKS.md`
- `docs/22-AI-SAFETY-CONTROLS.md`
- `docs/23-DATA-PRIVACY.md`
- `docs/24-TESTING-STRATEGY.md`
- `docs/25-ATTACK-SCENARIOS.md`
- `docs/26-BENCHMARK-DESIGN.md`
- `docs/27-RESEARCH-METHODOLOGY.md`
- `docs/28-DEPLOYMENT-ARCHITECTURE.md`
- `docs/29-DEVOPS-PLAN.md`
- `docs/30-IMPLEMENTATION-ROADMAP.md`
- `docs/31-REFERENCES-AND-SOURCES.md`

## Consistency rules
- The two `00-` files govern when a companion document overlaps with them.
- Companion documents are separate by topic but are not independent sources of truth.
- Requirements and architecture are proposed baselines until implemented and verified.
- Do not describe the platform as production-ready merely because the documentation exists.
- Update linked docs together when schemas, API contracts, permissions, data retention, or response policies change.
- Record major decisions in Architecture Decision Records (ADRs).
- Validate all references and dependency versions before relying on them.

## Initial implementation recommendation
Begin with repository foundation, schema/API contracts, migrations, synthetic event fixtures, deterministic ingestion and detection, incident/evidence workflow, RBAC, and audit. Keep AI integrations read-only and live response disabled until their dedicated test and approval gates pass.

---

## Phase 1 Developer Quickstart

### Prerequisites
- Python 3.12+ (Python 3.13 tested)
- `uv` package manager (recommended) or standard `pip`
- Docker & Docker Compose (optional, for local PostgreSQL/Redis/OpenSearch services)

### 1. Environment Setup
```bash
# Clone and enter workspace
cd CyberSentinel

# Create virtual environment with uv or python venv
uv venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies in editable mode
uv pip install -e ".[dev]"
```

Optional pre-commit hooks:
```bash
pre-commit install
pre-commit run --all-files
```

### 2. Environment Configuration
Copy the template configuration:
```bash
cp .env.example .env
```
*Note: In Phase 1, `LIVE_RESPONSE_DISABLED=true` is strictly enforced.*

### 3. Running Automated Checks
CyberSentinel AI provides a unified developer verification script:
```bash
python scripts/run_checks.py
```
This runs:
1. **Ruff Linter**: `ruff check .`
2. **Mypy Type Checker**: `mypy schemas apps services`
3. **Pytest Test Suite**: `pytest -v` (unit, contract, and persistence tests)
4. **Alembic Migration Verification**: `alembic -c infrastructure/alembic.ini upgrade head --sql`

Run the offline Phase 26 repository security gate separately:
```bash
python scripts/security_gate.py
```
It scans supported source/configuration files (excluding test fixtures and documentation examples) for high-confidence committed secrets and verifies that
the Python and frontend dependency lockfiles are present. Network-based dependency, SAST, and container
scans remain deployment/CI responsibilities and must run before production release.

### 4. Running the Local API
```bash
uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be accessible at:
- Swagger UI: `http://localhost:8000/docs`
- OpenAPI JSON: `http://localhost:8000/openapi.json`
- Health probe: `http://localhost:8000/health`
- Readiness probe: `http://localhost:8000/ready`
- Event Ingest endpoint: `POST http://localhost:8000/api/v1/events`

### 5. Local Infrastructure (Docker Compose)
To launch local backing services (when Docker is installed on host):
```bash
docker compose up -d
```
The Compose profile starts PostgreSQL, Redis, OpenSearch, the API, and the
production-built web shell on loopback-bound ports. OpenSearch is provided for
scale-out experimentation; relational event metadata remains authoritative.

For optional local HTTPS testing, provide deployment-managed certificate files
(`tls.crt` and `tls.key`) under `.secrets/tls` or set `TLS_CERT_DIR`, then run:

```bash
TLS_CERT_DIR=./.secrets/tls docker compose -f compose.yaml -f compose.tls.yaml --profile tls up -d
```

The TLS profile binds HTTPS to `127.0.0.1:3443`; it does not generate or
commit certificates and should not be used as a substitute for production
certificate management.

OpenSearch snapshot operations are explicit and require a mounted filesystem
repository:

```bash
python scripts/opensearch_snapshot.py register --location /snapshots
python scripts/opensearch_snapshot.py create --snapshot daily-2026-10-17
python scripts/opensearch_snapshot.py restore --snapshot daily-2026-10-17 --allow-destructive-restore
```

Model-response caching is disabled by default. If enabled for a controlled
deployment, use `LLM_CACHE_ENABLED=true` together with the bounded capacity and
TTL settings documented in the environment reference.

Additional operational references:
- [Environment reference](docs/ENVIRONMENT-REFERENCE.md)
- [Release checklist](docs/RELEASE-CHECKLIST.md)
- [User and administrator guide](docs/USER-ADMIN-GUIDE.md)
- [API operations guide](docs/API-OPERATIONS-GUIDE.md)
- [Rule authoring and agent permissions](docs/RULE-AUTHORING-AND-AGENT-PERMISSIONS.md)
- [Incident recovery and known limitations](docs/INCIDENT-RECOVERY-AND-LIMITATIONS.md)
- [Demo scenario and benchmark guide](docs/DEMO-SCENARIO-AND-BENCHMARK-GUIDE.md)
- [Research reproducibility record](docs/RESEARCH-REPORT-2026-10-17.md)
- [Deployment and recovery architecture](docs/28-DEPLOYMENT-ARCHITECTURE.md)
- ATT&CK catalog status: `GET /api/v1/attack/catalog` (release version, checksum, and validation gates)
