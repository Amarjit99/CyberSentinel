# PostgreSQL Infrastructure (`infrastructure/postgres`)

## Purpose
PostgreSQL 16 transactional database configuration, extensions (`pgcrypto`, `uuid-ossp`), performance tuning, and schema migration links.

## Schema Ownership & Migrations
- Authoritative transactional database for all 17 core entities (ADR-0003).
- Migrations are driven by Alembic located in `infrastructure/alembic/` with configuration in `infrastructure/alembic.ini`.
