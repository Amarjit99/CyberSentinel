"""CyberSentinel AI — Migration 0006 Evidence Relationships Verification Tests

Verifies:
1. Normal upgrade path from 0005 to 0006 on an isolated real development database.
2. Clean downgrade path back to 0005.
3. Idempotent upgrade against an existing-schema scenario (pre-existing columns/tables).
4. Zero disruption to existing database files or environments.
"""

import os
import tempfile
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config


def test_migration_0006_normal_upgrade_and_downgrade_path():
    """Verify clean upgrade from 0005 to 0006 and rollback to 0005 on an isolated SQLite database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_isolated_0006_normal.db"
        db_url = f"sqlite:///{db_path.as_posix()}"

        old_url = os.environ.get("DATABASE_URL")
        try:
            os.environ["DATABASE_URL"] = db_url
            cfg = Config("infrastructure/alembic.ini")

            # 1. Upgrade to 0005
            command.upgrade(cfg, "0005_event_search_fields")

            # 2. Upgrade to 0006
            command.upgrade(cfg, "0006_evidence_relationships")

            # 3. Verify schema
            engine = sa.create_engine(db_url)
            with engine.connect() as conn:
                inspector = sa.inspect(conn)
                ev_cols = {c["name"] for c in inspector.get_columns("evidence")}
                assert "conflict_group" in ev_cols, "conflict_group must be added to evidence"
                assert "conflict_status" in ev_cols, "conflict_status must be added to evidence"
                assert "evidence_relations" in inspector.get_table_names(), "evidence_relations table must exist"
                rel_cols = {c["name"] for c in inspector.get_columns("evidence_relations")}
                assert "incident_id" in rel_cols
                assert "from_evidence_id" in rel_cols
                assert "to_evidence_id" in rel_cols
                assert "relation_type" in rel_cols
            engine.dispose()

            # 4. Downgrade back to 0005
            command.downgrade(cfg, "0005_event_search_fields")

            # 5. Verify columns and table are removed
            engine_down = sa.create_engine(db_url)
            with engine_down.connect() as conn:
                inspector_down = sa.inspect(conn)
                ev_cols_down = {c["name"] for c in inspector_down.get_columns("evidence")}
                assert "conflict_group" not in ev_cols_down
                assert "conflict_status" not in ev_cols_down
                assert "evidence_relations" not in inspector_down.get_table_names()
            engine_down.dispose()

        finally:
            if old_url is not None:
                os.environ["DATABASE_URL"] = old_url
            else:
                os.environ.pop("DATABASE_URL", None)


def test_migration_0006_existing_schema_idempotency():
    """Verify that migration 0006 handles pre-existing columns and tables without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_isolated_0006_existing.db"
        db_url = f"sqlite:///{db_path.as_posix()}"

        old_url = os.environ.get("DATABASE_URL")
        try:
            os.environ["DATABASE_URL"] = db_url
            cfg = Config("infrastructure/alembic.ini")

            # 1. Upgrade to 0005
            command.upgrade(cfg, "0005_event_search_fields")

            # 2. Simulate pre-existing schema: add conflict_group and evidence_relations manually
            setup_engine = sa.create_engine(db_url)
            with setup_engine.begin() as conn:
                conn.execute(sa.text("ALTER TABLE evidence ADD COLUMN conflict_group VARCHAR(64)"))
                conn.execute(
                    sa.text("""
                    CREATE TABLE evidence_relations (
                        id VARCHAR(64) PRIMARY KEY,
                        incident_id VARCHAR(64) NOT NULL,
                        from_evidence_id VARCHAR(64) NOT NULL,
                        to_evidence_id VARCHAR(64) NOT NULL,
                        relation_type VARCHAR(64) NOT NULL,
                        created_by VARCHAR(64) NOT NULL,
                        created_at TIMESTAMP NOT NULL,
                        FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                        FOREIGN KEY(from_evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                        FOREIGN KEY(to_evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
                    )
                """)
                )
            setup_engine.dispose()

            # 3. Execute upgrade 0006 — defensive inspection must prevent duplicate creation errors
            command.upgrade(cfg, "0006_evidence_relationships")

            # 4. Verify resulting schema is complete and valid
            verify_engine = sa.create_engine(db_url)
            with verify_engine.connect() as conn:
                inspector = sa.inspect(conn)
                ev_cols = {c["name"] for c in inspector.get_columns("evidence")}
                assert "conflict_group" in ev_cols
                assert "conflict_status" in ev_cols
                assert "evidence_relations" in inspector.get_table_names()
            verify_engine.dispose()

        finally:
            if old_url is not None:
                os.environ["DATABASE_URL"] = old_url
            else:
                os.environ.pop("DATABASE_URL", None)


def test_migration_0006_offline_sql_generation():
    """Verify that Alembic generates correct offline DDL for migration 0006."""
    import subprocess
    import sys

    cmd = [
        sys.executable,
        "-m",
        "alembic",
        "-c",
        "infrastructure/alembic.ini",
        "upgrade",
        "0005_event_search_fields:0006_evidence_relationships",
        "--sql",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"Offline SQL generation failed:\n{proc.stderr}"
    assert "conflict_group" in proc.stdout
    assert "conflict_status" in proc.stdout
    assert "evidence_relations" in proc.stdout
