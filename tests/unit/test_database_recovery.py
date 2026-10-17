"""Recovery drill tests for database backup helpers."""

import sqlite3

from services.persistence.backup import create_backup, restore_backup, verify_backup


def test_sqlite_backup_verify_and_restore(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"

    connection = sqlite3.connect(source)
    connection.execute("CREATE TABLE recovery_probe (value TEXT NOT NULL)")
    connection.execute("INSERT INTO recovery_probe(value) VALUES ('intact')")
    connection.commit()
    connection.close()

    create_backup(backup, f"sqlite:///{source}")
    assert verify_backup(backup)

    restore_backup(backup, f"sqlite:///{restored}")
    restored_connection = sqlite3.connect(restored)
    value = restored_connection.execute("SELECT value FROM recovery_probe").fetchone()
    restored_connection.close()

    assert value == ("intact",)
