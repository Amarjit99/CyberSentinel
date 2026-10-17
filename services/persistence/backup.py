"""Database backup and restore helpers for controlled recovery exercises."""

import os
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Sequence

from sqlalchemy.engine import URL, make_url


class BackupError(RuntimeError):
    """Raised when a backup or restore operation cannot be completed safely."""


def _database_url(database_url: str | None = None) -> URL:
    configured_url = database_url or os.getenv("DATABASE_URL") or "sqlite:///./cybersentinel_dev.db"
    return make_url(configured_url)


def _run_command(command: Sequence[str], *, env: dict[str, str] | None = None) -> None:
    try:
        result = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    except OSError as exc:
        raise BackupError(f"Required database utility is unavailable: {command[0]}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown database utility error"
        raise BackupError(detail)


def create_backup(destination: str | Path, database_url: str | None = None) -> Path:
    """Create a consistent SQLite or PostgreSQL backup without logging credentials."""
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    url = _database_url(database_url)

    if url.get_backend_name() == "sqlite":
        source = Path(url.database or "")
        if not source.is_absolute():
            source = Path.cwd() / source
        if not source.is_file():
            raise BackupError(f"SQLite database does not exist: {source}")
        source_connection = sqlite3.connect(str(source))
        target_connection = sqlite3.connect(str(target))
        try:
            source_connection.backup(target_connection)
        finally:
            target_connection.close()
            source_connection.close()
        return target

    if url.get_backend_name() == "postgresql":
        env = os.environ.copy()
        if url.password:
            env["PGPASSWORD"] = url.password
        command = [
            "pg_dump",
            "--format=custom",
            "--no-owner",
            "--file",
            str(target),
            "--host",
            url.host or "localhost",
            "--port",
            str(url.port or 5432),
            "--username",
            url.username or "",
            url.database or "",
        ]
        _run_command(command, env=env)
        return target

    raise BackupError(f"Unsupported database backend: {url.get_backend_name()}")


def restore_backup(
    source: str | Path,
    database_url: str | None = None,
    *,
    allow_overwrite: bool = False,
) -> None:
    """Restore a backup; destructive targets require explicit overwrite permission."""
    backup = Path(source)
    if not backup.is_file():
        raise BackupError(f"Backup file does not exist: {backup}")
    url = _database_url(database_url)

    if url.get_backend_name() == "sqlite":
        target = Path(url.database or "")
        if not target.is_absolute():
            target = Path.cwd() / target
        if target.exists() and not allow_overwrite:
            raise BackupError("Refusing to overwrite an existing SQLite database without --overwrite")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(backup, target)
        return

    if url.get_backend_name() == "postgresql":
        if not allow_overwrite:
            raise BackupError("PostgreSQL restore requires explicit overwrite permission")
        env = os.environ.copy()
        if url.password:
            env["PGPASSWORD"] = url.password
        command = [
            "pg_restore",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--host",
            url.host or "localhost",
            "--port",
            str(url.port or 5432),
            "--username",
            url.username or "",
            "--dbname",
            url.database or "",
            str(backup),
        ]
        _run_command(command, env=env)
        return

    raise BackupError(f"Unsupported database backend: {url.get_backend_name()}")


def verify_backup(backup: str | Path) -> bool:
    """Verify that a backup is readable and contains a database schema."""
    path = Path(backup)
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        connection = sqlite3.connect(str(path))
        tables = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'"
        ).fetchone()
        connection.close()
        return bool(tables and tables[0] > 0)
    except sqlite3.DatabaseError:
        return False
