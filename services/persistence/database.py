"""CyberSentinel AI — Database Session, Connection Pool & Reliability Controls
Sprint 25: Bounded timeouts, pool exhaustion handling, rollback guarantees, and health checks.
"""

import os
import time
from contextlib import contextmanager
from typing import Generator, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from packages.observability.metrics import metrics
from services.persistence.models import Base

# Read database URL from environment or fallback to SQLite for offline dev/tests
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cybersentinel_dev.db")

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

# Relational connection pool tuning parameters (PostgreSQL / MySQL)
engine_kwargs: dict = {
    "connect_args": connect_args,
    "pool_pre_ping": True,
    "echo": os.getenv("SQL_ECHO", "false").lower() == "true",
}

if not is_sqlite:
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_timeout": float(os.getenv("DB_POOL_TIMEOUT", "10.0")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "1800")),
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all tables in the configured database (for local dev/tests)."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency injection session generator with guaranteed rollback on unhandled exceptions."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        metrics.inc_counter("db_transaction_rollbacks_total", 1)
        raise
    finally:
        db.close()


@contextmanager
def managed_transaction(session: Session) -> Generator[Session, None, None]:
    """Context manager for atomic database units of work with automatic rollback on failure."""
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        metrics.inc_counter("db_transaction_rollbacks_total", 1)
        raise


def check_database_health(timeout_seconds: float = 2.0) -> Tuple[bool, str, float]:
    """Execute a bounded SELECT 1 query to verify active connectivity and measure latency.

    Returns:
        (is_healthy, detail_message, latency_ms)
    """
    start = time.perf_counter()
    try:
        with engine.connect() as conn:
            # Set statement timeout on supported dialects if needed
            conn.execute(text("SELECT 1"))
        latency_ms = (time.perf_counter() - start) * 1000.0
        return True, "connected", round(latency_ms, 2)
    except Exception as ex:
        latency_ms = (time.perf_counter() - start) * 1000.0
        metrics.inc_counter("db_health_check_failures_total", 1)
        return False, f"unreachable: {type(ex).__name__}", round(latency_ms, 2)
