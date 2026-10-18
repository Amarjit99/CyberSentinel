"""Root test configuration and fixtures for CyberSentinel test suite."""

import pytest

from services.persistence.database import init_db


@pytest.fixture(scope="session", autouse=True)
def initialize_test_database():
    """Ensure database tables are initialized before tests execute."""
    init_db()
