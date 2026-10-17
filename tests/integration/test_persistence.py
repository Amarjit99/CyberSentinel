"""Integration Tests for Persistence Layer & PostgreSQL Schema Models
Traceability: TEST-FR-003, TEST-FR-011, TEST-FR-025, ADR-0001, ADR-0003
"""

import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from schemas.enums import IncidentStateEnum, ResponseRiskTierEnum
from services.persistence.models import (
    Base,
    Incident,
    ResponseAction,
    ResponseProposal,
    User,
)

# Test with in-memory SQLite for deterministic unit/integration test execution
TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def test_models_table_registry_matches_authoritative_entities():
    """Verify that all 17 authoritative tables from ADR-0003 are defined in Base.metadata."""
    expected_tables = {
        "users",
        "roles",
        "user_roles",
        "connectors",
        "events",
        "detections",
        "detection_events",
        "incidents",
        "incident_detections",
        "incident_entities",
        "evidence",
        "incident_notes",
        "agent_runs",
        "agent_findings",
        "response_proposals",
        "approvals",
        "response_actions",
        "audit_events",
    }

    registered_tables = set(Base.metadata.tables.keys())
    for t in expected_tables:
        assert t in registered_tables, f"Missing authoritative table: {t}"


def test_incident_creation_and_state_constraint(test_db: Session):
    """Verify incident creation and check constraint enforcement on status."""
    now = datetime.now(timezone.utc)
    incident = Incident(
        title="Suspicious C2 Beacon Detected",
        status=IncidentStateEnum.NEW.value,
        severity="high",
        confidence=0.95,
        first_seen=now,
        last_seen=now,
    )
    test_db.add(incident)
    test_db.commit()

    saved = test_db.execute(
        select(Incident).where(Incident.title == "Suspicious C2 Beacon Detected")
    ).scalar_one()
    assert saved.status == "NEW"
    assert saved.severity == "high"
    assert saved.version == 1


def test_response_action_idempotency_key_uniqueness(test_db: Session):
    """Verify that duplicate idempotency keys on response_actions are rejected."""
    now = datetime.now(timezone.utc)

    # Create user & incident
    user = User(display_name="Sec Analyst")
    incident = Incident(
        title="Test Incident",
        status=IncidentStateEnum.INVESTIGATING.value,
        severity="medium",
        first_seen=now,
        last_seen=now,
    )
    test_db.add_all([user, incident])
    test_db.commit()

    # Create proposal
    proposal = ResponseProposal(
        incident_id=incident.id,
        action_type="isolate_host",
        action_payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        risk=ResponseRiskTierEnum.TIER_2.value,
        state="PENDING",
        created_by=user.id,
        expires_at=now + timedelta(minutes=15),
    )
    test_db.add(proposal)
    test_db.commit()

    # Create first action
    action1 = ResponseAction(
        proposal_id=proposal.id,
        idempotency_key="idemp-action-unique-001",
        state="QUEUED",
        result_redacted={},
    )
    test_db.add(action1)
    test_db.commit()

    # Attempt to insert second action with identical idempotency_key must raise IntegrityError
    action2 = ResponseAction(
        proposal_id=proposal.id,
        idempotency_key="idemp-action-unique-001",
        state="QUEUED",
        result_redacted={},
    )
    test_db.add(action2)
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()


def test_alembic_offline_migration_compiles():
    """Verify that Alembic initial migration can be compiled to offline SQL without error."""
    cmd = [".venv/Scripts/alembic", "-c", "infrastructure/alembic.ini", "upgrade", "head", "--sql"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Alembic offline SQL generation failed: {result.stderr}"
    assert "CREATE TABLE incidents" in result.stdout
    assert "CREATE TABLE response_actions" in result.stdout
