"""Unit Tests for 11-State Incident Lifecycle State Machine and Concurrency Control.
Enforces ADR-0001 lifecycle states, valid/invalid transitions, optimistic locking, and audit trails.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from packages.auth import Principal
from schemas.enums import EventSeverityEnum, IncidentStateEnum, RBACRoleEnum
from services.incidents.lifecycle import (
    IncidentConcurrencyError,
    IncidentLifecycleManager,
    InvalidIncidentTransitionError,
)
from services.persistence.models import AuditEvent, Base, Incident


@pytest.fixture(scope="function")
def test_db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def create_incident(session, incident_id="inc-test-01", status=IncidentStateEnum.NEW, version=1):
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=incident_id,
        title="Test Security Incident",
        severity=EventSeverityEnum.HIGH.value,
        status=status.value,
        version=version,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    session.add(inc)
    session.commit()
    return inc


def test_valid_forward_transitions(test_db_session):
    manager = IncidentLifecycleManager()
    analyst = Principal(id="analyst_1", name="Analyst One", roles=[RBACRoleEnum.SOC_ANALYST])
    manager_user = Principal(id="mgr_1", name="Manager One", roles=[RBACRoleEnum.SOC_MANAGER])

    inc = create_incident(test_db_session, "inc-valid-flow", IncidentStateEnum.NEW, version=1)

    # NEW -> TRIAGE
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.TRIAGE, analyst, expected_version=1)
    assert updated.status == IncidentStateEnum.TRIAGE.value
    assert updated.version == 2

    # TRIAGE -> INVESTIGATING
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.INVESTIGATING, analyst, expected_version=2)
    assert updated.status == IncidentStateEnum.INVESTIGATING.value
    assert updated.version == 3

    # INVESTIGATING -> CONFIRMED
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.CONFIRMED, analyst, expected_version=3)
    assert updated.status == IncidentStateEnum.CONFIRMED.value
    assert updated.version == 4

    # CONFIRMED -> AWAITING_APPROVAL
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.AWAITING_APPROVAL, analyst, expected_version=4)
    assert updated.status == IncidentStateEnum.AWAITING_APPROVAL.value
    assert updated.version == 5

    # AWAITING_APPROVAL -> CONTAINMENT (requires SOC_MANAGER or ADMIN)
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.CONTAINMENT, manager_user, expected_version=5)
    assert updated.status == IncidentStateEnum.CONTAINMENT.value
    assert updated.version == 6

    # CONTAINMENT -> ERADICATION
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.ERADICATION, manager_user, expected_version=6)
    assert updated.status == IncidentStateEnum.ERADICATION.value
    assert updated.version == 7

    # ERADICATION -> RECOVERY
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.RECOVERY, manager_user, expected_version=7)
    assert updated.status == IncidentStateEnum.RECOVERY.value
    assert updated.version == 8

    # RECOVERY -> CLOSED
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.CLOSED, manager_user, expected_version=8)
    assert updated.status == IncidentStateEnum.CLOSED.value
    assert updated.version == 9

    # CLOSED -> LESSONS_LEARNED
    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.LESSONS_LEARNED, manager_user, expected_version=9)
    assert updated.status == IncidentStateEnum.LESSONS_LEARNED.value
    assert updated.version == 10

    # Verify audit logs
    audits = test_db_session.query(AuditEvent).filter_by(object_id=inc.id).all()
    assert len(audits) == 9


def test_reopen_closed_incident(test_db_session):
    manager = IncidentLifecycleManager()
    mgr = Principal(id="mgr_1", name="Manager One", roles=[RBACRoleEnum.SOC_MANAGER])
    analyst = Principal(id="analyst_1", name="Analyst One", roles=[RBACRoleEnum.SOC_ANALYST])

    inc = create_incident(test_db_session, "inc-reopen", IncidentStateEnum.CLOSED, version=1)

    # CLOSED -> REOPENED
    reopened = manager.transition(
        test_db_session,
        inc.id,
        IncidentStateEnum.REOPENED,
        mgr,
        expected_version=1,
        reason="New correlated alerts emerged",
    )
    assert reopened.status == IncidentStateEnum.REOPENED.value
    assert reopened.version == 2

    # REOPENED -> INVESTIGATING
    investigating = manager.transition(
        test_db_session,
        inc.id,
        IncidentStateEnum.INVESTIGATING,
        analyst,
        expected_version=2,
    )
    assert investigating.status == IncidentStateEnum.INVESTIGATING.value


def test_invalid_transition_rejected(test_db_session):
    manager = IncidentLifecycleManager()
    analyst = Principal(id="analyst_1", name="Analyst One", roles=[RBACRoleEnum.SOC_ANALYST])

    inc = create_incident(test_db_session, "inc-invalid", IncidentStateEnum.NEW, version=1)

    # NEW -> CONTAINMENT is illegal
    with pytest.raises(InvalidIncidentTransitionError, match="Illegal transition"):
        manager.transition(test_db_session, inc.id, IncidentStateEnum.CONTAINMENT, analyst, expected_version=1)

    # Verify state remains NEW and version remains 1
    refreshed = test_db_session.get(Incident, inc.id)
    assert refreshed.status == IncidentStateEnum.NEW.value
    assert refreshed.version == 1


def test_optimistic_concurrency_conflict(test_db_session):
    manager = IncidentLifecycleManager()
    analyst = Principal(id="analyst_1", name="Analyst One", roles=[RBACRoleEnum.SOC_ANALYST])

    inc = create_incident(test_db_session, "inc-conflict", IncidentStateEnum.NEW, version=2)

    # Expected version 1 when actual version is 2
    with pytest.raises(IncidentConcurrencyError, match="version mismatch"):
        manager.transition(test_db_session, inc.id, IncidentStateEnum.TRIAGE, analyst, expected_version=1)


def test_sensitive_transition_permission_enforcement(test_db_session):
    manager = IncidentLifecycleManager()
    # Analyst lacks SOC_MANAGER or ADMIN role for CONTAINMENT
    analyst = Principal(id="analyst_1", name="Analyst One", roles=[RBACRoleEnum.SOC_ANALYST])

    inc = create_incident(test_db_session, "inc-sensitive", IncidentStateEnum.AWAITING_APPROVAL, version=1)

    with pytest.raises(PermissionError, match="Required roles"):
        manager.transition(test_db_session, inc.id, IncidentStateEnum.CONTAINMENT, analyst, expected_version=1)



def test_live_response_disabled_during_containment(test_db_session):
    """Verify separation of concerns: entering CONTAINMENT state does not invoke live containment."""
    manager = IncidentLifecycleManager()
    mgr = Principal(id="mgr_1", name="Manager One", roles=[RBACRoleEnum.SOC_MANAGER])

    inc = create_incident(test_db_session, "inc-no-live", IncidentStateEnum.AWAITING_APPROVAL, version=1)

    updated = manager.transition(test_db_session, inc.id, IncidentStateEnum.CONTAINMENT, mgr, expected_version=1)
    assert updated.status == IncidentStateEnum.CONTAINMENT.value

    # Check that no live response actions were created in the database
    from services.persistence.models import ResponseAction
    actions = test_db_session.query(ResponseAction).all()
    assert len(actions) == 0
