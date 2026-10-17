"""Security Tests for Phase 4 Correlation Engine & Incident Case Management.
Tests RBAC enforcement, unauthorized transition rejection, injection attempts in notes,
secret redaction, and strict enforcement of LIVE_RESPONSE_DISABLED=true.
"""

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import EventSeverityEnum, IncidentStateEnum
from services.persistence.database import get_db
from services.persistence.models import Base, Incident, ResponseAction

# Setup test DB with StaticPool
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)



def create_security_test_incident(incident_id="inc-sec-01", status=IncidentStateEnum.AWAITING_APPROVAL):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=incident_id,
        title="Security Test Incident",
        severity=EventSeverityEnum.HIGH.value,
        status=status.value,
        version=1,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db.add(inc)
    db.commit()
    db.close()
    return incident_id


def test_unauthenticated_requests_rejected():
    """Verify unauthenticated requests cannot access incident or correlation endpoints."""
    # List incidents without header
    res = client.get("/api/v1/incidents")
    assert res.status_code == 401

    # List correlation rules without header
    res_corr = client.get("/api/v1/correlation/rules")
    assert res_corr.status_code == 401


def test_unauthorized_role_transition_rejected():
    """Verify VIEWER or SOC_ANALYST cannot trigger sensitive transitions (e.g. CONTAINMENT)."""
    inc_id = create_security_test_incident("inc-rbac-01", IncidentStateEnum.AWAITING_APPROVAL)

    # 1. Viewer role attempt -> 403 Forbidden by endpoint role guard
    res_viewer = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "CONTAINMENT", "version": 1},
        headers={"X-Operator-Role": "VIEWER"},
    )
    assert res_viewer.status_code == 403

    # 2. Analyst role attempt to CONTAINMENT -> 403 Forbidden by lifecycle manager sensitive role policy
    res_analyst = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "CONTAINMENT", "version": 1},
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res_analyst.status_code == 403


def test_credential_and_token_redaction_in_notes():
    """Verify secrets, passwords, and bearer tokens are automatically redacted in analyst notes."""
    inc_id = create_security_test_incident("inc-redact-01", IncidentStateEnum.NEW)

    malicious_payload = (
        "Found leaked credentials: password=P@ssw0rd123! "
        "and Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret "
        "and api_key: ak_live_998877665544"
    )

    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"note": malicious_payload},
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200
    saved_note = res.json()["note"]

    # Verify secrets are not stored in plaintext
    assert "P@ssw0rd123!" not in saved_note
    assert "ak_live_998877665544" not in saved_note
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret" not in saved_note
    assert "[REDACTED_SECRET]" in saved_note


def test_injection_attempt_in_notes_sanitized():
    """Verify SQL injection and XSS payloads in notes do not execute or corrupt database."""
    inc_id = create_security_test_incident("inc-inj-01", IncidentStateEnum.NEW)

    injection_note = "'; DROP TABLE incidents; <script>alert('xss')</script> --"

    res = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"note": injection_note},
        headers={"X-Operator-Role": "SOC_ANALYST"},
    )
    assert res.status_code == 200

    # Ensure table 'incidents' is intact
    res_check = client.get(f"/api/v1/incidents/{inc_id}", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert res_check.status_code == 200
    assert res_check.json()["id"] == inc_id


def test_pagination_bounds_enforced():
    """Verify limit parameter is bounded between 1 and 100."""
    # Limit too large
    res_large = client.get("/api/v1/incidents?limit=500", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert res_large.status_code == 422

    # Limit zero or negative
    res_zero = client.get("/api/v1/incidents?limit=0", headers={"X-Operator-Role": "SOC_ANALYST"})
    assert res_zero.status_code == 422


def test_live_response_disabled_enforcement():
    """Verify LIVE_RESPONSE_DISABLED=true remains enforced and CONTAINMENT transition executes NO actions."""
    assert os.getenv("LIVE_RESPONSE_DISABLED", "true").lower() == "true"

    inc_id = create_security_test_incident("inc-contain-safe", IncidentStateEnum.AWAITING_APPROVAL)

    # Manager transitions incident to CONTAINMENT
    res = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "CONTAINMENT", "version": 1, "reason": "Approved containment workflow"},
        headers={"X-Operator-Role": "SOC_MANAGER"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "CONTAINMENT"

    # Verify ZERO live response actions were created or executed
    db = TestingSessionLocal()
    actions = db.query(ResponseAction).all()
    assert len(actions) == 0
    db.close()
