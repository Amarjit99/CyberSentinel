"""Integration Tests for FastAPI Incident and Correlation Endpoints.
Tests API contracts, RBAC authorization, pagination, transitions, notes, and timeline.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from schemas.enums import EventSeverityEnum, IncidentStateEnum
from services.persistence.database import get_db
from services.persistence.models import (
    AuditEvent,
    Base,
    Detection,
    Incident,
    IncidentDetection,
)

# Setup test DB with StaticPool so all connections share the same memory instance
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

ANALYST_HEADERS = {"X-Operator-Role": "SOC_ANALYST"}
MANAGER_HEADERS = {"X-Operator-Role": "SOC_MANAGER"}
DET_ENG_HEADERS = {"X-Operator-Role": "DETECTION_ENGINEER"}
ADMIN_HEADERS = {"X-Operator-Role": "ADMIN"}
VIEWER_HEADERS = {"X-Operator-Role": "VIEWER"}


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.pop(get_db, None)



def create_test_incident(incident_id="inc-api-test-01", status=IncidentStateEnum.NEW, version=1):
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    inc = Incident(
        id=incident_id,
        title="Test Incident for API",
        severity=EventSeverityEnum.HIGH.value,
        status=status.value,
        version=version,
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db.add(inc)
    db.commit()
    db.close()
    return incident_id


def test_list_correlation_rules_endpoint():
    res = client.get("/api/v1/correlation/rules", headers=ANALYST_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "rules_count" in data
    assert isinstance(data["rules"], list)


def test_reload_correlation_rules_endpoint():
    # Analyst cannot reload rules (requires DETECTION_ENGINEER or ADMIN)
    res_forbidden = client.post("/api/v1/correlation/rules/reload", headers=ANALYST_HEADERS)
    assert res_forbidden.status_code == 403

    # Detection engineer can reload
    res = client.post("/api/v1/correlation/rules/reload", headers=DET_ENG_HEADERS)
    assert res.status_code == 200
    assert res.json()["status"] in ("success", "skipped")


def test_list_and_get_incidents():
    create_test_incident("inc-01", IncidentStateEnum.NEW)
    create_test_incident("inc-02", IncidentStateEnum.TRIAGE)

    # List all
    res = client.get("/api/v1/incidents", headers=ANALYST_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert len(data["incidents"]) == 2

    # Filter by status
    res_filtered = client.get("/api/v1/incidents?status=TRIAGE", headers=ANALYST_HEADERS)
    assert res_filtered.status_code == 200
    assert res_filtered.json()["count"] == 1
    assert res_filtered.json()["incidents"][0]["id"] == "inc-02"

    # Get single detail
    res_detail = client.get("/api/v1/incidents/inc-01", headers=ANALYST_HEADERS)
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == "inc-01"
    assert res_detail.json()["status"] == "NEW"

    # 404 for nonexistent
    res_not_found = client.get("/api/v1/incidents/inc-nonexistent", headers=ANALYST_HEADERS)
    assert res_not_found.status_code == 404


def test_incident_transition_lifecycle_api():
    inc_id = create_test_incident("inc-transition", IncidentStateEnum.NEW, version=1)

    # 1. Valid transition: NEW -> TRIAGE
    res1 = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "TRIAGE", "version": 1, "reason": "Triage started"},
        headers=ANALYST_HEADERS,
    )
    assert res1.status_code == 200
    assert res1.json()["status"] == "TRIAGE"
    assert res1.json()["version"] == 2

    # 2. Concurrency conflict (trying with stale version 1)
    res_conflict = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "INVESTIGATING", "version": 1},
        headers=ANALYST_HEADERS,
    )
    assert res_conflict.status_code == 409

    # 3. Invalid transition: TRIAGE -> CONTAINMENT (illegal leap)
    res_invalid = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"to_state": "CONTAINMENT", "version": 2},
        headers=MANAGER_HEADERS,
    )
    assert res_invalid.status_code == 400


def test_add_note_and_view_timeline_api():
    inc_id = create_test_incident("inc-note-timeline", IncidentStateEnum.NEW, version=1)

    # Add Note
    res_note = client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"note": "Initial investigation note with password=secret_pass_123"},
        headers=ANALYST_HEADERS,
    )
    assert res_note.status_code == 200
    assert "secret_pass_123" not in res_note.json()["note"]
    assert "[REDACTED_SECRET]" in res_note.json()["note"]

    # View Timeline
    res_tl = client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=ANALYST_HEADERS)
    assert res_tl.status_code == 200
    data = res_tl.json()
    assert data["incident_id"] == inc_id
    assert data["timeline_events_count"] >= 2


def test_incident_export_is_authorized_audited_and_redacted():
    inc_id = create_test_incident("inc-export", IncidentStateEnum.NEW, version=1)

    denied = client.get(f"/api/v1/incidents/{inc_id}/export", headers=VIEWER_HEADERS)
    assert denied.status_code == 403

    response = client.get(f"/api/v1/incidents/{inc_id}/export", headers=ANALYST_HEADERS)
    assert response.status_code == 200
    assert response.headers["content-disposition"].endswith(f'incident-{inc_id}.json"')
    payload = response.json()
    assert payload["report_version"] == "1.0.0"
    assert payload["incident"]["id"] == inc_id
    assert "raw_payload" not in payload


def test_incident_merge_and_split_are_manager_only_and_versioned():
    source_id = create_test_incident("inc-merge-source", IncidentStateEnum.NEW, version=1)
    target_id = create_test_incident("inc-merge-target", IncidentStateEnum.NEW, version=1)
    db = TestingSessionLocal()
    now = datetime.now(timezone.utc)
    detection = Detection(
        id="det-merge-1",
        rule_id="rule-1",
        rule_version="1",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db.add(detection)
    db.add(
        IncidentDetection(
            incident_id=source_id,
            detection_id=detection.id,
            link_reason="test",
            linked_by="test",
            linked_at=now,
        )
    )
    db.commit()
    db.close()

    denied = client.post(
        f"/api/v1/incidents/{source_id}/merge",
        json={
            "target_incident_id": target_id,
            "source_version": 1,
            "target_version": 1,
            "reason": "viewer cannot merge",
        },
        headers=ANALYST_HEADERS,
    )
    assert denied.status_code == 403

    merged = client.post(
        f"/api/v1/incidents/{source_id}/merge",
        json={
            "target_incident_id": target_id,
            "source_version": 1,
            "target_version": 1,
            "reason": "same case",
        },
        headers=MANAGER_HEADERS,
    )
    assert merged.status_code == 200
    assert merged.json()["source_status"] == "CLOSED"

    split = client.post(
        f"/api/v1/incidents/{target_id}/split",
        json={
            "detection_ids": ["det-merge-1"],
            "evidence_ids": [],
            "source_version": 2,
            "title": "Separated detection case",
            "reason": "distinct activity",
        },
        headers=MANAGER_HEADERS,
    )
    assert split.status_code == 201
    child_id = split.json()["child_incident_id"]
    db = TestingSessionLocal()
    assert db.get(IncidentDetection, (child_id, "det-merge-1")) is not None
    assert db.query(AuditEvent).filter(AuditEvent.action.in_(["incident:merge", "incident:split"])).count() == 2
    db.close()
