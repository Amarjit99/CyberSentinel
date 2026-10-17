"""Evidence collection and retrieval API tests."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.main import app
from services.persistence.database import get_db
from services.persistence.models import Base, Incident

client = TestClient(app)


def test_evidence_collection_is_append_only_and_role_protected():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(
        Incident(
            id="inc-evidence-api",
            title="Evidence API incident",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
    )
    session.commit()

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        payload = {
            "evidence_type": "log_slice",
            "source_ref": "s3://lab/evidence/001.log",
            "checksum": "sha256:fixture",
            "provenance": {"collector": "test"},
            "classification": "internal",
        }
        denied = client.post(
            "/api/v1/incidents/inc-evidence-api/evidence",
            json=payload,
            headers={"X-Operator-Role": "VIEWER"},
        )
        assert denied.status_code == 403

        created = client.post(
            "/api/v1/incidents/inc-evidence-api/evidence",
            json=payload,
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
        assert created.status_code == 201
        evidence_id = created.json()["id"]
        assert created.json()["immutable"] is True

        retrieved = client.get(
            f"/api/v1/evidence/{evidence_id}",
            headers={"X-Operator-Role": "VIEWER"},
        )
        assert retrieved.status_code == 200
        assert retrieved.json()["checksum"] == "sha256:fixture"
        assert "raw_payload" not in retrieved.json()
    finally:
        app.dependency_overrides.pop(get_db, None)
        session.close()
        engine.dispose()


def test_evidence_relationships_conflicts_and_completeness_are_exposed_as_metadata():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(
        Incident(
            id="inc-evidence-relationships",
            title="Evidence relationship incident",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
    )
    session.commit()

    def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    try:
        headers = {"X-Operator-Role": "SOC_ANALYST"}
        first = client.post(
            "/api/v1/incidents/inc-evidence-relationships/evidence",
            json={
                "evidence_type": "endpoint_log",
                "source_ref": "collector://endpoint/001",
                "checksum": "sha256:first",
                "conflict_group": "timeline-1",
                "conflict_status": "open",
            },
            headers=headers,
        )
        assert first.status_code == 201

        second = client.post(
            "/api/v1/incidents/inc-evidence-relationships/evidence",
            json={
                "evidence_type": "analyst_note",
                "source_ref": "case://note/001",
                "checksum": "sha256:second",
                "related_evidence_ids": [first.json()["id"]],
                "relation_type": "corroborates",
            },
            headers=headers,
        )
        assert second.status_code == 201
        assert second.json()["relationships"][0]["relation_type"] == "corroborates"

        completeness = client.get(
            "/api/v1/incidents/inc-evidence-relationships/evidence/completeness",
            headers={"X-Operator-Role": "VIEWER"},
        )
        assert completeness.status_code == 200
        assert completeness.json()["evidence_count"] == 2
        assert completeness.json()["relationship_count"] == 1
        assert completeness.json()["open_conflict_count"] == 1
        assert completeness.json()["status"] == "complete"
    finally:
        app.dependency_overrides.pop(get_db, None)
        session.close()
        engine.dispose()
