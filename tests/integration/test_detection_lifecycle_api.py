from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from apps.api.main import app
from services.persistence.database import SessionLocal
from services.persistence.models import AnalystNotification, Detection

client = TestClient(app)


def test_detection_lifecycle_update_is_audited_and_transitioned():
    detection_id = f"lifecycle-{uuid4()}"
    with SessionLocal() as db:
        db.add(
            Detection(
                id=detection_id,
                rule_id="test.rule",
                rule_version="1.0.0",
                severity="high",
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                status="open",
            )
        )
        db.commit()

    try:
        response = client.patch(
            f"/api/v1/detections/{detection_id}/lifecycle",
            headers={"X-Operator-Role": "SOC_ANALYST"},
            json={
                "status": "acknowledged",
                "assigned_to": "dev-operator",
                "analyst_notes": "Reviewed supporting event evidence.",
                "reason": "Initial analyst review",
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "acknowledged"
        assert body["assigned_to"] == "dev-operator"
        assert body["analyst_notes"] == "Reviewed supporting event evidence."
        notifications = client.get(
            "/api/v1/notifications",
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
        assert notifications.status_code == 200
        assigned = [
            item for item in notifications.json()["notifications"]
            if item["detection_id"] == detection_id
        ]
        assert assigned
        other_role = client.get(
            "/api/v1/notifications",
            headers={"X-API-Key": "different-recipient-key"},
        )
        assert other_role.status_code == 200
        assert all(item["detection_id"] != detection_id for item in other_role.json()["notifications"])
        marked = client.patch(
            f"/api/v1/notifications/{assigned[0]['id']}/read",
            headers={"X-Operator-Role": "SOC_ANALYST"},
        )
        assert marked.status_code == 200

        invalid = client.patch(
            f"/api/v1/detections/{detection_id}/lifecycle",
            headers={"X-Operator-Role": "SOC_ANALYST"},
            json={"status": "closed"},
        )
        assert invalid.status_code == 200
        invalid = client.patch(
            f"/api/v1/detections/{detection_id}/lifecycle",
            headers={"X-Operator-Role": "SOC_ANALYST"},
            json={"status": "escalated"},
        )
        assert invalid.status_code == 409
    finally:
        with SessionLocal() as db:
            detection = db.get(Detection, detection_id)
            if detection:
                db.delete(detection)
                for notification in db.query(AnalystNotification).filter(
                    AnalystNotification.detection_id == detection_id
                ):
                    db.delete(notification)
                db.commit()
