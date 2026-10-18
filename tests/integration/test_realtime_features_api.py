"""Integration tests for real-time features:
- Stream ingestion API (/api/v1/ingest/stream)
- Event metadata export API (/api/v1/events/export)
- Notification webhook test API (/api/v1/notifications/webhook/test)
- Enterprise OIDC token claims authentication
"""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from packages.auth import RBACRoleEnum, create_access_token


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    token = create_access_token(subject="admin-user", role=RBACRoleEnum.ADMIN)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token(subject="analyst-user", role=RBACRoleEnum.SOC_ANALYST)
    return {"Authorization": f"Bearer {token}"}


def test_stream_ingest_api(client, analyst_headers):
    payload = {
        "client_id": "integration-stream",
        "auto_correlate": True,
        "events": [
            {
                "event_id": "stream-api-evt-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_type": "windows",
                "source_name": "sysmon",
                "event_type": "process_creation",
                "hostname": "srv-finance",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c dir",
                "raw_record": {"cmd": "dir"},
            }
        ],
    }

    resp = client.post("/api/v1/ingest/stream", json=payload, headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_received"] == 1
    assert data["events_ingested"] == 1
    assert "batch_id" in data


def test_event_export_api_jsonl_and_csv(client, analyst_headers):
    # 1. Test JSONL export
    resp_jsonl = client.get("/api/v1/events/export?format=jsonl&limit=10", headers=analyst_headers)
    assert resp_jsonl.status_code == 200
    assert "application/x-ndjson" in resp_jsonl.headers["content-type"]

    # 2. Test CSV export
    resp_csv = client.get("/api/v1/events/export?format=csv&limit=10", headers=analyst_headers)
    assert resp_csv.status_code == 200
    assert "text/csv" in resp_csv.headers["content-type"]
    assert "id,event_time,source_id" in resp_csv.text


def test_notification_webhook_test_api(client, admin_headers):
    payload = {
        "channel": "generic_webhook",
        "title": "Integration Test Alert",
        "message": "Testing real-time outbound alert delivery",
        "severity": "high",
    }
    resp = client.post("/api/v1/notifications/webhook/test", json=payload, headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "dispatched"
    assert "configured_channels" in data


def test_oidc_claims_token_authentication(client):
    # Craft a JWT with enterprise OIDC claims ("groups": ["SOC_ANALYST"])
    import base64
    import hashlib
    import hmac
    import os
    import time
    from uuid import uuid4

    secret = os.getenv("SECRET_KEY", "local_insecure_development_secret_key_minimum_32_chars_long")
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": "okta-analyst-99",
        "email": "analyst99@enterprise.org",
        "groups": ["SOC_ANALYST", "Employees"],
        "jti": uuid4().hex,
        "iat": now,
        "exp": now + 3600,
    }

    def b64url(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode("ascii")

    hdr_b64 = b64url(json.dumps(header).encode("utf-8"))
    pay_b64 = b64url(json.dumps(payload).encode("utf-8"))
    to_sign = f"{hdr_b64}.{pay_b64}".encode("ascii")
    sig = b64url(hmac.new(secret.encode("utf-8"), to_sign, hashlib.sha256).digest())
    token = f"{hdr_b64}.{pay_b64}.{sig}"

    # Use OIDC token against an authenticated endpoint
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/events/export?format=jsonl&limit=5", headers=headers)
    assert resp.status_code == 200
