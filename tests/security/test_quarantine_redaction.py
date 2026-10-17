"""CyberSentinel AI — Quarantine Secret Masking & Sanitization Tests
Traceability: ADR-0005, Requirement 2.E, Requirement 2.F
"""

from fastapi.testclient import TestClient

from apps.api.main import app
from services.ingestion.queue import quarantine_manager

client = TestClient(app)


def setup_function():
    quarantine_manager.clear()


def test_quarantine_sanitizes_credentials_in_raw_payload():
    """Verify that credentials and secret tokens in malformed events are masked before quarantine storage."""
    payload_with_secrets = {
        "timestamp": "invalid_date_format_triggers_quarantine",
        "source_type": "auth",
        "username": "victim_user",
        "password": "SuperSecretPassword123!",
        "api_key": "sk-live-abcdef1234567890",
        "nested": {
            "token": "bearer-token-val-999",
            "safe_field": "safe_value",
        },
    }

    # Quarantine event
    q_rec = quarantine_manager.quarantine_event(
        source_type="auth",
        error_reason="Invalid timestamp format",
        raw_payload=payload_with_secrets,
        raw_hash="hash123",
    )

    # 1. Verify in-memory record has secrets redacted
    assert q_rec.raw_payload["password"] == "********"
    assert q_rec.raw_payload["api_key"] == "********"
    assert q_rec.raw_payload["nested"]["token"] == "********"
    assert q_rec.raw_payload["nested"]["safe_field"] == "safe_value"

    # 2. Verify API response from GET /api/v1/events/quarantine does not expose plaintext secrets
    resp = client.get(
        "/api/v1/events/quarantine",
        headers={"X-Operator-Role": "SECURITY_ENGINEER"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["records"]) == 1
    record = data["records"][0]
    raw = record["raw_payload"]
    assert raw["password"] == "********"
    assert raw["api_key"] == "********"
    assert "SuperSecretPassword123!" not in str(data)
    assert "sk-live-abcdef1234567890" not in str(data)
