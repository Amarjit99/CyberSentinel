"""Unit tests for outbound notification dispatcher."""

from services.notifications.dispatcher import (
    NotificationPayload,
    WebhookDispatcher,
)


def test_notification_payload_creation():
    payload = NotificationPayload(
        event_type="alert_created",
        title="Suspicious PowerShell Execution",
        message="Encoded powershell command observed on host-01",
        severity="high",
        detection_id="det-12345",
    )
    assert payload.event_type == "alert_created"
    assert payload.severity == "high"
    assert payload.detection_id == "det-12345"
    assert payload.timestamp is not None


def test_hmac_signature_generation():
    dispatcher = WebhookDispatcher(
        webhook_url="https://example.com/webhook",
        webhook_secret="super-secret-key-123",
    )
    body = b'{"hello":"world"}'
    sig = dispatcher._sign_payload(body)
    assert len(sig) == 64  # sha256 hex digest
    # Verify with standard hmac
    import hashlib
    import hmac
    expected = hmac.new(b"super-secret-key-123", body, hashlib.sha256).hexdigest()
    assert sig == expected


def test_slack_formatting():
    dispatcher = WebhookDispatcher(slack_webhook_url="https://hooks.slack.com/services/test")
    payload = NotificationPayload(
        event_type="incident_escalated",
        title="Ransomware Canary Alert",
        message="Multi-host lateral movement detected",
        severity="critical",
        incident_id="inc-999",
    )
    slack_msg = dispatcher._format_slack_message(payload)
    assert "[CRITICAL] Ransomware Canary Alert" in slack_msg["text"]
    assert slack_msg["attachments"][0]["color"] == "#e01e5a"
    assert len(slack_msg["attachments"][0]["fields"]) >= 2


def test_pagerduty_formatting():
    dispatcher = WebhookDispatcher(pagerduty_routing_key="pd-routing-key-123")
    payload = NotificationPayload(
        event_type="alert_created",
        title="DCSync Attack",
        message="Replication traffic from non-DC host",
        severity="high",
        detection_id="det-dcsync",
    )
    pd_event = dispatcher._format_pagerduty_event(payload)
    assert pd_event["routing_key"] == "pd-routing-key-123"
    assert pd_event["event_action"] == "trigger"
    assert pd_event["payload"]["severity"] == "error"
    assert pd_event["payload"]["custom_details"]["detection_id"] == "det-dcsync"
