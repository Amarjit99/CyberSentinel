"""CyberSentinel AI — Outbound Notification Dispatcher Service.

Dispatches real-time security alerts and incident lifecycle notifications
to external systems: Generic Webhooks (with HMAC signatures), Slack, and PagerDuty.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("cybersentinel.notifications")


class NotificationChannel(str, Enum):
    GENERIC_WEBHOOK = "generic_webhook"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"


class NotificationPayload(BaseModel):
    event_type: str = Field(..., description="e.g. alert_created, alert_status, incident_created")
    title: str = Field(..., description="Short summary title")
    message: str = Field(..., description="Descriptive notification message")
    severity: str = Field(default="medium", description="critical, high, medium, low, info")
    detection_id: Optional[str] = None
    incident_id: Optional[str] = None
    recipient_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DeliveryRecord(BaseModel):
    id: str
    channel: str
    url: str
    status_code: Optional[int]
    success: bool
    error: Optional[str] = None
    timestamp: str


class WebhookDispatcher:
    """Thread-safe, non-blocking outbound webhook dispatcher with HMAC signing."""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_NOTIFICATION_URL")
        self.webhook_secret = webhook_secret or os.getenv("WEBHOOK_NOTIFICATION_SECRET")
        self.slack_webhook_url = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        self.pagerduty_routing_key = pagerduty_routing_key or os.getenv("PAGERDUTY_ROUTING_KEY")
        self.timeout = timeout_seconds
        self._history: collections.deque[DeliveryRecord] = collections.deque(maxlen=50)

    @property
    def history(self) -> List[DeliveryRecord]:
        return list(self._history)

    def _sign_payload(self, body_bytes: bytes) -> str:
        if not self.webhook_secret:
            return ""
        return hmac.new(
            self.webhook_secret.encode("utf-8"),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()

    def _format_slack_message(self, payload: NotificationPayload) -> Dict[str, Any]:
        color_map = {
            "critical": "#e01e5a",
            "high": "#e8912d",
            "medium": "#ecb22e",
            "low": "#2eb886",
            "info": "#439fe0",
        }
        color = color_map.get(payload.severity.lower(), "#ecb22e")
        fields = [
            {"title": "Event Type", "value": payload.event_type, "short": True},
            {"title": "Severity", "value": payload.severity.upper(), "short": True},
        ]
        if payload.detection_id:
            fields.append({"title": "Detection ID", "value": payload.detection_id, "short": True})
        if payload.incident_id:
            fields.append({"title": "Incident ID", "value": payload.incident_id, "short": True})

        return {
            "text": f"[{payload.severity.upper()}] {payload.title}",
            "attachments": [
                {
                    "color": color,
                    "title": payload.title,
                    "text": payload.message,
                    "fields": fields,
                    "footer": "CyberSentinel AI SOC",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }

    def _format_pagerduty_event(self, payload: NotificationPayload) -> Dict[str, Any]:
        pd_severity = "warning"
        if payload.severity.lower() in ("critical", "high"):
            pd_severity = "error" if payload.severity.lower() == "high" else "critical"
        elif payload.severity.lower() == "info":
            pd_severity = "info"

        return {
            "routing_key": self.pagerduty_routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"{payload.title}: {payload.message[:100]}",
                "severity": pd_severity,
                "source": "cybersentinel-ai",
                "custom_details": {
                    "event_type": payload.event_type,
                    "detection_id": payload.detection_id,
                    "incident_id": payload.incident_id,
                    **payload.metadata,
                },
            },
        }

    async def dispatch(self, payload: NotificationPayload) -> List[DeliveryRecord]:
        """Dispatch a notification to all configured external channels asynchronously."""
        records: List[DeliveryRecord] = []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # 1. Generic Webhook
            if self.webhook_url:
                rec = await self._send_generic(client, payload)
                records.append(rec)
                self._history.append(rec)

            # 2. Slack Webhook
            if self.slack_webhook_url:
                rec = await self._send_slack(client, payload)
                records.append(rec)
                self._history.append(rec)

            # 3. PagerDuty Events API
            if self.pagerduty_routing_key:
                rec = await self._send_pagerduty(client, payload)
                records.append(rec)
                self._history.append(rec)

        return records

    def dispatch_sync(self, payload: NotificationPayload) -> List[DeliveryRecord]:
        """Synchronous dispatch for non-async callers."""
        records: List[DeliveryRecord] = []
        with httpx.Client(timeout=self.timeout) as client:
            if self.webhook_url:
                raw_json = payload.model_dump_json()
                body_bytes = raw_json.encode("utf-8")
                headers = {"Content-Type": "application/json"}
                sig = self._sign_payload(body_bytes)
                if sig:
                    headers["X-CyberSentinel-Signature"] = f"sha256={sig}"
                try:
                    resp = client.post(self.webhook_url, content=body_bytes, headers=headers)
                    rec = DeliveryRecord(
                        id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                        channel=NotificationChannel.GENERIC_WEBHOOK.value,
                        url=self.webhook_url,
                        status_code=resp.status_code,
                        success=resp.is_success,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                except Exception as e:
                    rec = DeliveryRecord(
                        id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                        channel=NotificationChannel.GENERIC_WEBHOOK.value,
                        url=self.webhook_url,
                        status_code=None,
                        success=False,
                        error=str(e),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    )
                records.append(rec)
                self._history.append(rec)
        return records

    async def _send_generic(self, client: httpx.AsyncClient, payload: NotificationPayload) -> DeliveryRecord:
        raw_json = payload.model_dump_json()
        body_bytes = raw_json.encode("utf-8")
        headers = {"Content-Type": "application/json"}
        sig = self._sign_payload(body_bytes)
        if sig:
            headers["X-CyberSentinel-Signature"] = f"sha256={sig}"

        try:
            resp = await client.post(self.webhook_url, content=body_bytes, headers=headers)  # type: ignore[arg-type]
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.GENERIC_WEBHOOK.value,
                url=self.webhook_url or "",
                status_code=resp.status_code,
                success=resp.is_success,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as e:
            logger.warning("Generic webhook dispatch failed: %s", e)
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.GENERIC_WEBHOOK.value,
                url=self.webhook_url or "",
                status_code=None,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    async def _send_slack(self, client: httpx.AsyncClient, payload: NotificationPayload) -> DeliveryRecord:
        body = self._format_slack_message(payload)
        try:
            resp = await client.post(self.slack_webhook_url, json=body)  # type: ignore[arg-type]
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.SLACK.value,
                url=self.slack_webhook_url or "",
                status_code=resp.status_code,
                success=resp.is_success,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as e:
            logger.warning("Slack webhook dispatch failed: %s", e)
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.SLACK.value,
                url=self.slack_webhook_url or "",
                status_code=None,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    async def _send_pagerduty(self, client: httpx.AsyncClient, payload: NotificationPayload) -> DeliveryRecord:
        body = self._format_pagerduty_event(payload)
        url = "https://events.pagerduty.com/v2/enqueue"
        try:
            resp = await client.post(url, json=body)
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.PAGERDUTY.value,
                url=url,
                status_code=resp.status_code,
                success=resp.is_success,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as e:
            logger.warning("PagerDuty dispatch failed: %s", e)
            return DeliveryRecord(
                id=f"del-{int(datetime.now(timezone.utc).timestamp()*1000)}",
                channel=NotificationChannel.PAGERDUTY.value,
                url=url,
                status_code=None,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )


_global_dispatcher: Optional[WebhookDispatcher] = None


def get_notification_dispatcher() -> WebhookDispatcher:
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = WebhookDispatcher()
    return _global_dispatcher
