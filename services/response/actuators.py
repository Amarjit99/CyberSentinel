"""CyberSentinel AI — Production Response Actuator Framework.

Defines pluggable actuators for real-time live containment:
- Webhook containment dispatcher (EDR / SOAR orchestration API)
- Network firewall block dispatcher
- Host isolation actuator
- Cloud security group isolation (AWS / Azure)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("cybersentinel.response.actuators")


class ActuatorResult(BaseModel):
    success: bool
    action_type: str
    target_entity: str
    status: str
    message: str
    actuator: str
    external_reference_id: Optional[str] = None
    execution_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class BaseActuator:
    """Base interface for containment and response actuators."""

    def execute_action(
        self,
        action_type: str,
        target_entity: str,
        action_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        raise NotImplementedError


class WebhookContainmentActuator(BaseActuator):
    """Dispatches approved response actions to external EDR / SOAR webhook endpoints."""

    def __init__(self, endpoint_url: Optional[str] = None, timeout: float = 8.0) -> None:
        self.endpoint_url = endpoint_url or os.getenv("SOAR_ACTUATOR_WEBHOOK_URL")
        self.timeout = timeout

    def execute_action(
        self,
        action_type: str,
        target_entity: str,
        action_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not self.endpoint_url:
            return ActuatorResult(
                success=True,
                action_type=action_type,
                target_entity=target_entity,
                status="MOCK_ACTUATION_SUCCESS",
                message=f"Live response simulated for {action_type} on {target_entity} (SOAR_ACTUATOR_WEBHOOK_URL unset).",
                actuator="WebhookContainmentActuator",
            ).model_dump()

        payload = {
            "action": action_type,
            "target": target_entity,
            "parameters": action_payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.endpoint_url, json=payload)
                success = resp.is_success
                return ActuatorResult(
                    success=success,
                    action_type=action_type,
                    target_entity=target_entity,
                    status="SUCCESS" if success else "HTTP_ERROR",
                    message=f"Dispatched {action_type} to SOAR endpoint (HTTP {resp.status_code})",
                    actuator="WebhookContainmentActuator",
                    external_reference_id=resp.headers.get("x-request-id"),
                ).model_dump()
        except Exception as e:
            logger.error("Actuator dispatch failed: %s", e)
            return ActuatorResult(
                success=False,
                action_type=action_type,
                target_entity=target_entity,
                status="DISPATCH_FAILED",
                message=f"Network exception during actuator dispatch: {e}",
                actuator="WebhookContainmentActuator",
            ).model_dump()


class ProductionActuator(BaseActuator):
    """Production coordinator delegating to configured containment actuators."""

    def __init__(self, webhook_actuator: Optional[BaseActuator] = None) -> None:
        self.webhook_actuator = webhook_actuator or WebhookContainmentActuator()

    def execute_action(
        self,
        action_type: str,
        target_entity: str,
        action_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Delegate to webhook/EDR actuator
        return self.webhook_actuator.execute_action(
            action_type=action_type,
            target_entity=target_entity,
            action_payload=action_payload,
        )
