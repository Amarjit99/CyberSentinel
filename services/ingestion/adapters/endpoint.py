"""CyberSentinel AI — Endpoint Security Telemetry Source Adapter"""

import json
from typing import Any, Dict, List, Optional

from packages.common import utc_now
from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ErrorClassification,
    IngestionException,
)


class EndpointAdapter(BaseConnector):
    """Adapter for ingesting endpoint telemetry records (Sysmon, EDR, Auditd)."""

    def __init__(self, config: Optional[ConnectorConfig] = None) -> None:
        cfg = config or ConnectorConfig(
            connector_id="endpoint-adapter-01",
            name="Endpoint Telemetry Ingest",
            source_type="endpoint",
        )
        super().__init__(cfg)

    def supported_formats(self) -> List[str]:
        return ["endpoint_json", "sysmon_json", "edr_telemetry"]

    def parse_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize endpoint telemetry event into canonical-ready dictionary."""
        if not isinstance(item, dict):
            raise IngestionException(
                "Endpoint record must be a JSON object",
                error_code="INVALID_ENDPOINT_TYPE",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        host_info = item.get("host") or {}
        user_info = item.get("user") or {}
        proc_info = item.get("process") or {}

        # Fallback to top-level keys if nested objects are absent
        host_id = host_info.get("id") or item.get("host_id")
        hostname = host_info.get("name") or item.get("hostname")
        user_id = user_info.get("id") or item.get("user_id")
        username = user_info.get("name") or item.get("username")

        process_name = proc_info.get("name") or item.get("process_name")
        process_id = proc_info.get("id") or item.get("process_id")
        command_line = proc_info.get("command_line") or item.get("command_line")
        parent_process = proc_info.get("parent_name") or item.get("parent_process")
        sha256 = proc_info.get("sha256") or item.get("hash_sha256")

        event_type = item.get("event_type") or "process_creation"

        return {
            "source_type": "windows" if "win" in str(host_id or hostname).lower() else "linux",
            "source_name": item.get("source_name") or "edr_sensor",
            "event_type": event_type,
            "timestamp": item.get("timestamp") or utc_now().isoformat(),
            "host_id": host_id,
            "hostname": hostname,
            "user_id": user_id,
            "username": username,
            "process_name": process_name,
            "process_id": int(process_id) if process_id is not None else None,
            "command_line": command_line,
            "parent_process": parent_process,
            "hash_sha256": sha256,
            "severity": item.get("severity") or "informational",
            "raw_record": item,
        }

    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        """Parse raw endpoint telemetry payload."""
        data: Any = payload
        if isinstance(payload, (str, bytes)):
            try:
                data = json.loads(payload)
            except Exception as ex:
                self.metrics.errors_permanent += 1
                raise IngestionException(
                    f"Malformed Endpoint JSON: {ex}",
                    error_code="INVALID_ENDPOINT_JSON",
                    classification=ErrorClassification.PERMANENT,
                    source_id=self.config.connector_id,
                ) from ex

        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            self.metrics.errors_permanent += 1
            raise IngestionException(
                "Endpoint payload must be a JSON dictionary or list",
                error_code="INVALID_ENDPOINT_PAYLOAD",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        results = []
        for r in records:
            norm = self.parse_item(r)
            self.buffer_event(norm)
            results.append(norm)

        return results
