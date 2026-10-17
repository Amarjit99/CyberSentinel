"""CyberSentinel AI — Zeek Network Security Monitor Source Adapter"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from packages.common import utc_now
from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ErrorClassification,
    IngestionException,
)


def epoch_to_iso(ts_val: Any) -> str:
    """Convert Zeek epoch timestamp (float or int) to UTC ISO 8601 string."""
    if isinstance(ts_val, (int, float)):
        return datetime.fromtimestamp(ts_val, tz=timezone.utc).isoformat()
    elif isinstance(ts_val, str):
        try:
            return datetime.fromtimestamp(float(ts_val), tz=timezone.utc).isoformat()
        except ValueError:
            return ts_val
    return utc_now().isoformat()


class ZeekAdapter(BaseConnector):
    """Adapter for ingesting Zeek JSON network monitoring logs (conn, dns, http, ssl)."""

    def __init__(self, config: Optional[ConnectorConfig] = None) -> None:
        cfg = config or ConnectorConfig(
            connector_id="zeek-adapter-01",
            name="Zeek Network Ingest",
            source_type="zeek",
        )
        super().__init__(cfg)

    def supported_formats(self) -> List[str]:
        return ["zeek_json", "zeek_conn", "zeek_dns", "zeek_http"]

    def parse_entry(self, record: Dict[str, Any], log_type: Optional[str] = None) -> Dict[str, Any]:
        """Normalize a single Zeek JSON log entry."""
        if not isinstance(record, dict):
            raise IngestionException(
                "Zeek record must be a JSON dictionary",
                error_code="INVALID_ZEEK_TYPE",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        inferred_type = log_type
        if not inferred_type:
            if "query" in record or "qtype_name" in record:
                inferred_type = "dns"
            elif "method" in record or "uri" in record:
                inferred_type = "http"
            elif "conn_state" in record or "duration" in record:
                inferred_type = "conn"
            else:
                inferred_type = "network"

        # Network 5-tuple extraction
        src_ip = record.get("id.orig_h") or record.get("orig_h")
        src_port = record.get("id.orig_p") or record.get("orig_p")
        dst_ip = record.get("id.resp_h") or record.get("resp_h")
        dst_port = record.get("id.resp_p") or record.get("resp_p")
        proto = record.get("proto", "tcp").lower()

        # Domain / URL resolution
        domain = record.get("query") or record.get("host")
        url = None
        if inferred_type == "http":
            host = record.get("host", "")
            uri = record.get("uri", "")
            url = f"http://{host}{uri}" if host and uri else uri or None

        return {
            "source_type": "network",
            "source_name": f"zeek_{inferred_type}",
            "event_type": f"network_{inferred_type}",
            "timestamp": epoch_to_iso(record.get("ts")),
            "session_id": record.get("uid"),
            "src_ip": src_ip,
            "src_port": int(src_port) if src_port is not None else None,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port) if dst_port is not None else None,
            "protocol": proto,
            "service": record.get("service"),
            "domain": domain,
            "url": url,
            "duration": record.get("duration"),
            "bytes_in": record.get("orig_bytes"),
            "bytes_out": record.get("resp_bytes"),
            "conn_state": record.get("conn_state"),
            "severity": "informational",
            "raw_record": record,
        }

    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        """Parse raw Zeek payload (JSON lines or JSON array)."""
        entries: List[Dict[str, Any]] = []

        if isinstance(payload, (str, bytes)):
            text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        entries.append(parsed)
                except Exception as ex:
                    self.metrics.errors_permanent += 1
                    raise IngestionException(
                        f"Malformed Zeek JSON line: {ex}",
                        error_code="INVALID_ZEEK_JSON",
                        classification=ErrorClassification.PERMANENT,
                        source_id=self.config.connector_id,
                    ) from ex
        elif isinstance(payload, list):
            entries = payload
        elif isinstance(payload, dict):
            entries = [payload]
        else:
            self.metrics.errors_permanent += 1
            raise IngestionException(
                "Zeek payload must be JSON text or array",
                error_code="INVALID_ZEEK_PAYLOAD",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        results = []
        for entry in entries:
            # Check if entry wrapped with log_type
            log_type = entry.get("log_type") if "log_type" in entry and "record" in entry else None
            actual_record = entry.get("record") if log_type else entry
            if isinstance(actual_record, dict):
                norm = self.parse_entry(actual_record, log_type=log_type)
                self.buffer_event(norm)
                results.append(norm)

        return results
