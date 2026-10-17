"""CyberSentinel AI — Syslog Source Adapter (RFC 3164 & RFC 5424)"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from packages.common import utc_now
from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ErrorClassification,
    IngestionException,
)

# RFC 5424 regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<proc_id>\S+)\s+"
    r"(?P<msg_id>\S+)"
    r"(?:\s+\[(?P<structured_data>.*?)\])?\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# RFC 3164 regex: <PRI>TIMESTAMP HOSTNAME TAG: MSG
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?:(?P<tag>[A-Za-z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)


def map_syslog_severity(pri_val: int) -> str:
    """Map syslog PRI severity component (0..7) to canonical severity string."""
    syslog_sev = pri_val % 8
    if syslog_sev <= 1:
        return "critical"
    elif syslog_sev in (2, 3):
        return "high"
    elif syslog_sev == 4:
        return "medium"
    elif syslog_sev == 5:
        return "low"
    return "informational"


class SyslogAdapter(BaseConnector):
    """Adapter for ingesting and parsing RFC 3164 and RFC 5424 Syslog messages."""

    def __init__(self, config: Optional[ConnectorConfig] = None) -> None:
        cfg = config or ConnectorConfig(
            connector_id="syslog-adapter-01",
            name="Syslog Stream Ingest",
            source_type="syslog",
        )
        super().__init__(cfg)

    def supported_formats(self) -> List[str]:
        return ["rfc3164", "rfc5424", "raw_syslog"]

    def parse_line(self, line: str) -> Dict[str, Any]:
        """Parse a single syslog message string into a structured raw dictionary."""
        line = line.strip()
        if not line:
            raise IngestionException(
                "Empty syslog line",
                error_code="EMPTY_SYSLOG_LINE",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        # 1. Try RFC 5424
        match_5424 = RFC5424_PATTERN.match(line)
        if match_5424:
            pri = int(match_5424.group("pri"))
            ts_str = match_5424.group("timestamp")
            try:
                # ISO timestamp
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = utc_now()

            return {
                "format": "rfc5424",
                "facility": pri // 8,
                "severity_code": pri % 8,
                "severity": map_syslog_severity(pri),
                "timestamp": ts.astimezone(timezone.utc).isoformat(),
                "hostname": match_5424.group("hostname"),
                "app_name": match_5424.group("app_name"),
                "proc_id": match_5424.group("proc_id"),
                "msg_id": match_5424.group("msg_id"),
                "structured_data": match_5424.group("structured_data"),
                "message": match_5424.group("msg"),
                "raw_text": line,
            }

        # 2. Try RFC 3164
        match_3164 = RFC3164_PATTERN.match(line)
        if match_3164:
            pri = int(match_3164.group("pri"))
            # RFC 3164 dates omit year, default to current year
            ts_raw = match_3164.group("timestamp")
            current_year = utc_now().year
            try:
                parsed_dt = datetime.strptime(f"{current_year} {ts_raw}", "%Y %b %d %H:%M:%S")
                ts = parsed_dt.replace(tzinfo=timezone.utc)
            except Exception:
                ts = utc_now()

            pid_val = match_3164.group("pid")
            return {
                "format": "rfc3164",
                "facility": pri // 8,
                "severity_code": pri % 8,
                "severity": map_syslog_severity(pri),
                "timestamp": ts.isoformat(),
                "hostname": match_3164.group("hostname"),
                "program": match_3164.group("tag") or "unknown",
                "pid": int(pid_val) if pid_val and pid_val.isdigit() else None,
                "message": match_3164.group("msg"),
                "raw_text": line,
            }

        # 3. Unstructured fallback
        return {
            "format": "unstructured_syslog",
            "facility": 1,
            "severity_code": 6,
            "severity": "informational",
            "timestamp": utc_now().isoformat(),
            "hostname": "unknown",
            "message": line,
            "raw_text": line,
        }

    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        """Parse raw syslog payload (single string or list of log lines)."""
        if isinstance(payload, str):
            lines = payload.splitlines()
        elif isinstance(payload, list):
            lines = [str(x) for x in payload]
        else:
            lines = [str(payload)]

        parsed_records = []
        for line in lines:
            if not line.strip():
                continue
            try:
                record = self.parse_line(line)
                self.buffer_event(record)
                parsed_records.append(record)
            except IngestionException as ex:
                self.metrics.errors_permanent += 1
                raise ex
            except Exception as ex:
                self.metrics.errors_permanent += 1
                raise IngestionException(
                    f"Unexpected error parsing syslog line: {ex}",
                    error_code="SYSLOG_PARSE_FAILED",
                    classification=ErrorClassification.PERMANENT,
                    source_id=self.config.connector_id,
                ) from ex

        return parsed_records
