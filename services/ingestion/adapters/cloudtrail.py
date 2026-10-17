"""CyberSentinel AI — AWS CloudTrail Source Adapter"""

import json
from typing import Any, Dict, List, Optional

from packages.common import utc_now
from services.ingestion.framework import (
    BaseConnector,
    ConnectorConfig,
    ErrorClassification,
    IngestionException,
)


class CloudTrailAdapter(BaseConnector):
    """Adapter for ingesting and parsing AWS CloudTrail JSON audit records."""

    def __init__(self, config: Optional[ConnectorConfig] = None) -> None:
        cfg = config or ConnectorConfig(
            connector_id="cloudtrail-adapter-01",
            name="AWS CloudTrail Ingest",
            source_type="cloudtrail",
        )
        super().__init__(cfg)

    def supported_formats(self) -> List[str]:
        return ["cloudtrail_json", "aws_audit"]

    def parse_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize a single CloudTrail record dictionary."""
        if not isinstance(record, dict):
            raise IngestionException(
                "CloudTrail record must be a JSON dictionary",
                error_code="INVALID_CLOUDTRAIL_TYPE",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        event_name = record.get("eventName")
        event_source = record.get("eventSource")
        if not event_name or not event_source:
            raise IngestionException(
                "Missing required CloudTrail fields: eventName or eventSource",
                error_code="CLOUDTRAIL_SCHEMA_MISMATCH",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        # Extract nested identity attributes safely
        user_identity = record.get("userIdentity") or {}
        principal_id = user_identity.get("principalId")
        user_name = user_identity.get("userName") or principal_id or "unknown"
        user_arn = user_identity.get("arn")
        account_id = user_identity.get("accountId")

        # Map API error codes to severity
        error_code = record.get("errorCode")
        error_message = record.get("errorMessage")
        severity = "medium" if error_code else "informational"
        if error_code in ("AccessDenied", "UnauthorizedOperation"):
            severity = "high"

        return {
            "source_type": "cloud",
            "source_name": "aws_cloudtrail",
            "event_type": f"aws:{event_source}:{event_name}",
            "timestamp": record.get("eventTime") or utc_now().isoformat(),
            "event_id": record.get("eventID"),
            "event_name": event_name,
            "event_source": event_source,
            "aws_region": record.get("awsRegion"),
            "src_ip": record.get("sourceIPAddress"),
            "user_agent": record.get("userAgent"),
            "username": user_name,
            "user_arn": user_arn,
            "account_id": account_id,
            "severity": severity,
            "error_code": error_code,
            "error_message": error_message,
            "request_parameters": record.get("requestParameters") or {},
            "raw_record": record,
        }

    def parse_raw(self, payload: Any) -> List[Dict[str, Any]]:
        """Parse raw CloudTrail payload (JSON string, dict, or list)."""
        data: Any = payload
        if isinstance(payload, (str, bytes)):
            try:
                data = json.loads(payload)
            except Exception as ex:
                self.metrics.errors_permanent += 1
                raise IngestionException(
                    f"Malformed CloudTrail JSON payload: {ex}",
                    error_code="INVALID_JSON",
                    classification=ErrorClassification.PERMANENT,
                    source_id=self.config.connector_id,
                ) from ex

        # Handle AWS Records wrapper format
        if isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                raw_records = data["Records"]
            else:
                raw_records = [data]
        elif isinstance(data, list):
            raw_records = data
        else:
            self.metrics.errors_permanent += 1
            raise IngestionException(
                "CloudTrail payload must be a JSON object or array",
                error_code="INVALID_PAYLOAD_STRUCTURE",
                classification=ErrorClassification.PERMANENT,
                source_id=self.config.connector_id,
            )

        parsed = []
        for item in raw_records:
            norm_rec = self.parse_record(item)
            self.buffer_event(norm_rec)
            parsed.append(norm_rec)

        return parsed
