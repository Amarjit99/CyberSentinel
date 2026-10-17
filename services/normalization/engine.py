"""CyberSentinel AI — Production Event Normalization Engine

Normalizes parsed telemetry records into canonical Pydantic v2 CanonicalEvent models (ADR-0005).
Applies UTC normalization, cryptographic hashing, provenance tagging, and quarantine gating.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import ValidationError

from packages.common import compute_payload_hash, utc_now
from packages.observability import metrics
from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum


class NormalizationResult:
    """Outcome of attempting to normalize a raw event record."""

    def __init__(
        self,
        success: bool,
        event: Optional[CanonicalEvent] = None,
        raw_hash: str = "",
        error: Optional[str] = None,
        is_quarantined: bool = False,
        raw_payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.success = success
        self.event = event
        self.raw_hash = raw_hash
        self.error = error
        self.is_quarantined = is_quarantined
        self.raw_payload = raw_payload or {}


class NormalizationEngine:
    """Core normalization engine transforming adapter outputs into CanonicalEvents."""

    def __init__(self, lake_bucket_prefix: str = "s3://telemetry-lake") -> None:
        self.lake_bucket_prefix = lake_bucket_prefix

    def _normalize_timestamp(self, ts_val: Any) -> datetime:
        """Parse arbitrary timestamp representation into timezone-aware UTC datetime."""
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc)
            return ts_val.astimezone(timezone.utc)
        elif isinstance(ts_val, (int, float)):
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)
        elif isinstance(ts_val, str):
            clean_str = ts_val.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(clean_str)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass
        return utc_now()

    def normalize(
        self, record: Dict[str, Any], connector_id: Optional[str] = None
    ) -> NormalizationResult:
        """Normalize a single telemetry dictionary into a verified CanonicalEvent."""
        metrics.inc_received()
        raw_hash = compute_payload_hash(record)

        try:
            ts = self._normalize_timestamp(record.get("timestamp"))

            # Derive or preserve event UUID
            raw_event_id = record.get("event_id")
            event_id: UUID
            if raw_event_id:
                try:
                    event_id = UUID(str(raw_event_id))
                except Exception:
                    # Deterministically generate UUID from raw_hash
                    event_id = UUID(raw_hash[:32])
            else:
                event_id = uuid4()

            # Date partition path for raw reference
            dt_str = ts.strftime("%Y/%m/%d")
            source_type = record.get("source_type")
            source_name = record.get("source_name")
            event_type = record.get("event_type")
            raw_ref = (
                record.get("raw_ref")
                or f"{self.lake_bucket_prefix}/{source_type or 'unknown'}/{dt_str}/{event_id}.json"
            )

            # Parse severity
            raw_sev = str(record.get("severity", "informational")).lower()
            severity_map = {
                "critical": EventSeverityEnum.CRITICAL,
                "high": EventSeverityEnum.HIGH,
                "medium": EventSeverityEnum.MEDIUM,
                "low": EventSeverityEnum.LOW,
                "informational": EventSeverityEnum.INFORMATIONAL,
            }
            severity = severity_map.get(raw_sev, EventSeverityEnum.INFORMATIONAL)

            # Build canonical payload dictionary
            canonical_dict = {
                "event_id": event_id,
                "timestamp": ts,
                "ingest_timestamp": utc_now(),
                "source_type": source_type,
                "source_name": source_name,
                "event_type": event_type,
                "host_id": record.get("host_id"),
                "hostname": record.get("hostname"),
                "user_id": record.get("user_id"),
                "username": record.get("username"),
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dst_ip"),
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "process_name": record.get("process_name"),
                "process_id": record.get("process_id"),
                "parent_process": record.get("parent_process"),
                "command_line": record.get("command_line"),
                "hash_sha256": record.get("hash_sha256"),
                "domain": record.get("domain"),
                "url": record.get("url"),
                "severity": severity,
                "raw_ref": raw_ref,
                "raw_event": record.get("raw_record") or record.get("raw_event") or record,
                "entities": record.get("entities") or {},
            }

            # Filter out None values for optional fields so Pydantic defaults apply cleanly
            clean_dict: Dict[str, Any] = {k: v for k, v in canonical_dict.items() if v is not None}
            canonical_event = CanonicalEvent.model_validate(clean_dict)
            metrics.inc_normalized()

            return NormalizationResult(
                success=True,
                event=canonical_event,
                raw_hash=raw_hash,
                raw_payload=record,
            )

        except (ValidationError, Exception) as ex:
            metrics.inc_quarantined()
            error_msg = f"Canonical normalization error: {ex}"
            return NormalizationResult(
                success=False,
                error=error_msg,
                raw_hash=raw_hash,
                is_quarantined=True,
                raw_payload=record,
            )

    def normalize_batch(
        self, records: List[Dict[str, Any]], connector_id: Optional[str] = None
    ) -> List[NormalizationResult]:
        """Normalize a collection of records into NormalizationResults."""
        return [self.normalize(r, connector_id=connector_id) for r in records]
