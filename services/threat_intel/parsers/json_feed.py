"""CyberSentinel AI — Documented JSON Threat Intelligence Feed Parser (Sprint 13)"""

from typing import Any, Dict, List

from services.threat_intel.normalizer import normalize_indicator
from services.threat_intel.parsers.stix21 import (
    ParsedFeedRecord,
    parse_iso_datetime,
    sanitize_feed_text,
)


class JsonFeedParser:
    """Parser for structured JSON threat intelligence feeds."""

    MAX_INDICATORS_PER_FEED = 50_000

    @classmethod
    def parse_feed(cls, feed_dict: Dict[str, Any]) -> List[ParsedFeedRecord]:
        """Parse structured JSON feed dictionary into standardized ParsedFeedRecord objects."""
        indicators = feed_dict.get("indicators", [])
        if not isinstance(indicators, list):
            raise ValueError("JSON feed must contain an 'indicators' list")

        if len(indicators) > cls.MAX_INDICATORS_PER_FEED:
            raise ValueError(
                f"JSON feed exceeds maximum allowed indicator limit of {cls.MAX_INDICATORS_PER_FEED}"
            )

        results: List[ParsedFeedRecord] = []

        for idx, item in enumerate(indicators):
            if not isinstance(item, dict):
                continue

            raw_type = str(item.get("type", "")).strip().lower()
            raw_val = str(item.get("value", "")).strip()

            if not raw_type or not raw_val:
                results.append(
                    ParsedFeedRecord(
                        indicator_type=raw_type or "unknown",
                        indicator_value=raw_val,
                        raw_value=raw_val,
                        external_record_id=item.get("id") or f"json-rec-{idx}",
                        is_valid=False,
                        quarantine_reason="MISSING_TYPE_OR_VALUE",
                        raw_payload=item,
                    )
                )
                continue

            # Validate and normalize
            norm = normalize_indicator(raw_type, raw_val)
            if not norm.is_valid:
                results.append(
                    ParsedFeedRecord(
                        indicator_type=raw_type,
                        indicator_value=raw_val,
                        raw_value=raw_val,
                        external_record_id=item.get("id") or f"json-rec-{idx}",
                        is_valid=False,
                        quarantine_reason=f"INVALID_INDICATOR_SYNTAX: {norm.error_message}",
                        raw_payload=item,
                    )
                )
                continue

            # Parse scores and confidence
            raw_score = item.get("reputation_score")
            score = None
            if raw_score is not None:
                try:
                    score = max(0.0, min(100.0, float(raw_score)))
                except (ValueError, TypeError):
                    score = None

            raw_conf = item.get("confidence")
            confidence = None
            if raw_conf is not None:
                try:
                    confidence = max(0.0, min(100.0, float(raw_conf)))
                except (ValueError, TypeError):
                    confidence = None

            first_seen = parse_iso_datetime(item.get("first_seen"))
            last_seen = parse_iso_datetime(item.get("last_seen"))
            expires_at = parse_iso_datetime(item.get("expires_at"))

            classification = sanitize_feed_text(item.get("classification", "suspicious"))
            threat_actor = sanitize_feed_text(item.get("threat_actor"))
            campaign = sanitize_feed_text(item.get("campaign"))
            description = sanitize_feed_text(item.get("description"))
            handling_tlp = sanitize_feed_text(
                item.get("tlp") or item.get("handling") or item.get("tlp_marking"),
                max_length=64,
            )

            results.append(
                ParsedFeedRecord(
                    indicator_type=norm.indicator_type,
                    indicator_value=norm.value,
                    raw_value=raw_val,
                    external_record_id=item.get("id") or f"json-rec-{idx}",
                    first_seen=first_seen,
                    last_seen=last_seen,
                    published_at=first_seen,
                    expires_at=expires_at,
                    confidence=confidence,
                    source_reputation_score=score,
                    source_classification=classification.lower() if classification else "suspicious",
                    threat_actor=threat_actor,
                    campaign=campaign,
                    description=description,
                    handling_tlp=handling_tlp,
                    raw_payload={
                        "id": item.get("id"),
                        "type": raw_type,
                        "value": raw_val,
                        "reputation_score": score,
                        "confidence": confidence,
                    },
                    is_valid=True,
                )
            )

        return results


__all__ = ["JsonFeedParser"]
