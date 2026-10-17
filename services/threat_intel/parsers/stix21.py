"""CyberSentinel AI — STIX 2.1 Bundle Parser (Sprint 13)

Parses STIX 2.1 JSON Bundles safely using deterministic regex matching without eval.
Enforces untrusted text sanitization and pattern validation.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from services.threat_intel.normalizer import normalize_indicator

# Safe regex pattern extractors for supported STIX 2.1 comparison expressions
# Example: [ipv4-addr:value = '198.51.100.1']
STIX_PATTERNS = [
    (
        "ipv4",
        re.compile(
            r"\[\s*ipv4-addr:value\s*=\s*'([^']+)'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "ipv6",
        re.compile(
            r"\[\s*ipv6-addr:value\s*=\s*'([^']+)'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "domain",
        re.compile(
            r"\[\s*domain-name:value\s*=\s*'([^']+)'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "url",
        re.compile(
            r"\[\s*url:value\s*=\s*'([^']+)'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "hash_sha256",
        re.compile(
            r"\[\s*file:hashes\.(?:'SHA-256'|'SHA256'|SHA256)\s*=\s*'([0-9a-fA-F]{64})'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "hash_sha1",
        re.compile(
            r"\[\s*file:hashes\.(?:'SHA-1'|'SHA1'|SHA1)\s*=\s*'([0-9a-fA-F]{40})'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "hash_md5",
        re.compile(
            r"\[\s*file:hashes\.(?:'MD5'|MD5)\s*=\s*'([0-9a-fA-F]{32})'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "email",
        re.compile(
            r"\[\s*email-addr:value\s*=\s*'([^']+)'\s*\]",
            re.IGNORECASE,
        ),
    ),
    (
        "certificate_sha256",
        re.compile(
            r"\[\s*x509-certificate:hashes\.(?:'SHA-256'|'SHA256'|SHA256)\s*=\s*'([0-9a-fA-F]{64})'\s*\]",
            re.IGNORECASE,
        ),
    ),
]


class ParsedFeedRecord(BaseModel):
    """Normalized intermediate record extracted from a threat intel feed."""

    indicator_type: str
    indicator_value: str
    raw_value: str
    external_record_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    published_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    confidence: Optional[float] = None  # Source-reported confidence (0-100)
    source_reputation_score: Optional[float] = None  # Source-reported score (0-100)
    source_classification: Optional[str] = None  # e.g. "malicious", "suspicious", "c2"
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    description: Optional[str] = None
    handling_tlp: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    is_valid: bool = True
    quarantine_reason: Optional[str] = None


def sanitize_feed_text(text: Optional[str], max_length: int = 1000) -> Optional[str]:
    """Sanitize untrusted feed descriptions and names against prompt injection and control chars."""
    if text is None:
        return None
    # Truncate and strip
    clean = text.strip()[:max_length]
    # Neutralize potential prompt injection tags
    clean = clean.replace("<<<UNTRUSTED_", "[ESCAPED_TAG_").replace("_UNTRUSTED>>>", "[ESCAPED_TAG_]")
    clean = clean.replace("SYSTEM OVERRIDE", "[OVERRIDE_FILTERED]")
    clean = clean.replace("IGNORE ALL PREVIOUS INSTRUCTIONS", "[INSTRUCTION_FILTERED]")
    return clean


def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Safely parse ISO 8601 timestamps from feed records."""
    if not dt_str:
        return None
    try:
        # Standard datetime.fromisoformat supports +00:00 or Z
        norm = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(norm)
    except Exception:
        return None


class Stix21FeedParser:
    """Parser for STIX 2.1 bundles containing Indicator SDOs."""

    MAX_BUNDLE_OBJECTS = 10_000

    @classmethod
    def extract_pattern(cls, pattern_str: str) -> Tuple[Optional[str], Optional[str]]:
        """Safely match observable type and indicator value from STIX pattern string."""
        for ind_type, regex in STIX_PATTERNS:
            match = regex.search(pattern_str)
            if match:
                return ind_type, match.group(1).strip()
        return None, None

    @classmethod
    def parse_bundle(cls, bundle_dict: Dict[str, Any]) -> List[ParsedFeedRecord]:
        """Parse a STIX 2.1 bundle dictionary and return extracted indicator records."""
        bundle_type = bundle_dict.get("type")
        if bundle_type != "bundle":
            raise ValueError(f"Expected STIX 'bundle', received '{bundle_type}'")

        objects = bundle_dict.get("objects", [])
        if not isinstance(objects, list):
            raise ValueError("STIX bundle 'objects' must be a list")

        if len(objects) > cls.MAX_BUNDLE_OBJECTS:
            raise ValueError(
                f"STIX bundle exceeds maximum allowed object limit of {cls.MAX_BUNDLE_OBJECTS}"
            )

        results: List[ParsedFeedRecord] = []

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            obj_type = obj.get("type")
            if obj_type != "indicator":
                # Currently extracting Indicators; skip other SDOs like attack-pattern or identity
                continue

            obj_id = str(obj.get("id", ""))
            pattern = str(obj.get("pattern", "")).strip()

            if not pattern:
                results.append(
                    ParsedFeedRecord(
                        indicator_type="unknown",
                        indicator_value="",
                        raw_value="",
                        external_record_id=obj_id,
                        is_valid=False,
                        quarantine_reason="MISSING_STIX_PATTERN",
                        raw_payload=obj,
                    )
                )
                continue

            extracted_type, extracted_val = cls.extract_pattern(pattern)
            if not extracted_type or not extracted_val:
                results.append(
                    ParsedFeedRecord(
                        indicator_type="unsupported",
                        indicator_value=pattern,
                        raw_value=pattern,
                        external_record_id=obj_id,
                        is_valid=False,
                        quarantine_reason=f"UNSUPPORTED_STIX_PATTERN: '{pattern}'",
                        raw_payload=obj,
                    )
                )
                continue

            # Validate and normalize indicator
            norm = normalize_indicator(extracted_type, extracted_val)
            if not norm.is_valid:
                results.append(
                    ParsedFeedRecord(
                        indicator_type=extracted_type,
                        indicator_value=extracted_val,
                        raw_value=extracted_val,
                        external_record_id=obj_id,
                        is_valid=False,
                        quarantine_reason=f"INVALID_INDICATOR_SYNTAX: {norm.error_message}",
                        raw_payload=obj,
                    )
                )
                continue

            # Parse confidence and timestamps
            raw_confidence = obj.get("confidence")
            confidence = None
            if raw_confidence is not None:
                try:
                    confidence = max(0.0, min(100.0, float(raw_confidence)))
                except (ValueError, TypeError):
                    confidence = None

            valid_from = parse_iso_datetime(obj.get("valid_from"))
            valid_until = parse_iso_datetime(obj.get("valid_until"))
            created = parse_iso_datetime(obj.get("created"))

            # Classification from indicator_types or labels
            labels = obj.get("indicator_types") or obj.get("labels") or []
            if isinstance(labels, list) and labels:
                classification = "/".join(str(lbl) for lbl in labels)
            else:
                classification = "suspicious"

            # Threat actor or campaign from custom properties or name
            name_text = sanitize_feed_text(obj.get("name"))
            desc_text = sanitize_feed_text(obj.get("description"))
            handling_tlp = sanitize_feed_text(
                obj.get("tlp") or obj.get("handling") or obj.get("tlp_marking"),
                max_length=64,
            )

            # Build record
            results.append(
                ParsedFeedRecord(
                    indicator_type=norm.indicator_type,
                    indicator_value=norm.value,
                    raw_value=extracted_val,
                    external_record_id=obj_id,
                    first_seen=valid_from,
                    last_seen=None,
                    published_at=created,
                    expires_at=valid_until,
                    confidence=confidence,
                    source_reputation_score=None,  # STIX indicators do not specify a numeric reputation score unless proprietary
                    source_classification=str(classification).lower(),
                    threat_actor=None,
                    campaign=None,
                    description=desc_text or name_text,
                    handling_tlp=handling_tlp,
                    raw_payload={
                        "stix_id": obj_id,
                        "pattern": pattern,
                        "labels": labels,
                        "name": name_text,
                    },
                    is_valid=True,
                )
            )

        return results


__all__ = [
    "ParsedFeedRecord",
    "Stix21FeedParser",
    "sanitize_feed_text",
    "parse_iso_datetime",
]
