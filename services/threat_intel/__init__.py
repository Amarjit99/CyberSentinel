"""CyberSentinel AI — Threat Intelligence Service Boundary (Sprint 13)

Enriches indicators of compromise (IOCs) against authoritative threat intelligence sources.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from services.threat_intel.normalizer import (
    IndicatorType,
    NormalizedIndicator,
    normalize_indicator,
)
from services.threat_intel.parsers import (
    JsonFeedParser,
    ParsedFeedRecord,
    Stix21FeedParser,
    parse_iso_datetime,
    sanitize_feed_text,
)
from services.threat_intel.service import (
    FeedIngestResult,
    IndicatorLookupResult,
    SourceObservationItem,
    ThreatIntelService,
)


class EnrichedIndicator(BaseModel):
    """Enriched indicator metadata and threat score (backward-compatible schema)."""

    indicator_type: str = Field(..., description="Indicator type (ipv4, domain, hash, url)")
    indicator_value: str = Field(..., description="Raw indicator value")
    reputation_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Risk score 0-100")
    threat_actor: Optional[str] = Field(default=None, description="Attributed threat group")
    campaign: Optional[str] = Field(default=None, description="Associated attack campaign")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Provider context")


class BaseThreatIntelProvider(ABC):
    """Abstract interface for threat intel lookups."""

    @abstractmethod
    def lookup_indicator(
        self, indicator_type: str, indicator_value: str
    ) -> Optional[EnrichedIndicator]:
        """Query local cache and external threat feeds for indicator reputation."""
        raise NotImplementedError


__all__ = [
    "EnrichedIndicator",
    "BaseThreatIntelProvider",
    "IndicatorType",
    "NormalizedIndicator",
    "normalize_indicator",
    "ParsedFeedRecord",
    "Stix21FeedParser",
    "JsonFeedParser",
    "sanitize_feed_text",
    "parse_iso_datetime",
    "SourceObservationItem",
    "IndicatorLookupResult",
    "FeedIngestResult",
    "ThreatIntelService",
]
