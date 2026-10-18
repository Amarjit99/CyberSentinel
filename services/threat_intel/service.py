"""CyberSentinel AI — Threat Intelligence Service & Ingestion Pipeline (Sprint 13)

Governing Decisions: ADR-0001, ADR-0004, Phase 13 Specification
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from packages.observability.metrics import metrics
from services.persistence.models import (
    EventMetadata,
    ThreatIndicator,
    ThreatIndicatorRecord,
    ThreatSource,
)
from services.threat_intel.normalizer import normalize_indicator
from services.threat_intel.parsers.json_feed import JsonFeedParser
from services.threat_intel.parsers.stix21 import (
    ParsedFeedRecord,
    Stix21FeedParser,
)

FRESHNESS_FRESH_HOURS = 24
FRESHNESS_STALE_HOURS = 72


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_dt(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class SourceObservationItem(BaseModel):
    """Source-attributed threat intelligence observation."""

    source_id: str
    source_name: str
    source_reliability: str
    external_record_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    published_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_expired: bool = False
    confidence: Optional[float] = None
    source_reported_score: Optional[float] = None
    source_classification: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    description: Optional[str] = None
    handling_tlp: Optional[str] = None


class IndicatorLookupResult(BaseModel):
    """Authoritative result of an indicator intelligence enrichment query."""

    found: bool
    indicator_type: str
    indicator_value: str
    raw_value: Optional[str] = None
    is_valid: bool = True
    verdict: str = Field(
        default="unknown", description="'malicious', 'suspicious', 'benign', 'unknown', 'expired', 'invalid'"
    )
    normalized_score: Optional[float] = Field(
        default=None, description="Deterministic calculated score 0-100 or None if source supplies no score"
    )
    reliability_weighted_score: Optional[float] = Field(
        default=None,
        description="Reliability-weighted source score 0-100 when source scores are available",
    )
    reliability_summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of active observations by source reliability classification",
    )
    has_score: bool = False
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    records: List[SourceObservationItem] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    limitations: str = Field(
        default="", description="Explicit statement of data boundaries and missing intelligence"
    )
    is_expired: bool = False

    def to_agent_dict(self) -> Dict[str, Any]:
        """Convert to structured fact dictionary for ReadOnlyInvestigationTools."""
        primary_source = self.records[0].source_name if self.records else "Local Threat Intel Feed"
        return {
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "reputation": self.verdict,
            "score": self.normalized_score if self.normalized_score is not None else 0.0,
            "has_reputation_score": self.has_score,
            "threat_actor": self.threat_actor,
            "campaign": self.campaign,
            "source": primary_source,
            "records_count": len(self.records),
            "is_expired": self.is_expired,
            "conflicts": self.conflicts,
            "provenance": [r.source_name for r in self.records],
            "limitations": self.limitations,
        }


class FeedIngestResult(BaseModel):
    """Summary of a completed feed ingestion batch."""

    source_id: str
    import_id: str
    total_parsed: int
    accepted_count: int
    quarantined_count: int
    duplicate_count: int
    expired_count: int
    errors: List[str] = Field(default_factory=list)


class ThreatIntelService:
    """Core domain service for threat intelligence ingestion, queries, and enrichment."""

    def __init__(self, session: Optional[Session] = None):
        self.session = session

    def _ensure_source(
        self, session: Session, source_id: str, name: str, source_type: str, reliability: str = "B"
    ) -> ThreatSource:
        """Ensure the threat feed source record exists."""
        source = session.get(ThreatSource, source_id)
        if not source:
            source = ThreatSource(
                id=source_id,
                name=name,
                source_type=source_type,
                reliability=reliability,
                description=f"Auto-registered {source_type} source",
                created_at=utc_now(),
            )
            session.add(source)
            session.flush()
        return source

    def ingest_records(
        self,
        session: Session,
        source_id: str,
        source_name: str,
        source_type: str,
        records: List[ParsedFeedRecord],
        import_id: Optional[str] = None,
        feed_version: Optional[str] = "1.0",
        reliability: str = "B",
    ) -> FeedIngestResult:
        """Persist a parsed batch of feed records idempotently."""
        actual_import_id = import_id or str(uuid4())
        self._ensure_source(session, source_id, source_name, source_type, reliability=reliability)

        accepted = 0
        quarantined = 0
        duplicates = 0
        expired = 0
        errors: List[str] = []
        now = utc_now()

        for rec in records:
            if not rec.is_valid:
                quarantined += 1
                errors.append(f"Quarantined record {rec.external_record_id}: {rec.quarantine_reason}")
                continue

            # Check expiration
            is_rec_expired = (
                rec.expires_at is not None and _normalize_dt(rec.expires_at) < now  # type: ignore[operator]
            )
            if is_rec_expired:
                expired += 1

            # 1. Lookup or create Canonical ThreatIndicator
            stmt = select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == rec.indicator_type,
                ThreatIndicator.value == rec.indicator_value,
            )
            indicator = session.execute(stmt).scalar_one_or_none()

            if not indicator:
                indicator = ThreatIndicator(
                    id=str(uuid4()),
                    indicator_type=rec.indicator_type,
                    value=rec.indicator_value,
                    raw_value=rec.raw_value,
                    status="expired" if is_rec_expired else "active",
                    created_at=now,
                    updated_at=now,
                )
                session.add(indicator)
                session.flush()
            else:
                # Update existing indicator updated_at
                indicator.updated_at = now
                if not is_rec_expired and indicator.status == "expired":
                    indicator.status = "active"

            # 2. Check for duplicate observation from same source and external record ID
            stmt_rec = select(ThreatIndicatorRecord).where(
                ThreatIndicatorRecord.indicator_id == indicator.id,
                ThreatIndicatorRecord.source_id == source_id,
            )
            if rec.external_record_id:
                stmt_rec = stmt_rec.where(
                    ThreatIndicatorRecord.external_record_id == rec.external_record_id
                )

            existing_obs = session.execute(stmt_rec).scalar_one_or_none()
            if existing_obs:
                duplicates += 1
                # Update last seen and import_id
                existing_obs.last_seen = rec.last_seen or now
                existing_obs.import_id = actual_import_id
                existing_obs.expires_at = rec.expires_at
                existing_obs.confidence = rec.confidence
                existing_obs.source_reputation_score = rec.source_reputation_score
                existing_obs.source_classification = rec.source_classification
                existing_obs.handling_tlp = rec.handling_tlp
            else:
                obs = ThreatIndicatorRecord(
                    id=str(uuid4()),
                    indicator_id=indicator.id,
                    source_id=source_id,
                    external_record_id=rec.external_record_id,
                    first_seen=rec.first_seen or now,
                    last_seen=rec.last_seen or now,
                    published_at=rec.published_at or now,
                    expires_at=rec.expires_at,
                    confidence=rec.confidence,
                    source_reputation_score=rec.source_reputation_score,
                    source_classification=rec.source_classification,
                    handling_tlp=rec.handling_tlp,
                    threat_actor=rec.threat_actor,
                    campaign=rec.campaign,
                    feed_version=feed_version,
                    import_id=actual_import_id,
                    ingested_at=now,
                    raw_record_json=rec.raw_payload,
                    validation_status="valid",
                )
                session.add(obs)
                accepted += 1

        session.commit()
        metrics.inc_counter("threat_intel_indicators_ingested_total", accepted)

        return FeedIngestResult(
            source_id=source_id,
            import_id=actual_import_id,
            total_parsed=len(records),
            accepted_count=accepted,
            quarantined_count=quarantined,
            duplicate_count=duplicates,
            expired_count=expired,
            errors=errors[:50],
        )

    def ingest_feed_file(
        self,
        session: Session,
        file_path: Path,
        source_id: Optional[str] = None,
        source_name: Optional[str] = None,
    ) -> FeedIngestResult:
        """Inspect and ingest a local STIX 2.1 or JSON feed file."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Feed file not found: {path}")

        raw_content = path.read_text(encoding="utf-8")
        data = json.loads(raw_content)

        # Detect format
        if data.get("type") == "bundle":
            records = Stix21FeedParser.parse_bundle(data)
            sid = source_id or f"stix_{path.stem}"
            sname = source_name or f"STIX Feed ({path.name})"
            return self.ingest_records(
                session=session,
                source_id=sid,
                source_name=sname,
                source_type="stix21",
                records=records,
            )
        elif "indicators" in data:
            records = JsonFeedParser.parse_feed(data)
            sid = source_id or data.get("source_id") or f"json_{path.stem}"
            sname = source_name or data.get("feed_name") or f"JSON Feed ({path.name})"
            ver = data.get("version", "1.0")
            return self.ingest_records(
                session=session,
                source_id=sid,
                source_name=sname,
                source_type="json_feed",
                records=records,
                feed_version=ver,
            )
        else:
            raise ValueError(
                "Unrecognized feed format. Expected a STIX 2.1 bundle or JSON feed with 'indicators' key."
            )

    def lookup_indicator(
        self,
        indicator_type: str,
        indicator_value: str,
        include_expired: bool = False,
        session: Optional[Session] = None,
    ) -> IndicatorLookupResult:
        """Lookup an indicator in the local threat intelligence database with full provenance."""
        metrics.inc_counter("threat_intel_lookups_total", 1)
        sess = session or self.session
        if sess is None:
            raise RuntimeError("Database session required for threat intel lookup")

        # 1. Normalize and validate indicator syntax
        norm = normalize_indicator(indicator_type, indicator_value)
        if not norm.is_valid:
            return IndicatorLookupResult(
                found=False,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                raw_value=indicator_value,
                is_valid=False,
                verdict="invalid",
                limitations=f"Invalid indicator syntax: {norm.error_message}",
            )

        # 2. Query database
        stmt = (
            select(ThreatIndicator)
            .where(
                ThreatIndicator.indicator_type == norm.indicator_type,
                ThreatIndicator.value == norm.value,
            )
        )
        indicator = sess.execute(stmt).scalar_one_or_none()

        if not indicator:
            return IndicatorLookupResult(
                found=False,
                indicator_type=norm.indicator_type,
                indicator_value=norm.value,
                raw_value=indicator_value,
                is_valid=True,
                verdict="unknown",
                limitations=(
                    "Indicator not found in local threat intelligence repository. "
                    "Absence of evidence is not proof of benignity."
                ),
            )

        # 3. Query observation records
        stmt_records = (
            select(ThreatIndicatorRecord, ThreatSource)
            .join(ThreatSource, ThreatIndicatorRecord.source_id == ThreatSource.id)
            .where(
                ThreatIndicatorRecord.indicator_id == indicator.id,
                ThreatIndicatorRecord.validation_status == "valid",
            )
        )
        results = sess.execute(stmt_records).all()

        if not results:
            return IndicatorLookupResult(
                found=True,
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                raw_value=indicator.raw_value,
                is_valid=True,
                verdict="unknown",
                limitations="Indicator registered but has no valid source observation records.",
            )

        now = utc_now()
        obs_items: List[SourceObservationItem] = []
        scores: List[float] = []
        weighted_scores: List[tuple[float, float]] = []
        confidences: List[float] = []
        reliability_summary: Dict[str, int] = {}
        classifications: Set[str] = set()
        threat_actors: Set[str] = set()
        campaigns: Set[str] = set()
        all_expired = True

        for rec, src in results:
            rec_expired = (
                rec.expires_at is not None and _normalize_dt(rec.expires_at) < now  # type: ignore[operator]
            )
            if not rec_expired:
                all_expired = False

            if not include_expired and rec_expired:
                continue

            obs_items.append(
                SourceObservationItem(
                    source_id=src.id,
                    source_name=src.name,
                    source_reliability=src.reliability,
                    external_record_id=rec.external_record_id,
                    first_seen=rec.first_seen,
                    last_seen=rec.last_seen,
                    published_at=rec.published_at,
                    expires_at=rec.expires_at,
                    is_expired=rec_expired,
                    confidence=rec.confidence,
                    source_reported_score=rec.source_reputation_score,
                    source_classification=rec.source_classification,
                    threat_actor=rec.threat_actor,
                    campaign=rec.campaign,
                    description=rec.raw_record_json.get("description"),
                    handling_tlp=rec.handling_tlp,
                )
            )

            if rec.source_reputation_score is not None:
                scores.append(rec.source_reputation_score)
                reliability = src.reliability.upper()
                reliability_weight = {"A": 1.0, "B": 0.8, "C": 0.6}.get(reliability, 0.5)
                weighted_scores.append((rec.source_reputation_score, reliability_weight))
                reliability_summary[reliability if reliability in ("A", "B", "C") else "unknown"] = (
                    reliability_summary.get(
                        reliability if reliability in ("A", "B", "C") else "unknown", 0
                    )
                    + 1
                )
            if rec.confidence is not None:
                confidences.append(rec.confidence)
            if rec.source_classification:
                classifications.add(rec.source_classification.lower())
            if rec.threat_actor:
                threat_actors.add(rec.threat_actor)
            if rec.campaign:
                campaigns.add(rec.campaign)

        if all_expired and not include_expired:
            return IndicatorLookupResult(
                found=True,
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                raw_value=indicator.raw_value,
                is_valid=True,
                verdict="expired",
                is_expired=True,
                limitations="All threat intelligence observations for this indicator have expired.",
            )

        # 4. Check for conflicts
        conflicts = []
        has_malicious = any(c in ("malicious", "c2", "malware", "phishing") for c in classifications)
        has_benign = any(c in ("benign", "allowlist", "clean") for c in classifications)
        if has_malicious and has_benign:
            conflicts.append("Conflicting sources: both malicious and benign classifications observed")

        # 5. Deterministic calculated score
        calculated_score = None
        has_score = len(scores) > 0
        if has_score:
            # Deterministic maximum/average calculation
            calculated_score = round(sum(scores) / len(scores), 2)
        weighted_score = None
        if weighted_scores:
            total_weight = sum(weight for _, weight in weighted_scores)
            weighted_score = round(
                sum(score * weight for score, weight in weighted_scores) / total_weight,
                2,
            )

        # 6. Verdict determination
        if has_malicious:
            verdict = "malicious"
        elif any(c in ("suspicious", "anomalous") for c in classifications):
            verdict = "suspicious"
        elif has_benign:
            verdict = "benign"
        else:
            verdict = "unknown"

        actor_str = ", ".join(sorted(list(threat_actors))) if threat_actors else None
        camp_str = ", ".join(sorted(list(campaigns))) if campaigns else None

        return IndicatorLookupResult(
            found=True,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            raw_value=indicator.raw_value,
            is_valid=True,
            verdict=verdict,
            normalized_score=calculated_score,
            reliability_weighted_score=weighted_score,
            reliability_summary=reliability_summary,
            has_score=has_score,
            threat_actor=actor_str,
            campaign=camp_str,
            records=obs_items,
            conflicts=conflicts,
            limitations=(
                "Local threat intelligence matching only. External live enrichment not performed."
                if not conflicts
                else "Discrepancy among feed sources detected. Review individual observations."
            ),
            is_expired=all_expired,
        )

    def source_health(self, session: Session) -> List[Dict[str, Any]]:
        """Report source freshness and reliability using the latest ingested record."""
        now = utc_now()
        sources = session.execute(select(ThreatSource).order_by(ThreatSource.name)).scalars().all()
        health: List[Dict[str, Any]] = []
        for source in sources:
            latest = session.execute(
                select(ThreatIndicatorRecord.ingested_at)
                .where(ThreatIndicatorRecord.source_id == source.id)
                .order_by(ThreatIndicatorRecord.ingested_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            age_hours = None
            state = "never_ingested"
            if latest is not None:
                norm_latest = _normalize_dt(latest)
                if norm_latest is not None:
                    age_hours = round(max(0.0, (now - norm_latest).total_seconds() / 3600), 2)
                    state = (
                        "fresh"
                        if age_hours <= FRESHNESS_FRESH_HOURS
                        else "stale"
                        if age_hours <= FRESHNESS_STALE_HOURS
                        else "expired"
                    )
            health.append(
                {
                    "source_id": source.id,
                    "source_name": source.name,
                    "source_type": source.source_type,
                    "reliability": source.reliability,
                    "enabled": source.enabled,
                    "endpoint_url": source.endpoint_url,
                    "freshness_state": state,
                    "latest_ingested_at": latest.isoformat() if latest else None,
                    "age_hours": age_hours,
                    "freshness_policy_hours": {
                        "fresh": FRESHNESS_FRESH_HOURS,
                        "stale": FRESHNESS_STALE_HOURS,
                    },
                }
            )
        return health

    def match_event(self, session: Session, event: EventMetadata) -> Dict[str, Any]:
        """Enrich indexed canonical event fields with local IOC provenance."""
        candidates = [
            ("ipv4", event.src_ip),
            ("ipv4", event.dst_ip),
            ("domain", event.hostname),
        ]
        matches: List[Dict[str, Any]] = []
        seen: Set[tuple[str, str]] = set()
        for indicator_type, value in candidates:
            if not value:
                continue
            normalized = normalize_indicator(indicator_type, value)
            if not normalized.is_valid:
                continue
            key = (normalized.indicator_type, normalized.value)
            if key in seen:
                continue
            seen.add(key)
            result = self.lookup_indicator(
                normalized.indicator_type,
                normalized.value,
                session=session,
            )
            if result.found:
                matches.append(result.model_dump(mode="json"))

        return {
            "event_id": event.id,
            "matched_count": len(matches),
            "matches": matches,
            "limitations": [
                "Matching uses indexed canonical source IP, destination IP, and hostname fields.",
                "File hashes, URLs, and email indicators require canonical event fields before they can be matched.",
                "Only local threat-intelligence observations are consulted; no live external enrichment is performed.",
            ],
        }


__all__ = [
    "ThreatIntelService",
    "IndicatorLookupResult",
    "SourceObservationItem",
    "FeedIngestResult",
]
