"""CyberSentinel AI — Stateful Temporal Sliding Windows
Maintains memory-bounded, event-time sliding windows for multi-event correlation and threshold aggregation.
Governing Decisions: ADR-0005, CSAI-P4-CORRELATION
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from schemas.enums import EventSeverityEnum
from services.correlation.models import CorrelationMatch, CorrelationRule

# Maximum entries held per individual entity window (DoS protection)
MAX_WINDOW_CAPACITY = 2000

# Maximum permitted age for late-arriving events (1 hour)
MAX_LATE_ARRIVAL_SECONDS = 3600


@dataclass
class WindowEntry:
    """Single detection entry recorded in a temporal correlation window."""

    timestamp: datetime
    detection_id: str
    event_id: str
    rule_id: str
    rule_name: str
    tags: List[str]
    severity: EventSeverityEnum
    raw_event: Dict[str, Any] = field(default_factory=dict)


class SlidingEventWindow:
    """Event-time sliding window evaluating detections across a temporal boundary."""

    def __init__(self, window_seconds: int, max_capacity: int = MAX_WINDOW_CAPACITY) -> None:
        self.window_seconds = window_seconds
        self.max_capacity = max_capacity
        self.entries: List[WindowEntry] = []
        self._seen_detection_ids: Set[str] = set()
        self.last_triggered_at: Optional[datetime] = None

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def add_entry(self, entry: WindowEntry) -> bool:
        """Insert a detection into the window using event-time ordering.

        Returns True if accepted, False if duplicate or rejected.
        """
        # 1. Deduplication check
        if entry.detection_id in self._seen_detection_ids:
            return False

        # Ensure timestamp is timezone-aware UTC
        ts = entry.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
            entry.timestamp = ts

        # 2. Late arrival boundary check
        if self.entries:
            latest_time = self.entries[-1].timestamp
            oldest_allowed = latest_time - timedelta(seconds=self.window_seconds + MAX_LATE_ARRIVAL_SECONDS)
            if ts < oldest_allowed:
                return False

        # 3. Insert and maintain chronological event-time order
        self.entries.append(entry)
        self.entries.sort(key=lambda e: e.timestamp)
        self._seen_detection_ids.add(entry.detection_id)

        # 4. Enforce capacity limit
        if len(self.entries) > self.max_capacity:
            evicted = self.entries.pop(0)
            self._seen_detection_ids.discard(evicted.detection_id)

        # 5. Prune expired entries relative to latest entry
        latest_ts = self.entries[-1].timestamp
        self.purge_expired(latest_ts)

        return True

    def purge_expired(self, current_time: datetime) -> int:
        """Remove entries outside the active sliding time window."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        original_count = len(self.entries)
        valid_entries = [e for e in self.entries if e.timestamp >= cutoff]
        self.entries = valid_entries

        # Sync seen IDs
        self._seen_detection_ids = {e.detection_id for e in self.entries}
        return original_count - len(self.entries)

    def evaluate_rule(
        self,
        rule: CorrelationRule,
        entity_type: str,
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelationMatch]:
        """Evaluate threshold or sequence logic for a correlation rule."""
        if not self.entries:
            return None

        # 1. Cooldown suppression check
        if self.last_triggered_at:
            cooldown_delta = (current_time - self.last_triggered_at).total_seconds()
            if cooldown_delta < rule.cooldown_seconds:
                return None

        # 2. Filter candidate entries matching rule filters
        qualifying_entries = self._filter_qualifying_entries(rule)
        if not qualifying_entries:
            return None

        # 3. Check sequence condition if defined
        if rule.sequence:
            return self._evaluate_sequence(rule, qualifying_entries, entity_type, entity_key, current_time)

        # 4. Check threshold condition
        if len(qualifying_entries) >= rule.threshold:
            self.last_triggered_at = current_time
            w_start = qualifying_entries[0].timestamp
            w_end = qualifying_entries[-1].timestamp

            det_ids = [e.detection_id for e in qualifying_entries]
            ev_ids = [e.event_id for e in qualifying_entries]

            title = f"{rule.name} on {entity_type} '{entity_key}'"
            description = (
                f"Correlation rule '{rule.name}' triggered: {len(qualifying_entries)} detections "
                f"observed within {rule.window_seconds}s for {entity_type} '{entity_key}'."
            )

            return CorrelationMatch(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                entity_type=entity_type,
                entity_key=entity_key,
                detection_ids=det_ids,
                event_ids=ev_ids,
                window_start=w_start,
                window_end=w_end,
                title=title,
                description=description,
                confidence=1.0,
                matched_count=len(qualifying_entries),
            )

        return None

    def _filter_qualifying_entries(self, rule: CorrelationRule) -> List[WindowEntry]:
        """Filter entries matching the rule's detection_rules or tags filters."""
        result: List[WindowEntry] = []
        for e in self.entries:
            # Match by rule ID / name
            if rule.rule_matches:
                rule_matched = False
                for pattern in rule.rule_matches:
                    p = pattern.lower()
                    if p in e.rule_id.lower() or p in e.rule_name.lower():
                        rule_matched = True
                        break
                if not rule_matched:
                    continue

            # Match by tags
            if rule.tags:
                tag_matched = False
                for rtag in rule.tags:
                    rt = rtag.lower()
                    if any(rt in et.lower() or et.lower() in rt for et in e.tags):
                        tag_matched = True
                        break
                if not tag_matched:
                    continue

            result.append(e)
        return result

    def _evaluate_sequence(
        self,
        rule: CorrelationRule,
        entries: List[WindowEntry],
        entity_type: str,
        entity_key: str,
        current_time: datetime,
    ) -> Optional[CorrelationMatch]:
        """Evaluate ordered multi-stage sequence conditions across chronological entries."""
        if not rule.sequence or len(entries) < len(rule.sequence):
            return None

        # Greedily match sequence steps forward in time
        matched_entries: List[WindowEntry] = []
        entry_idx = 0

        for step in rule.sequence:
            step_matched = False
            while entry_idx < len(entries):
                candidate = entries[entry_idx]
                entry_idx += 1

                # Check step matching conditions
                if step.rule_id and step.rule_id.lower() not in candidate.rule_id.lower():
                    continue
                if step.tag and not any(step.tag.lower() in t.lower() or t.lower() in step.tag.lower() for t in candidate.tags):
                    continue
                if step.filter_field and step.filter_value:
                    val = candidate.raw_event.get(step.filter_field)
                    if not val or str(val).lower() != step.filter_value.lower():
                        continue

                # Step satisfied
                matched_entries.append(candidate)
                step_matched = True
                break

            if not step_matched:
                return None

        # Full sequence confirmed
        self.last_triggered_at = current_time
        w_start = matched_entries[0].timestamp
        w_end = matched_entries[-1].timestamp

        return CorrelationMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            entity_type=entity_type,
            entity_key=entity_key,
            detection_ids=[e.detection_id for e in matched_entries],
            event_ids=[e.event_id for e in matched_entries],
            window_start=w_start,
            window_end=w_end,
            title=f"Multi-Stage Sequence: {rule.name} on {entity_type} '{entity_key}'",
            description=(
                f"Multi-stage attack sequence '{rule.name}' detected across {len(matched_entries)} stages "
                f"on {entity_type} '{entity_key}'."
            ),
            confidence=1.0,
            matched_count=len(matched_entries),
        )
