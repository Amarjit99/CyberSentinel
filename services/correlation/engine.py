"""CyberSentinel AI — Stateful Correlation Engine
Correlates streaming Sigma detections and canonical events across temporal sliding windows.
Governing Decisions: ADR-0005, CSAI-P4-CORRELATION
"""

import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from packages.observability.metrics import metrics
from schemas.canonical_event import CanonicalEvent
from schemas.enums import EventSeverityEnum
from services.correlation import BaseCorrelationEngine, CorrelationCluster
from services.correlation.entity_extractor import entity_extractor
from services.correlation.models import (
    CorrelationMatch,
    CorrelationRule,
    CorrelationRuleValidationError,
)
from services.correlation.window import SlidingEventWindow, WindowEntry
from services.detection import DetectionMatch
from services.detection.persistence import DetectionPersistenceManager

logger = logging.getLogger("cybersentinel.correlation.engine")


class CorrelationEngine(BaseCorrelationEngine):
    """Multi-event temporal correlation engine evaluating sliding windows over extracted entities."""

    def __init__(self) -> None:
        self._rules: Dict[str, CorrelationRule] = {}
        # Key: (rule_id, entity_type, entity_key)
        self._windows: Dict[Tuple[str, str, str], SlidingEventWindow] = {}
        self._lock = threading.RLock()

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)

    def load_rule(self, rule_spec: Union[str, Dict[str, Any]]) -> CorrelationRule:
        """Parse, validate, and register a CorrelationRule."""
        if isinstance(rule_spec, str):
            try:
                data = yaml.safe_load(rule_spec)
            except Exception as ex:
                raise CorrelationRuleValidationError(f"Invalid correlation rule YAML: {ex}") from ex
        else:
            data = rule_spec

        if not isinstance(data, dict):
            raise CorrelationRuleValidationError("Correlation rule payload must be a mapping")

        try:
            rule = CorrelationRule.model_validate(data)
        except Exception as val_err:
            raise CorrelationRuleValidationError(f"Correlation rule validation error: {val_err}") from val_err

        with self._lock:
            self._rules[rule.id] = rule
            metrics.set_gauge("correlation_rules_active_total", len(self._rules))
            logger.info("Registered correlation rule '%s' (ID: %s)", rule.name, rule.id)

        return rule

    def load_rules_from_directory(self, dir_path: Union[str, Path]) -> int:
        """Load and register all correlation rules from a directory (.yml / .yaml)."""
        path = Path(dir_path)
        if not path.is_dir():
            logger.warning("Correlation rules directory not found: %s", path)
            return 0

        loaded = 0
        rule_files = list(path.glob("**/*.yml")) + list(path.glob("**/*.yaml"))

        for rf in rule_files:
            if rf.name.lower() in ("readme.md", "metadata.yaml"):
                continue
            try:
                content = rf.read_text(encoding="utf-8")
                self.load_rule(content)
                loaded += 1
            except Exception as ex:
                logger.error("Failed to load correlation rule from '%s': %s", rf.name, ex)

        return loaded

    def get_rule(self, rule_id: str) -> Optional[CorrelationRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def get_active_rules(self) -> List[CorrelationRule]:
        with self._lock:
            return list(self._rules.values())

    def list_rules(self) -> List[CorrelationRule]:
        """Alias for get_active_rules conforming to standard interface."""
        return self.get_active_rules()


    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                # Cleanup associated windows
                to_del = [k for k in self._windows if k[0] == rule_id]
                for k in to_del:
                    del self._windows[k]
                metrics.set_gauge("correlation_rules_active_total", len(self._rules))
                return True
            return False

    def clear_rules(self) -> None:
        with self._lock:
            self._rules.clear()
            self._windows.clear()
            metrics.set_gauge("correlation_rules_active_total", 0)

    def process_detection(
        self,
        detection: DetectionMatch,
        event: CanonicalEvent,
    ) -> List[CorrelationMatch]:
        """Evaluate a new detection alert across registered correlation rules.

        Returns a list of CorrelationMatch findings if thresholds or sequences are triggered.
        """
        metrics.inc_counter("correlation_detections_received_total")
        matches: List[CorrelationMatch] = []
        event_dict = event.model_dump(mode="json")
        target_event_id = str(event.event_id)

        with self._lock:
            active_rules = [r for r in self._rules.values() if r.enabled]

        for rule in active_rules:
            # 1. Determine entity grouping keys
            for group_field in rule.group_by:
                entity_val = entity_extractor.get_group_key(event, group_field)
                if not entity_val:
                    continue

                window_key = (rule.id, group_field, entity_val)

                with self._lock:
                    if window_key not in self._windows:
                        self._windows[window_key] = SlidingEventWindow(
                            window_seconds=rule.window_seconds
                        )
                    window = self._windows[window_key]

                # 2. Add entry to window
                det_id = DetectionPersistenceManager.derive_detection_id(detection.rule_id, target_event_id)
                entry = WindowEntry(
                    timestamp=event.timestamp,
                    detection_id=det_id,
                    event_id=target_event_id,
                    rule_id=detection.rule_id,
                    rule_name=detection.rule_name,
                    tags=detection.mitre_attack_ids,
                    severity=detection.severity,
                    raw_event=event_dict,
                )

                accepted = window.add_entry(entry)
                if not accepted:
                    continue

                # 3. Evaluate rule conditions against updated window
                match = window.evaluate_rule(
                    rule=rule,
                    entity_type=group_field,
                    entity_key=entity_val,
                    current_time=event.timestamp,
                )

                if match:
                    metrics.inc_counter("correlation_matches_total")
                    logger.info(
                        "Correlation MATCH: '%s' for %s='%s' (%d events)",
                        match.rule_name,
                        match.entity_type,
                        match.entity_key,
                        match.matched_count,
                    )
                    matches.append(match)

        return matches

    def correlate(self, detection_ids: List[str]) -> List[CorrelationCluster]:
        """Ad-hoc clustering of detection IDs for BaseCorrelationEngine interface."""
        if not detection_ids:
            return []
        cluster = CorrelationCluster(
            cluster_id=f"cluster-{len(detection_ids)}",
            detection_ids=detection_ids,
            common_entities=[],
            confidence=1.0,
        )
        return [cluster]

    def reset_windows(self) -> None:
        """Clear all active sliding event windows (used for test and scenario isolation)."""
        with self._lock:
            self._windows.clear()

    def export_state(self) -> List[Dict[str, Any]]:
        """Export bounded window state for durable restart recovery."""
        with self._lock:
            return [
                {
                    "key": "|".join(key),
                    "rule_id": key[0],
                    "entity_type": key[1],
                    "entity_key": key[2],
                    "state": {
                        "window_seconds": window.window_seconds,
                        "last_triggered_at": (
                            window.last_triggered_at.isoformat()
                            if window.last_triggered_at
                            else None
                        ),
                        "entries": [
                            {
                                "timestamp": entry.timestamp.isoformat(),
                                "detection_id": entry.detection_id,
                                "event_id": entry.event_id,
                                "rule_id": entry.rule_id,
                                "rule_name": entry.rule_name,
                                "tags": entry.tags,
                                "severity": entry.severity.value,
                                "raw_event": entry.raw_event,
                            }
                            for entry in window.entries
                        ],
                    },
                }
                for key, window in self._windows.items()
            ]

    def import_state(self, states: List[Dict[str, Any]]) -> None:
        """Restore previously persisted windows, ignoring malformed rows safely."""
        with self._lock:
            for item in states:
                try:
                    key = (item["rule_id"], item["entity_type"], item["entity_key"])
                    payload = item["state"]
                    window = SlidingEventWindow(window_seconds=int(payload["window_seconds"]))
                    for raw in payload.get("entries", []):
                        window.add_entry(
                            WindowEntry(
                                timestamp=datetime.fromisoformat(raw["timestamp"]),
                                detection_id=raw["detection_id"],
                                event_id=raw["event_id"],
                                rule_id=raw["rule_id"],
                                rule_name=raw["rule_name"],
                                tags=list(raw.get("tags", [])),
                                severity=EventSeverityEnum(raw["severity"]),
                                raw_event=dict(raw.get("raw_event", {})),
                            )
                        )
                    triggered = payload.get("last_triggered_at")
                    window.last_triggered_at = (
                        datetime.fromisoformat(triggered) if triggered else None
                    )
                    self._windows[key] = window
                except (KeyError, TypeError, ValueError):
                    logger.warning("Skipping malformed persisted correlation window state")


# Default singleton instance
correlation_engine = CorrelationEngine()
