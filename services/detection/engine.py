"""CyberSentinel AI — Sigma Detection Engine
Evaluates CanonicalEvents against compiled Sigma rules in real-time.
Governing Decisions: ADR-0005, CSAI-P3-DETECTION
"""

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from packages.observability.metrics import metrics
from schemas.canonical_event import CanonicalEvent
from services.detection import BaseDetectionEngine, DetectionMatch
from services.detection.compiler import CompiledSigmaRule, SigmaCompilationError, SigmaCompiler

logger = logging.getLogger("cybersentinel.detection")


class SigmaDetectionEngine(BaseDetectionEngine):
    """Production Sigma detection engine evaluating CanonicalEvents against registered rules."""

    def __init__(self, compiler: Optional[SigmaCompiler] = None) -> None:
        self.compiler = compiler or SigmaCompiler()
        self._rules: Dict[str, CompiledSigmaRule] = {}
        self._lock = threading.RLock()

    @property
    def rule_count(self) -> int:
        """Return the number of active compiled detection rules."""
        with self._lock:
            return len(self._rules)

    def load_rule(self, yaml_content: str, source_name: Optional[str] = None) -> CompiledSigmaRule:
        """Compile and register a single Sigma rule from YAML."""
        try:
            compiled = self.compiler.compile_from_yaml(yaml_content, source_path=source_name)
            with self._lock:
                self._rules[compiled.id] = compiled
                metrics.set_active_rules(len(self._rules))
            return compiled
        except SigmaCompilationError as err:
            metrics.inc_compilation_error()
            logger.warning("Failed to compile Sigma rule '%s': %s", source_name or "inline", err)
            raise

    def load_rules_from_directory(self, dir_path: Union[str, Path]) -> int:
        """Scan a directory for .yml/.yaml Sigma rules and compile them."""
        path = Path(dir_path)
        if not path.is_dir():
            logger.warning("Sigma rules directory does not exist: %s", path)
            return 0

        loaded_count = 0
        rule_files = list(path.glob("**/*.yml")) + list(path.glob("**/*.yaml"))

        for rf in rule_files:
            if rf.name.lower() in ("readme.md", "metadata.yaml"):
                continue
            try:
                content = rf.read_text(encoding="utf-8")
                self.load_rule(content, source_name=rf.name)
                loaded_count += 1
            except Exception as ex:
                metrics.inc_compilation_error()
                logger.error("Error loading rule file '%s': %s", rf.name, ex)

        return loaded_count

    def get_rule(self, rule_id: str) -> Optional[CompiledSigmaRule]:
        """Fetch active rule by ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def get_active_rules(self) -> List[CompiledSigmaRule]:
        """Return all active compiled rules."""
        with self._lock:
            return list(self._rules.values())

    list_rules = get_active_rules

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the active registry."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                metrics.set_active_rules(len(self._rules))
                return True
            return False

    def clear_rules(self) -> None:
        """Clear all active rules and compiler cache."""
        with self._lock:
            self._rules.clear()
            self.compiler.clear_cache()
            metrics.set_active_rules(0)

    def evaluate(self, event: CanonicalEvent) -> List[DetectionMatch]:
        """Evaluate a validated CanonicalEvent against all registered Sigma rules."""
        event_dict = event.model_dump(mode="json")
        matches = self.evaluate_dict(event_dict, event_id=str(event.event_id))
        return matches

    def evaluate_dict(
        self, event_dict: Dict[str, Any], event_id: Optional[str] = None
    ) -> List[DetectionMatch]:
        """Evaluate a raw event dictionary against all registered Sigma rules."""
        metrics.inc_evaluated()
        target_event_id = event_id or str(event_dict.get("event_id") or "unknown")
        matches: List[DetectionMatch] = []

        with self._lock:
            rules_to_eval = list(self._rules.values())

        for rule in rules_to_eval:
            try:
                matched = rule.evaluate(event_dict)
                if matched:
                    metrics.inc_rules_matched()
                    match = DetectionMatch(
                        rule_id=rule.id,
                        rule_name=rule.title,
                        severity=rule.severity,
                        matched_event_ids=[target_event_id],
                        mitre_attack_ids=rule.mitre_attack_ids,
                    )
                    matches.append(match)
            except Exception as ex:
                metrics.inc_evaluation_error()
                logger.debug(
                    "Error evaluating rule '%s' on event '%s': %s",
                    rule.id,
                    target_event_id,
                    ex,
                )

        return matches


# Default singleton instance
detection_engine = SigmaDetectionEngine()
