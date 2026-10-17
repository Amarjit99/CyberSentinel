"""CyberSentinel AI — Ingestion & System Metrics Registry"""

import threading
from typing import Dict, List, Union


class IngestionMetrics:
    """Thread-safe telemetry metrics aggregator for log ingestion."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events_received_total: int = 0
        self.events_normalized_total: int = 0
        self.events_persisted_total: int = 0
        self.events_duplicate_total: int = 0
        self.events_quarantined_total: int = 0
        self.events_dlq_total: int = 0
        self.events_replayed_total: int = 0
        self.events_evaluated_total: int = 0
        self.rules_active_total: int = 0
        self.rules_matched_total: int = 0
        self.detections_persisted_total: int = 0
        self.duplicate_detections_suppressed_total: int = 0
        self.rule_compilation_errors_total: int = 0
        self.rule_evaluation_errors_total: int = 0
        self._dynamic_counters: Dict[str, int] = {}
        self._dynamic_gauges: Dict[str, float] = {}
        self._latencies: List[float] = []

    def inc_counter(self, name: str, count: int = 1) -> None:
        with self._lock:
            self._dynamic_counters[name] = self._dynamic_counters.get(name, 0) + count

    def set_gauge(self, name: str, value: Union[int, float]) -> None:
        with self._lock:
            self._dynamic_gauges[name] = float(value)

    def inc_received(self, count: int = 1) -> None:
        with self._lock:
            self.events_received_total += count

    def inc_normalized(self, count: int = 1) -> None:
        with self._lock:
            self.events_normalized_total += count

    def inc_persisted(self, count: int = 1) -> None:
        with self._lock:
            self.events_persisted_total += count

    def inc_duplicate(self, count: int = 1) -> None:
        with self._lock:
            self.events_duplicate_total += count

    def inc_quarantined(self, count: int = 1) -> None:
        with self._lock:
            self.events_quarantined_total += count

    def inc_dlq(self, count: int = 1) -> None:
        with self._lock:
            self.events_dlq_total += count

    def inc_replayed(self, count: int = 1) -> None:
        with self._lock:
            self.events_replayed_total += count

    def inc_evaluated(self, count: int = 1) -> None:
        with self._lock:
            self.events_evaluated_total += count

    def set_active_rules(self, count: int) -> None:
        with self._lock:
            self.rules_active_total = count

    def inc_rules_matched(self, count: int = 1) -> None:
        with self._lock:
            self.rules_matched_total += count

    def inc_detections_persisted(self, count: int = 1) -> None:
        with self._lock:
            self.detections_persisted_total += count

    def inc_duplicate_detections_suppressed(self, count: int = 1) -> None:
        with self._lock:
            self.duplicate_detections_suppressed_total += count

    def inc_compilation_error(self, count: int = 1) -> None:
        with self._lock:
            self.rule_compilation_errors_total += count

    def inc_evaluation_error(self, count: int = 1) -> None:
        with self._lock:
            self.rule_evaluation_errors_total += count

    def record_latency(self, seconds: float) -> None:
        with self._lock:
            if len(self._latencies) > 1000:
                self._latencies.pop(0)
            self._latencies.append(seconds)

    def snapshot(self) -> Dict[str, float]:
        with self._lock:
            avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0.0
            return {
                "events_received_total": float(self.events_received_total),
                "events_normalized_total": float(self.events_normalized_total),
                "events_persisted_total": float(self.events_persisted_total),
                "events_duplicate_total": float(self.events_duplicate_total),
                "events_quarantined_total": float(self.events_quarantined_total),
                "events_dlq_total": float(self.events_dlq_total),
                "events_replayed_total": float(self.events_replayed_total),
                "events_evaluated_total": float(self.events_evaluated_total),
                "rules_active_total": float(self.rules_active_total),
                "rules_matched_total": float(self.rules_matched_total),
                "detections_persisted_total": float(self.detections_persisted_total),
                "duplicate_detections_suppressed_total": float(self.duplicate_detections_suppressed_total),
                "rule_compilation_errors_total": float(self.rule_compilation_errors_total),
                "rule_evaluation_errors_total": float(self.rule_evaluation_errors_total),
                "average_latency_seconds": round(avg_latency, 6),
                **{k: float(v) for k, v in self._dynamic_counters.items()},
                **{k: float(v) for k, v in self._dynamic_gauges.items()},
            }

    def reset(self) -> None:
        with self._lock:
            self.events_received_total = 0
            self.events_normalized_total = 0
            self.events_persisted_total = 0
            self.events_duplicate_total = 0
            self.events_quarantined_total = 0
            self.events_dlq_total = 0
            self.events_replayed_total = 0
            self.events_evaluated_total = 0
            self.rules_active_total = 0
            self.rules_matched_total = 0
            self.detections_persisted_total = 0
            self.duplicate_detections_suppressed_total = 0
            self.rule_compilation_errors_total = 0
            self.rule_evaluation_errors_total = 0
            self._dynamic_counters.clear()
            self._dynamic_gauges.clear()
            self._latencies.clear()


# Global singleton metrics instance
metrics = IngestionMetrics()
