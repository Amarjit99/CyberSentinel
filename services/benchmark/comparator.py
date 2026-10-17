"""CyberSentinel AI — Benchmark Baseline Comparator (Sprint 23)
Compares benchmark run results against stored versioned baselines,
detecting regressions and validating dataset compatibility without silent overwrites.

Governing Decisions: ADR-0002, Phase 23 Specification, docs/26-BENCHMARK-DESIGN.md
Traceability: CSAI-R1.2-BENCHMARK §6
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union

from services.benchmark.models import (
    BaselineComparisonResult,
    BenchmarkRunResult,
    MetricDelta,
)

logger = logging.getLogger("cybersentinel.benchmark.comparator")

DEFAULT_BASELINES_DIR = Path(__file__).parent.parent.parent / "benchmarks" / "baselines"


class IncompatibleBaselineError(Exception):
    """Raised when an attempted comparison involves incompatible datasets or versions."""

    pass


class BaselineComparator:
    """Compares benchmark evaluation results against stored reference baselines.

    Non-negotiable invariants:
    1. Baselines are NEVER silently overwritten. Establishing a new baseline requires explicit action.
    2. Comparisons are rejected if dataset IDs or ground-truth versions are incompatible.
    3. Regressions are strictly flagged for security compliance and detection drop-offs.
    """

    def __init__(self, baselines_dir: Optional[Union[str, Path]] = None) -> None:
        self.baselines_dir = Path(baselines_dir or DEFAULT_BASELINES_DIR)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)

    def load_baseline(self, baseline_id: str) -> BenchmarkRunResult:
        """Load a stored baseline by filename or ID."""
        file_path = self.baselines_dir / f"{baseline_id}.json"
        if not file_path.is_file():
            # Try with literal baseline_id
            candidates = list(self.baselines_dir.glob("*.json"))
            match = next((c for c in candidates if c.stem == baseline_id or c.name == baseline_id), None)
            if not match:
                raise FileNotFoundError(f"Baseline '{baseline_id}' not found in '{self.baselines_dir}'")
            file_path = match

        raw = json.loads(file_path.read_text(encoding="utf-8"))
        return BenchmarkRunResult.model_validate(raw)

    def save_baseline(
        self,
        arg1: Union[str, BenchmarkRunResult],
        arg2: Union[str, BenchmarkRunResult],
        overwrite: bool = False,
    ) -> Path:
        """Explicitly establish and persist a benchmark run as a versioned reference baseline.

        Non-negotiable: Overwrite is False by default to prevent silent overwrites.
        """
        if isinstance(arg1, str):
            baseline_name = arg1
            if not isinstance(arg2, BenchmarkRunResult):
                raise TypeError("arg2 must be a BenchmarkRunResult when arg1 is a baseline name")
            run_result = arg2
        else:
            if not isinstance(arg2, str):
                raise TypeError("arg2 must be a string when arg1 is a BenchmarkRunResult")
            run_result = arg1
            baseline_name = arg2

        dest_path = self.baselines_dir / f"{baseline_name}.json"
        if dest_path.exists() and not overwrite:
            raise FileExistsError(
                f"Baseline file '{dest_path.name}' already exists. "
                "Explicit overwrite=True parameter is required to update a baseline."
            )

        data = run_result.model_dump(mode="json")
        dest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Persisted benchmark run '%s' as baseline '%s'", run_result.run_id, dest_path.name)
        return dest_path

    def list_baselines(self) -> List[str]:
        """List all available baseline IDs."""
        return [f.stem for f in self.baselines_dir.glob("*.json")]

    def compare(
        self,
        current_run: BenchmarkRunResult,
        baseline: Union[str, BenchmarkRunResult],
        tolerance: float = 0.001,
    ) -> BaselineComparisonResult:
        """Compare a benchmark run against a baseline and flag regressions."""
        if isinstance(baseline, str):
            baseline_result = self.load_baseline(baseline)
        else:
            baseline_result = baseline

        # 1. Compatibility Check
        reasons: List[str] = []
        is_compatible = True

        if current_run.dataset_id != baseline_result.dataset_id:
            is_compatible = False
            reasons.append(
                f"Dataset mismatch: current run uses '{current_run.dataset_id}', baseline uses '{baseline_result.dataset_id}'"
            )

        if current_run.ground_truth_version != baseline_result.ground_truth_version:
            is_compatible = False
            reasons.append(
                f"Ground truth version mismatch: current '{current_run.ground_truth_version}' vs baseline '{baseline_result.ground_truth_version}'"
            )

        # Compare evaluated scenarios overlap
        current_scenarios = {r.scenario_id for r in current_run.per_scenario_results}
        baseline_scenarios = {r.scenario_id for r in baseline_result.per_scenario_results}
        missing_in_current = baseline_scenarios - current_scenarios
        if missing_in_current:
            reasons.append(f"Current run evaluated fewer scenarios; missing from baseline: {missing_in_current}")

        cmp_res = BaselineComparisonResult(
            baseline_id=baseline_result.run_id,
            baseline_version=baseline_result.framework_version,
            run_id=current_run.run_id,
            is_compatible=is_compatible,
            compatibility_reasons=reasons,
            overall_verdict="PASS" if is_compatible else "INCOMPATIBLE",
        )

        if not is_compatible:
            return cmp_res

        # 2. Metric Delta Computations
        deltas: Dict[str, MetricDelta] = {}
        regressions: List[str] = []

        # Define metrics: (metric_path, metric_name, higher_is_better)
        metric_definitions = [
            ("detection.precision", current_run.detection_metrics.precision, baseline_result.detection_metrics.precision, True),
            ("detection.recall", current_run.detection_metrics.recall, baseline_result.detection_metrics.recall, True),
            ("detection.f1_score", current_run.detection_metrics.f1_score, baseline_result.detection_metrics.f1_score, True),
            ("detection.negative_control_alert_rate", current_run.detection_metrics.negative_control_alert_rate, baseline_result.detection_metrics.negative_control_alert_rate, False),
            ("investigation.evidence_completeness", current_run.investigation_metrics.evidence_completeness, baseline_result.investigation_metrics.evidence_completeness, True),
            ("investigation.citation_validity_rate", current_run.investigation_metrics.citation_validity_rate, baseline_result.investigation_metrics.citation_validity_rate, True),
            ("investigation.supported_claim_rate", current_run.investigation_metrics.supported_claim_rate, baseline_result.investigation_metrics.supported_claim_rate, True),
            ("investigation.unsupported_claim_rate", current_run.investigation_metrics.unsupported_claim_rate, baseline_result.investigation_metrics.unsupported_claim_rate, False),
            ("investigation.attack_mapping_f1", current_run.investigation_metrics.attack_mapping_f1, baseline_result.investigation_metrics.attack_mapping_f1, True),
            ("security.unauthorized_tool_denial_rate", current_run.security_metrics.unauthorized_tool_denial_rate, baseline_result.security_metrics.unauthorized_tool_denial_rate, True),
            ("security.prompt_injection_containment_rate", current_run.security_metrics.prompt_injection_containment_rate, baseline_result.security_metrics.prompt_injection_containment_rate, True),
            ("security.actual_unsafe_dispatches", float(current_run.security_metrics.actual_unsafe_dispatches), float(baseline_result.security_metrics.actual_unsafe_dispatches), False),
        ]

        for m_name, cur_val, base_val, higher_is_better in metric_definitions:
            if cur_val is None and base_val is None:
                continue

            abs_delta: Optional[float] = None
            rel_delta: Optional[float] = None
            is_reg = False

            if cur_val is not None and base_val is not None:
                abs_delta = round(cur_val - base_val, 4)
                if abs(base_val) > 1e-6:
                    rel_delta = round((abs_delta / base_val) * 100.0, 2)

                if higher_is_better:
                    if abs_delta < -tolerance:
                        is_reg = True
                else:
                    if abs_delta > tolerance:
                        is_reg = True

            elif cur_val is None and base_val is not None:
                # Regressed from a computed metric to undefined
                is_reg = True
            elif cur_val is not None and base_val is None:
                # Improved from undefined to computed
                is_reg = False

            if is_reg:
                regressions.append(m_name)

            deltas[m_name] = MetricDelta(
                metric_name=m_name,
                baseline_value=base_val,
                current_value=cur_val,
                absolute_delta=abs_delta,
                relative_delta_percent=rel_delta,
                is_regression=is_reg,
                regression_threshold=tolerance,
            )

        cmp_res.metric_deltas = deltas
        cmp_res.regressions_detected = regressions

        # 3. Per-Scenario Transitions
        cur_passed = {r.scenario_id for r in current_run.per_scenario_results if r.passed}
        base_passed = {r.scenario_id for r in baseline_result.per_scenario_results if r.passed}

        cmp_res.newly_failing_scenarios = sorted(list(base_passed - cur_passed))
        cmp_res.newly_passing_scenarios = sorted(list(cur_passed - base_passed))

        if regressions or cmp_res.newly_failing_scenarios:
            cmp_res.overall_verdict = "REGRESSION_DETECTED"
        else:
            cmp_res.overall_verdict = "PASS"

        return cmp_res


default_baseline_comparator = BaselineComparator()
