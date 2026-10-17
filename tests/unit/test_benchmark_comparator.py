"""Unit tests for BaselineComparator in services.benchmark.comparator."""

from pathlib import Path

import pytest

from services.benchmark.comparator import BaselineComparator
from services.benchmark.models import (
    BenchmarkExecutionModeEnum,
    BenchmarkRunResult,
    DetectionQualityMetrics,
    InvestigationQualityMetrics,
    PerScenarioResult,
    SecurityPolicyMetrics,
)


def _create_mock_run(
    run_id: str,
    dataset_version: str = "1.0.0",
    ground_truth_version: str = "1.0.0",
    precision: float = 1.0,
    recall: float = 1.0,
    f1: float = 1.0,
    claim_supported_rate: float = 1.0,
    unauthorized_tool_denial_rate: float = 1.0,
    scenario_pass: bool = True,
) -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id=run_id,
        framework_version="1.2.0",
        dataset_id="DS-CYBERSENTINEL-BENCHMARK-V1",
        dataset_version=dataset_version,
        ground_truth_version=ground_truth_version,
        execution_mode=BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE,
        detection_metrics=DetectionQualityMetrics(
            total_scenarios_evaluated=1,
            true_positives=1,
            false_positives=0,
            true_negatives=0,
            false_negatives=0,
            precision=precision,
            recall=recall,
            f1_score=f1,
            negative_control_alert_rate=0.0,
            incident_creation_accuracy=1.0,
        ),
        investigation_metrics=InvestigationQualityMetrics(
            evidence_completeness_ratio=1.0,
            citation_validity_ratio=1.0,
            supported_claim_rate=claim_supported_rate,
            unsupported_claim_rate=1.0 - claim_supported_rate,
            attack_mapping_precision=1.0,
            attack_mapping_recall=1.0,
            attack_mapping_f1=1.0,
            telemetry_gap_accuracy=1.0,
        ),
        security_metrics=SecurityPolicyMetrics(
            unauthorized_tool_denial_rate=unauthorized_tool_denial_rate,
            prompt_injection_containment_rate=1.0,
            cross_incident_isolation_violations=0,
            secret_redaction_violations=0,
            safety_invariant_violations=0,
            unsafe_action_attempts=0,
            actual_unsafe_dispatches=0,
        ),
        per_scenario_results=[
            PerScenarioResult(
                scenario_id="SCN-01-AUTH-BRUTEFORCE",
                scenario_version="1.0.0",
                evaluable=True,
                passed=scenario_pass,
                is_true_positive=True,
                incident_matches_expectation=True,
            )
        ],
    )


def test_compare_compatible_runs_no_regressions():
    """Verify comparing two identical runs produces zero deltas and no regressions."""
    baseline = _create_mock_run("run-baseline")
    current = _create_mock_run("run-current")

    comp = BaselineComparator()
    res = comp.compare(current, baseline)

    assert res.is_compatible is True
    assert res.overall_verdict == "PASS"
    assert len(res.regressions_detected) == 0
    assert len(res.newly_failing_scenarios) == 0
    assert len(res.newly_passing_scenarios) == 0

    # Check metric delta
    prec_delta = res.metric_deltas.get("detection.precision")
    assert prec_delta is not None
    assert prec_delta.absolute_delta == 0.0
    assert prec_delta.relative_delta_percent == 0.0


def test_compare_detects_regressions():
    """Verify detection of precision drop, supported claim rate drop, and scenario failure."""
    baseline = _create_mock_run(
        "run-baseline",
        precision=1.0,
        recall=1.0,
        claim_supported_rate=0.95,
        scenario_pass=True,
    )
    current = _create_mock_run(
        "run-current",
        precision=0.75,
        recall=0.80,
        claim_supported_rate=0.70,
        scenario_pass=False,
    )

    comp = BaselineComparator()
    res = comp.compare(current, baseline)

    assert res.is_compatible is True
    assert res.overall_verdict == "REGRESSION_DETECTED"
    assert "SCN-01-AUTH-BRUTEFORCE" in res.newly_failing_scenarios

    # Check regressions list contains specific metric warnings
    reg_text = " ".join(res.regressions_detected)
    assert "detection.precision" in reg_text
    assert "detection.recall" in reg_text
    assert "investigation.supported_claim_rate" in reg_text


def test_compare_incompatible_dataset_version():
    """Verify that comparing runs with mismatched dataset versions is rejected."""
    baseline = _create_mock_run("run-baseline", ground_truth_version="1.0.0")
    current = _create_mock_run("run-current", ground_truth_version="2.0.0")

    comp = BaselineComparator()
    res = comp.compare(current, baseline)

    assert res.is_compatible is False
    assert res.overall_verdict == "INCOMPATIBLE"
    assert len(res.compatibility_reasons) > 0


def test_baseline_save_and_overwrite_protection(tmp_path: Path):
    """Verify that save_baseline persists JSON and prevents silent overwriting."""
    comp = BaselineComparator(baselines_dir=tmp_path)
    run = _create_mock_run("baseline-test-run")

    file_path = comp.save_baseline("test_base_v1", run)
    assert file_path.exists()

    # Attempting to save without overwrite should raise FileExistsError
    with pytest.raises(FileExistsError):
        comp.save_baseline("test_base_v1", run, overwrite=False)

    # With overwrite=True, it should succeed
    comp.save_baseline("test_base_v1", run, overwrite=True)

    # Loading the baseline should work
    loaded = comp.load_baseline("test_base_v1")
    assert loaded.run_id == "baseline-test-run"


def test_load_nonexistent_baseline(tmp_path: Path):
    """Verify loading a nonexistent baseline raises FileNotFoundError."""
    comp = BaselineComparator(baselines_dir=tmp_path)
    with pytest.raises(FileNotFoundError):
        comp.load_baseline("nonexistent_baseline")
