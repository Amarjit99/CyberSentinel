"""Integration tests for BenchmarkRunner and Benchmark API Endpoints."""

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from services.benchmark.runner import BenchmarkRunner


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {
        "X-Operator-Role": "ADMIN",
    }


@pytest.fixture
def analyst_headers() -> dict[str, str]:
    return {
        "X-Operator-Role": "SOC_ANALYST",
    }


def test_benchmark_runner_subset_execution():
    """Verify BenchmarkRunner executes an attack scenario and a negative control correctly."""
    runner = BenchmarkRunner()

    result = runner.run_benchmark_sync(
        scenario_ids=["SCN-01-AUTH-BRUTEFORCE", "SCN-NEG-01-BENIGN-AUTH"],
    )

    assert result.run_id.startswith("bmk-")
    assert result.dataset_id == "DS-CYBERSENTINEL-BENCHMARK-V1"
    assert result.dataset_version == "1.0.0"
    assert len(result.per_scenario_results) == 2

    # Check detection metrics
    det = result.detection_metrics
    assert det.total_scenarios_evaluated == 2
    assert det.true_positives == 1
    assert det.true_negatives == 1
    assert det.false_positives == 0
    assert det.false_negatives == 0
    assert det.precision == 1.0
    assert det.recall == 1.0
    assert det.f1_score == 1.0
    assert det.negative_control_alert_rate == 0.0

    # Check security metrics
    sec = result.security_metrics
    assert sec.actual_unsafe_dispatches == 0
    assert sec.safety_invariant_violations == 0

    # Check analyst agreement is explicitly NOT_EVALUABLE
    assert result.analyst_agreement.status.value == "NOT_EVALUABLE"
    assert "No independent analyst double-blind dataset available" in result.analyst_agreement.reason


def test_benchmark_runner_reproducibility():
    """Verify that deterministic benchmark runs produce identical evaluation decisions."""
    runner = BenchmarkRunner()

    res1 = runner.run_benchmark_sync(scenario_ids=["SCN-01-AUTH-BRUTEFORCE"])
    res2 = runner.run_benchmark_sync(scenario_ids=["SCN-01-AUTH-BRUTEFORCE"])

    assert res1.detection_metrics.true_positives == res2.detection_metrics.true_positives
    assert res1.detection_metrics.precision == res2.detection_metrics.precision
    assert res1.per_scenario_results[0].scenario_id == res2.per_scenario_results[0].scenario_id
    assert res1.per_scenario_results[0].passed == res2.per_scenario_results[0].passed
    assert res1.per_scenario_results[0].is_true_positive == res2.per_scenario_results[0].is_true_positive


def test_api_get_ground_truth(analyst_headers: dict[str, str]):
    """Verify GET /api/v1/benchmarks/ground-truth returns authoritative dataset."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/benchmarks/ground-truth", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["dataset_id"] == "DS-CYBERSENTINEL-BENCHMARK-V1"
        assert len(data["labels"]) == 16
        assert "SCN-01-AUTH-BRUTEFORCE" in data["labels"]
        assert "SCN-NEG-01-BENIGN-AUTH" in data["labels"]


def test_api_get_baselines(analyst_headers: dict[str, str]):
    """Verify GET /api/v1/benchmarks/baselines returns stored reference baselines."""
    with TestClient(app) as client:
        resp = client.get("/api/v1/benchmarks/baselines", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert "baseline_v1_0" in data


def test_api_run_benchmark(admin_headers: dict[str, str]):
    """Verify POST /api/v1/benchmarks/run executes benchmark and returns machine-readable results."""
    with TestClient(app) as client:
        payload = {
            "scenario_ids": ["SCN-01-AUTH-BRUTEFORCE", "SCN-NEG-01-BENIGN-AUTH"],
            "execution_mode": "deterministic_offline",
        }
        resp = client.post("/api/v1/benchmarks/run", json=payload, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["per_scenario_results"]) == 2
        assert data["detection_metrics"]["precision"] == 1.0
        assert data["security_metrics"]["actual_unsafe_dispatches"] == 0
        assert data["analyst_agreement"]["status"] == "NOT_EVALUABLE"


def test_api_compare_benchmark(admin_headers: dict[str, str]):
    """Verify POST /api/v1/benchmarks/compare against stored reference baseline."""
    runner = BenchmarkRunner()
    current_run = runner.run_benchmark_sync(scenario_ids=["SCN-01-AUTH-BRUTEFORCE"])

    with TestClient(app) as client:
        payload = {
            "run_result": current_run.model_dump(mode="json"),
            "baseline_id": "baseline_v1_0",
        }
        resp = client.post("/api/v1/benchmarks/compare", json=payload, headers=admin_headers)
        assert resp.status_code == 200
        comp_data = resp.json()
        assert comp_data["is_compatible"] is True
        assert "metric_deltas" in comp_data
