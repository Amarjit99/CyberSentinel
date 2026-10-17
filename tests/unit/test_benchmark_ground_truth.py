"""Unit tests for GroundTruthRepository in services.benchmark.ground_truth."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from services.benchmark.ground_truth import GroundTruthRepository
from services.benchmark.models import BenchmarkDataset, GroundTruthLabel


def test_load_default_ground_truth():
    """Verify that the default ground truth dataset loads validly and contains all 16 scenarios."""
    repo = GroundTruthRepository()
    dataset = repo.get_dataset()
    assert isinstance(dataset, BenchmarkDataset)
    assert dataset.dataset_id == "DS-CYBERSENTINEL-BENCHMARK-V1"
    assert dataset.version == "1.0.0"
    assert len(dataset.scenarios) == 16

    # Check known scenarios (12 attack + 4 negative controls)
    assert "SCN-01-AUTH-BRUTEFORCE" in dataset.scenarios
    assert "SCN-NEG-01-BENIGN-AUTH" in dataset.scenarios

    scn1 = repo.get_label("SCN-01-AUTH-BRUTEFORCE")
    assert scn1 is not None
    assert scn1.expected_incident_created is True
    assert scn1.evaluable is True
    assert "auth_root_failed" in scn1.expected_detections
    assert "T1110" in scn1.expected_attack_techniques
    assert "NIST SP 800-61r2" in scn1.source


def test_get_label_unknown_scenario():
    """Verify handling of unknown scenario IDs."""
    repo = GroundTruthRepository()
    label = repo.get_label("SCN-999-NONEXISTENT")
    assert label is None


def test_not_evaluable_scenario():
    """Verify behavior when a scenario is marked not evaluable."""
    label = GroundTruthLabel(
        scenario_id="SCN-99-TEST-INCOMPLETE",
        scenario_version="1.0.0",
        ground_truth_version="1.0.0",
        evaluable=False,
        not_evaluable_reason="Telemetry source deprecation and absence of authoritative ground truth",
        expected_detections=[],
        expected_non_detections=[],
        expected_incident_created=False,
        expected_incident_severity=None,
        expected_risk_band=None,
        expected_attack_techniques=[],
        required_evidence_sources=[],
        acceptable_citations=[],
        expected_investigation_conclusions=[],
        prohibited_unsupported_claims=[],
        expected_prompt_injection_contained=False,
        expected_response_safety_blocked=False,
        source="Test Lab Suite",
        label_rationale="Testing not_evaluable label enforcement",
    )
    assert label.evaluable is False
    assert label.not_evaluable_reason is not None
    assert "absence of authoritative ground truth" in label.not_evaluable_reason


def test_invalid_json_schema(tmp_path: Path):
    """Verify that invalid schema fails gracefully with ValidationError."""
    bad_file = tmp_path / "bad_gt.json"
    bad_file.write_text(
        '{"dataset_id": "test", "version": "1.0.0", "name": "bad", "description": "bad", "labels": {"SCN-1": {"scenario_id": "SCN-1"}}}',
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        GroundTruthRepository(file_path=bad_file)


def test_missing_file():
    """Verify that a nonexistent ground truth file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        GroundTruthRepository(file_path=Path("nonexistent/path/gt.json"))
