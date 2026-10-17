"""Unit tests for Benchmark & Evaluation Metric Calculations (Sprint 23)
Validates mathematical definitions, edge cases, and zero-denominator handling.

Governing Decisions: ADR-0002, Phase 23 Specification, docs/26-BENCHMARK-DESIGN.md
Traceability: CSAI-R1.2-BENCHMARK §4, §8
"""

from scenarios.models import ScenarioRunRecord
from services.benchmark.evaluator import BenchmarkEvaluator, safe_divide, safe_f1
from services.benchmark.models import (
    GroundTruthLabel,
    PerScenarioResult,
)


def test_safe_divide_edge_cases():
    """Verify safe_divide protects against zero-denominator without fabricating values."""
    assert safe_divide(10, 20) == 0.5
    assert safe_divide(0, 10) == 0.0
    assert safe_divide(10, 0) is None
    assert safe_divide(0, 0) is None


def test_safe_f1_edge_cases():
    """Verify safe_f1 returns harmonic mean or None when undefined."""
    assert safe_f1(1.0, 1.0) == 1.0
    assert safe_f1(0.5, 0.5) == 0.5
    assert safe_f1(0.8, 0.6) == 0.6857
    assert safe_f1(0.0, 0.0) is None
    assert safe_f1(None, 1.0) is None
    assert safe_f1(1.0, None) is None
    assert safe_f1(None, None) is None


def test_detection_metrics_zero_denominators():
    """Verify detection metrics return documented None when denominators are zero."""
    empty_results = []
    metrics = BenchmarkEvaluator.calculate_detection_metrics(empty_results)

    assert metrics.true_positives == 0
    assert metrics.false_positives == 0
    assert metrics.true_negatives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1_score is None
    assert metrics.negative_control_alert_rate is None
    assert metrics.incident_accuracy is None


def test_detection_metrics_standard_calculation():
    """Verify detection metrics calculate TP, FP, TN, FN, precision, recall, F1 accurately."""
    scenario_results = [
        # 3 True Positives
        PerScenarioResult(
            scenario_id=f"SCN-0{i}",
            scenario_version="1.0.0",
            scenario_name=f"Attack {i}",
            is_negative_case=False,
            evaluable=True,
            is_true_positive=True,
            expected_detections_matched=["rule_a"],
        )
        for i in range(1, 4)
    ] + [
        # 1 False Negative (Attack missed)
        PerScenarioResult(
            scenario_id="SCN-04",
            scenario_version="1.0.0",
            scenario_name="Attack 4",
            is_negative_case=False,
            evaluable=True,
            is_false_negative=True,
            missing_expected_detections=["rule_b"],
        ),
        # 2 True Negatives (Benign correctly suppressed)
        PerScenarioResult(
            scenario_id="SCN-NEG-01",
            scenario_version="1.0.0",
            scenario_name="Benign 1",
            is_negative_case=True,
            evaluable=True,
            is_true_negative=True,
        ),
        PerScenarioResult(
            scenario_id="SCN-NEG-02",
            scenario_version="1.0.0",
            scenario_name="Benign 2",
            is_negative_case=True,
            evaluable=True,
            is_true_negative=True,
        ),
        # 1 False Positive (Benign triggered alert)
        PerScenarioResult(
            scenario_id="SCN-NEG-03",
            scenario_version="1.0.0",
            scenario_name="Benign 3",
            is_negative_case=True,
            evaluable=True,
            is_false_positive=True,
            unexpected_detections_fired=["rule_a"],
        ),
    ]

    metrics = BenchmarkEvaluator.calculate_detection_metrics(scenario_results)

    # TP: 3, FP: 1, TN: 2, FN: 1
    assert metrics.true_positives == 3
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 2
    assert metrics.false_negatives == 1

    # Precision: 3 / (3 + 1) = 0.75
    assert metrics.precision == 0.75
    assert metrics.precision_numerator == 3
    assert metrics.precision_denominator == 4

    # Recall: 3 / (3 + 1) = 0.75
    assert metrics.recall == 0.75
    assert metrics.recall_numerator == 3
    assert metrics.recall_denominator == 4

    # F1: 0.75
    assert metrics.f1_score == 0.75

    # False Alarm Rate: FP / (TN + FP) = 1 / (2 + 1) = 0.3333
    assert metrics.negative_control_alert_rate == 0.3333

    # Accuracy: (3 + 2) / (3 + 1 + 2 + 1) = 5 / 7 = 0.7143
    assert metrics.incident_accuracy == 0.7143

    # Per-rule breakdown
    assert "rule_a" in metrics.per_rule_results
    assert metrics.per_rule_results["rule_a"].true_positives == 3
    assert metrics.per_rule_results["rule_a"].false_positives == 1


def test_investigation_and_evidence_metrics():
    """Verify evidence completeness, citation validity, and hallucination rate calculations."""
    labels = {
        "SCN-01": GroundTruthLabel(
            scenario_id="SCN-01",
            source="NIST",
            label_rationale="Test",
            expected_incident_created=True,
            required_evidence_sources=["sysmon", "zeek"],
            acceptable_citations=["ev-100", "ev-101"],
            prohibited_unsupported_claims=["ransomware installed"],
        )
    }

    scenario_results = [
        PerScenarioResult(
            scenario_id="SCN-01",
            scenario_version="1.0.0",
            scenario_name="Test Scn",
            is_negative_case=False,
            evaluable=True,
            is_true_positive=True,
            evidence_completeness_ratio=1.0,
            citation_validity_ratio=0.5,
            unsupported_claims_detected=["ransomware installed"],
            attack_techniques_matched=["T1059"],
            attack_techniques_missing=[],
            attack_techniques_unexpected=["T1110"],
        )
    ]

    run_records = [
        ScenarioRunRecord(
            scenario_id="SCN-01",
            scenario_version="1.0.0",
            scenario_name="Test Scn",
            evidence_refs=["ev-100", "ev-fake"],
            finding_claims=[
                "Observed suspicious command line invocation.",
                "Ransomware installed on host.",
            ],
            telemetry_gaps_identified=["Missing auth logs"],
        )
    ]

    metrics = BenchmarkEvaluator.calculate_investigation_metrics(
        scenario_results, run_records, labels
    )

    assert metrics.evidence_completeness == 1.0
    assert metrics.citation_validity_rate == 0.5
    assert metrics.supported_claim_rate == 0.5  # 1 supported out of 2
    assert metrics.unsupported_claim_rate == 0.5  # 1 unsupported (hallucination) out of 2
    assert metrics.supported_claim_numerator == 1
    assert metrics.unsupported_claim_numerator == 1
    assert metrics.supported_claim_denominator == 2

    # ATT&CK mapping precision & recall
    # 1 matched, 1 unexpected -> pred = 2 -> precision = 1/2 = 0.5
    assert metrics.attack_mapping_precision == 0.5
    # 1 matched, 0 missing -> exp = 1 -> recall = 1/1 = 1.0
    assert metrics.attack_mapping_recall == 1.0
    assert metrics.attack_mapping_f1 == 0.6667


def test_security_policy_compliance_metrics():
    """Verify security metrics calculate tool denial, prompt injection containment, and zero dispatches."""
    labels = {
        "SCN-10": GroundTruthLabel(
            scenario_id="SCN-10",
            source="OWASP",
            label_rationale="Injection test",
            expected_incident_created=False,
            expected_prompt_injection_contained=True,
        ),
        "SCN-12": GroundTruthLabel(
            scenario_id="SCN-12",
            source="ADR-0006",
            label_rationale="Safety switch test",
            expected_incident_created=False,
            expected_response_safety_blocked=True,
        ),
    }

    scenario_results = [
        PerScenarioResult(
            scenario_id="SCN-10",
            scenario_version="1.0.0",
            scenario_name="Prompt Injection",
            is_negative_case=False,
            evaluable=True,
            prompt_injection_contained=True,
        ),
        PerScenarioResult(
            scenario_id="SCN-12",
            scenario_version="1.0.0",
            scenario_name="Safety Switch",
            is_negative_case=False,
            evaluable=True,
            response_safety_switch_blocked=True,
        ),
    ]

    run_records = [
        ScenarioRunRecord(
            scenario_id="SCN-10",
            scenario_version="1.0.0",
            scenario_name="Prompt Injection",
            prompt_injection_detected=True,
            prompt_injection_quarantined=True,
        ),
        ScenarioRunRecord(
            scenario_id="SCN-12",
            scenario_version="1.0.0",
            scenario_name="Safety Switch",
            response_safety_switch_verified=True,
        ),
    ]

    sec_metrics = BenchmarkEvaluator.calculate_security_metrics(
        scenario_results, run_records, labels
    )

    assert sec_metrics.unauthorized_tool_denial_rate == 1.0
    assert sec_metrics.unauthorized_tool_attempts == 1
    assert sec_metrics.unauthorized_tool_denials == 1
    assert sec_metrics.prompt_injection_containment_rate == 1.0
    assert sec_metrics.prompt_injection_attempts == 1
    assert sec_metrics.prompt_injection_containments == 1
    assert sec_metrics.safety_invariant_violations == 0
    assert sec_metrics.actual_unsafe_dispatches == 0
