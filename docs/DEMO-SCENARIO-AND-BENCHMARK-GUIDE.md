# Demo Scenario and Benchmark Reproduction Guide

## Safety boundary

The scenario and benchmark suites use synthetic or approved data only. They do not contact
external providers and must not be pointed at production systems. Keep
`LIVE_RESPONSE_DISABLED=true` and `DRY_RUN_DEFAULT=true`.

## Scenario inventory

The catalogue contains 12 positive attack scenarios and 4 negative controls under
`scenarios/fixtures/`. Positive scenarios cover authentication abuse, suspicious process
execution, credential misuse, DNS/network activity, lateral movement, account takeover,
multi-stage intrusion, prompt injection, poisoned knowledge, and unauthorized tool use.
Negative controls cover benign authentication, legitimate administration, benign DNS, and
malformed telemetry.

## Reproduce the defensive demo

Run the scenario and security regression coverage from the repository root:

```powershell
.\.venv\Scripts\pytest.exe `
  tests/unit/test_scenario_framework.py `
  tests/integration/test_scenario_pipeline.py `
  tests/security/test_scenario_security.py -q
```

The runner feeds fixture events through canonical validation, Sigma detection, correlation,
incident handling, deterministic risk, bounded triage/investigation, evidence checks, and
response safety checks. The result records observed behavior separately from expected
ground truth; a missing detection is a failure, not an implicit success.

## Benchmark reproduction

The benchmark dataset and immutable baseline are:

- `benchmarks/ground_truth/ground_truth_v1.json`
- `benchmarks/baselines/baseline_v1_0.json`

Run the benchmark-focused validation:

```powershell
.\.venv\Scripts\pytest.exe `
  tests/unit/test_benchmark_metrics.py `
  tests/unit/test_benchmark_ground_truth.py `
  tests/unit/test_benchmark_comparator.py `
  tests/integration/test_benchmark_runner.py `
  tests/security/test_benchmark_security.py -q
```

Metrics with an undefined denominator are reported as `None`, not fabricated as zero or one.
Analyst agreement is `NOT_EVALUABLE` unless an independent labeled human dataset exists.
Comparisons must use compatible dataset and ground-truth versions; baseline overwrites require
an explicit opt-in.

## Interpretation

Benchmark results measure the versioned fixtures, rules, policies, provider configuration,
and code revision used for the run. They do not establish production detection rates,
generalize to unseen organizations, or authorize live response. Report scenario failures,
negative-control alerts, unsupported claims, tool-policy violations, and safety breaches
alongside aggregate precision, recall, and F1.
