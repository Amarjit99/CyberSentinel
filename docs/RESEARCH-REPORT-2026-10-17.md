# CyberSentinel AI Research Report — Reproducibility Record

## Scope

This document is a reproducibility record for the version 1.0.0 benchmark framework. It is
not a claim of production detection accuracy or a statistically powered organizational study.
The current repository contains versioned synthetic scenarios, ground truth, metrics, and a
baseline comparator. A measured result must be generated from an executed benchmark run and
stored with its configuration.

## Reproduction inputs

- Scenario fixtures: `scenarios/fixtures/` (12 positive scenarios and 4 negative controls)
- Ground truth: `benchmarks/ground_truth/ground_truth_v1.json`
- Baseline: `benchmarks/baselines/baseline_v1_0.json`
- Benchmark implementation: `services/benchmark/`
- Safety invariant: `LIVE_RESPONSE_DISABLED=true`
- Application release: `1.0.0`

## Reproduction command

```powershell
.\.venv\Scripts\pytest.exe `
  tests/unit/test_benchmark_metrics.py `
  tests/unit/test_benchmark_ground_truth.py `
  tests/unit/test_benchmark_comparator.py `
  tests/integration/test_benchmark_runner.py `
  tests/security/test_benchmark_security.py -q
```

The benchmark API can execute a configured run through
`POST /api/v1/benchmarks/run`; compare a result through
`POST /api/v1/benchmarks/compare`. Retain the request configuration, dataset version,
baseline version, application version, model/provider reference, prompt-template version,
and returned metrics together.

## Measurement rules

- Precision, recall, and F1 use explicit integer numerators and denominators.
- Undefined ratios remain `null`/`None`; they are not converted into fabricated scores.
- Analyst agreement is `NOT_EVALUABLE` until an independent human-labelled dataset exists.
- Negative controls are reported separately from positive detection performance.
- Unsupported claims, invalid citations, tool-policy violations, prompt-injection failures,
  and unsafe dispatches are reported as safety outcomes, not hidden in aggregate accuracy.

## Current evidence boundary

The automated benchmark tests verify schema validation, mathematical correctness, baseline
compatibility, scenario execution contracts, and safety enforcement. They do not by themselves
constitute a measured research result. Future runs must publish the returned metrics, failures,
confidence intervals where appropriate, configuration, and limitations without changing the
ground truth to improve a score.

## Limitations

The suite is synthetic and small, provider/model drift is possible, and deployment latency and
human workflow time are not represented by unit or integration tests. Docker/runtime validation,
browser E2E/accessibility validation, and independent security review are separate release
prerequisites.
