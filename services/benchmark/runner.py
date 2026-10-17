"""CyberSentinel AI — Benchmark Runner Harness (Sprint 23)
Orchestrates end-to-end benchmark execution across Sprint 22 scenarios,
evaluating pipeline behavior against authoritative ground-truth labels.

Governing Decisions: ADR-0002, ADR-0005, Phase 23 Specification, docs/26-BENCHMARK-DESIGN.md
Traceability: CSAI-R1.2-BENCHMARK §4, §5
"""

import logging
import platform
import sys
import time
from typing import List, Optional

from sqlalchemy.orm import Session

from packages.common import utc_now
from scenarios.catalogue import ScenarioCatalogue, default_scenario_catalogue
from scenarios.models import ScenarioCategoryEnum, ScenarioDefinition
from scenarios.runner import ScenarioRunner
from services.benchmark.evaluator import BenchmarkEvaluator
from services.benchmark.ground_truth import GroundTruthRepository, default_ground_truth_repo
from services.benchmark.models import (
    AnalystAgreementMetrics,
    BenchmarkExecutionModeEnum,
    BenchmarkRunResult,
    PerScenarioResult,
)

logger = logging.getLogger("cybersentinel.benchmark.runner")


class BenchmarkRunner:
    """Executes reproducible benchmark suites against ground-truth datasets.

    Non-negotiable invariants:
    1. NEVER executes live response actions (LIVE_RESPONSE_DISABLED=true enforced).
    2. Feeds genuine application components; does not use fake mock stubs for core logic.
    3. Evaluates against independent ground truth, never deriving labels from observed outputs.
    4. Explicitly handles zero-denominator edge cases without fabricating precision/recall.
    """

    def __init__(
        self,
        scenario_runner: Optional[ScenarioRunner] = None,
        catalogue: Optional[ScenarioCatalogue] = None,
        ground_truth_repo: Optional[GroundTruthRepository] = None,
    ) -> None:
        self.scenario_runner = scenario_runner or ScenarioRunner()
        self.catalogue = catalogue or default_scenario_catalogue
        self.ground_truth_repo = ground_truth_repo or default_ground_truth_repo

    async def run_benchmark(
        self,
        db_session: Optional[Session] = None,
        scenario_ids: Optional[List[str]] = None,
        category: Optional[ScenarioCategoryEnum] = None,
        execution_mode: BenchmarkExecutionModeEnum = BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE,
    ) -> BenchmarkRunResult:
        """Execute benchmark evaluation across selected or all catalogued scenarios."""
        start_time = time.perf_counter()
        started_at = utc_now()

        session_to_close = None
        if db_session is None:
            from services.persistence.database import SessionLocal
            db_session = SessionLocal()
            session_to_close = db_session

        try:
            # 1. Select Scenarios
            if scenario_ids:
                scenarios: List[ScenarioDefinition] = []
                for sid in scenario_ids:
                    scn = self.catalogue.get_scenario(sid)
                    if scn:
                        scenarios.append(scn)
                    else:
                        logger.warning("Requested scenario ID '%s' not found in catalogue", sid)
            elif category:
                scenarios = self.catalogue.list_scenarios(category=category.value)
            else:
                scenarios = self.catalogue.list_scenarios()

            # 2. Collect Environment Metadata safely
            env_metadata = {
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "live_response_disabled": True,
                "deterministic_rule_provider": True,
                "scenario_count": len(scenarios),
            }

            run_result = BenchmarkRunResult(
                started_at=started_at,
                dataset_id=self.ground_truth_repo.dataset_id,
                dataset_version=self.ground_truth_repo.version,
                ground_truth_version=self.ground_truth_repo.version,
                execution_mode=execution_mode,
                environment_metadata=env_metadata,
            )

            run_records = []
            scenario_results: List[PerScenarioResult] = []

            # 3. Execute Scenarios sequentially through authentic pipeline
            for scn in scenarios:
                try:
                    # Fetch ground truth label
                    label = self.ground_truth_repo.get_label(scn.scenario_id)
                    if not label:
                        # Missing ground truth: record error and mark not evaluable
                        run_result.notes.append(
                            f"Scenario '{scn.scenario_id}' lacks ground truth label; marked NOT_EVALUABLE."
                        )
                        from services.benchmark.models import GroundTruthLabel

                        label = GroundTruthLabel(
                            scenario_id=scn.scenario_id,
                            scenario_version=scn.version,
                            source="Unlabelled",
                            label_rationale="Ground truth missing from dataset",
                            evaluable=False,
                            not_evaluable_reason="Missing ground truth label",
                            expected_incident_created=False,
                        )

                    # Run scenario through genuine pipeline runner
                    record = await self.scenario_runner.run_scenario(scn, db_session)
                    run_records.append(record)

                    # Evaluate against ground truth
                    eval_res = BenchmarkEvaluator.evaluate_scenario(record, label)
                    scenario_results.append(eval_res)

                except Exception as scn_err:
                    err_msg = f"Scenario '{scn.scenario_id}' benchmark evaluation failed: {scn_err}"
                    run_result.errors.append(err_msg)
                    logger.exception(err_msg)

            # 4. Calculate Aggregate Metrics
            run_result.per_scenario_results = scenario_results
            run_result.detection_metrics = BenchmarkEvaluator.calculate_detection_metrics(scenario_results)
            run_result.investigation_metrics = BenchmarkEvaluator.calculate_investigation_metrics(
                scenario_results, run_records, self.ground_truth_repo.dataset.labels
            )
            run_result.security_metrics = BenchmarkEvaluator.calculate_security_metrics(
                scenario_results, run_records, self.ground_truth_repo.dataset.labels
            )
            perf_metrics = BenchmarkEvaluator.calculate_performance_metrics(run_records)
            perf_metrics.total_duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            perf_metrics.execution_mode = execution_mode
            run_result.performance_metrics = perf_metrics

            # Explicitly report Analyst Agreement as NOT_EVALUABLE (never fabricated)
            run_result.analyst_agreement = AnalystAgreementMetrics()

            run_result.completed_at = utc_now()
            logger.info(
                "Benchmark run '%s' completed: %d scenarios evaluated, detection precision: %s, recall: %s, F1: %s",
                run_result.run_id,
                len(scenario_results),
                run_result.detection_metrics.precision,
                run_result.detection_metrics.recall,
                run_result.detection_metrics.f1_score,
            )
        finally:
            if session_to_close:
                session_to_close.close()

        return run_result

    def run_benchmark_sync(
        self,
        db_session: Optional[Session] = None,
        scenario_ids: Optional[List[str]] = None,
        category: Optional[ScenarioCategoryEnum] = None,
        execution_mode: BenchmarkExecutionModeEnum = BenchmarkExecutionModeEnum.DETERMINISTIC_OFFLINE,
    ) -> BenchmarkRunResult:
        """Synchronous convenience wrapper for run_benchmark."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(
                    asyncio.run,
                    self.run_benchmark(
                        db_session=db_session,
                        scenario_ids=scenario_ids,
                        category=category,
                        execution_mode=execution_mode,
                    ),
                ).result()
        else:
            return asyncio.run(
                self.run_benchmark(
                    db_session=db_session,
                    scenario_ids=scenario_ids,
                    category=category,
                    execution_mode=execution_mode,
                )
            )


default_benchmark_runner = BenchmarkRunner()
