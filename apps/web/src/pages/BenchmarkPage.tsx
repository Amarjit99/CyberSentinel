import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Badge, EmptyState } from "../components/common";
import {
  BaselineComparison,
  BenchmarkRunResult,
  GroundTruthDataset,
} from "../types";

export function BenchmarkPage() {
  const [tab, setTab] = useState<"results" | "ground_truth" | "comparison">("results");
  const [groundTruth, setGroundTruth] = useState<GroundTruthDataset | null>(null);
  const [baselines, setBaselines] = useState<string[]>([]);
  const [selectedBaseline, setSelectedBaseline] = useState<string>("baseline_v1_0");
  const [runResult, setRunResult] = useState<BenchmarkRunResult | null>(null);
  const [comparison, setComparison] = useState<BaselineComparison | null>(null);

  const [loading, setLoading] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [executionMode, setExecutionMode] = useState<"deterministic_offline" | "offline_mock" | "online_hybrid">("deterministic_offline");
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [gtRes, baseRes] = await Promise.allSettled([
        api.getGroundTruth(),
        api.getBaselines(),
      ]);

      if (gtRes.status === "fulfilled") setGroundTruth(gtRes.value);
      if (baseRes.status === "fulfilled") {
        const val = baseRes.value;
        const list = Array.isArray(val) ? val : "baselines" in val ? val.baselines : [];
        setBaselines(list);
        if (list.length > 0) setSelectedBaseline(list[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed loading benchmark data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRunBenchmark = async () => {
    setIsRunning(true);
    setError(null);
    setActionSuccess(null);
    setComparison(null);
    try {
      const res = await api.runBenchmark(executionMode);
      setRunResult(res);
      setActionSuccess(`Benchmark execution finished in ${res.metrics.operations.duration_ms.toFixed(1)} ms. Evaluated ${res.metrics.operations.total_scenarios_evaluated} scenarios.`);
      setTab("results");

      // Auto-trigger comparison against baseline if baseline is available
      if (selectedBaseline) {
        try {
          const comp = await api.compareBenchmark(res, selectedBaseline);
          setComparison(comp);
        } catch {
          // ignore comparison error
        }
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`[${err.errorCode}] ${err.message}`);
      } else {
        setError(err instanceof Error ? err.message : "Benchmark run failed.");
      }
    } finally {
      setIsRunning(false);
    }
  };

  const handleCompare = async () => {
    if (!runResult || !selectedBaseline) return;
    setIsRunning(true);
    setError(null);
    try {
      const comp = await api.compareBenchmark(runResult, selectedBaseline);
      setComparison(comp);
      setTab("comparison");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(`[${err.errorCode}] ${err.message}`);
      } else {
        setError(err instanceof Error ? err.message : "Comparison failed.");
      }
    } finally {
      setIsRunning(false);
    }
  };

  const m = runResult?.metrics;

  return (
    <div className="benchmark-page">
      <div className="tab-bar">
        <button
          className={`tab-item ${tab === "results" ? "active" : ""}`}
          onClick={() => setTab("results")}
          type="button"
        >
          ▥ Benchmark Evaluation Results {runResult && `(${runResult.execution_mode})`}
        </button>
        <button
          className={`tab-item ${tab === "ground_truth" ? "active" : ""}`}
          onClick={() => setTab("ground_truth")}
          type="button"
        >
          📜 Independent Ground Truth ({groundTruth?.labels?.length || groundTruth?.scenarios?.length || 0} Scenarios)
        </button>
        <button
          className={`tab-item ${tab === "comparison" ? "active" : ""}`}
          onClick={() => setTab("comparison")}
          type="button"
        >
          ⚖ Baseline Regression Comparison
        </button>
      </div>

      {/* Runner Bar */}
      <section className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-heading">
          <div>
            <h2>Standardized Evaluation Runner (Sprint 23)</h2>
            <span className="muted">Multi-mode defensive validation against ground truth dataset</span>
          </div>
          <div className="runner-controls">
            <select
              className="filter-select"
              value={executionMode}
              onChange={(e) => setExecutionMode(e.target.value as "deterministic_offline" | "offline_mock" | "online_hybrid")}
              disabled={isRunning}
            >
              <option value="deterministic_offline">Deterministic Offline (Zero External Calls)</option>
              <option value="offline_mock">Offline Mocked Dependencies</option>
              <option value="online_hybrid">Online Hybrid (Live Evaluator)</option>
            </select>
            <button
              className="button-primary"
              onClick={handleRunBenchmark}
              disabled={isRunning}
              type="button"
            >
              {isRunning ? "Running Benchmark…" : "▶ Run Evaluation"}
            </button>
          </div>
        </div>

        {error && (
          <div className="alert-box error" role="alert" style={{ marginTop: "10px" }}>
            {error}
          </div>
        )}
        {actionSuccess && (
          <div className="alert-box success" role="status" style={{ marginTop: "10px" }}>
            {actionSuccess}
          </div>
        )}
      </section>

      {/* Tab 1: Results */}
      {tab === "results" && (
        <div>
          {!runResult ? (
            <section className="panel">
              <EmptyState
                text="No benchmark run executed in this session. Click '▶ Run Evaluation' above to evaluate detection quality, investigation grounding, and safety invariance."
              />
            </section>
          ) : (
            <div>
              {/* Metric Scoreboard Cards */}
              <div className="metric-grid" style={{ marginBottom: "16px" }}>
                <div className="metric-card">
                  <span className="metric-label">Precision (TP / [TP + FP])</span>
                  <strong>{m?.detection_quality.precision !== null && m?.detection_quality.precision !== undefined ? `${(m.detection_quality.precision * 100).toFixed(1)}%` : "N/A"}</strong>
                  <span className="metric-link">TP: {m?.detection_quality.true_positives} | FP: {m?.detection_quality.false_positives}</span>
                </div>

                <div className="metric-card">
                  <span className="metric-label">Recall (TP / [TP + FN])</span>
                  <strong>{m?.detection_quality.recall !== null && m?.detection_quality.recall !== undefined ? `${(m.detection_quality.recall * 100).toFixed(1)}%` : "N/A"}</strong>
                  <span className="metric-link">TP: {m?.detection_quality.true_positives} | FN: {m?.detection_quality.false_negatives}</span>
                </div>

                <div className="metric-card">
                  <span className="metric-label">F1-Score</span>
                  <strong>{m?.detection_quality.f1 !== null && m?.detection_quality.f1 !== undefined ? `${(m.detection_quality.f1 * 100).toFixed(1)}%` : "N/A"}</strong>
                  <span className="metric-link">Harmonic mean</span>
                </div>

                <div className="metric-card">
                  <span className="metric-label">Actual Unsafe Dispatches</span>
                  <strong className="text-healthy">{m?.security_policy.actual_unsafe_dispatches ?? 0}</strong>
                  <span className="metric-link text-healthy">Invariant: STRICTLY 0</span>
                </div>
              </div>

              {/* Detailed Breakdown Panels */}
              <div className="panel-grid">
                {/* Detection Quality */}
                <article className="panel">
                  <div className="panel-heading">
                    <h3>Detection Quality Metrics</h3>
                    <Badge label={`Dataset: ${runResult.dataset_version}`} variant="neutral" />
                  </div>
                  <div className="health-details">
                    <div className="health-row">
                      <span>True Positives (TP):</span>
                      <strong>{m?.detection_quality.true_positives}</strong>
                    </div>
                    <div className="health-row">
                      <span>False Positives (FP):</span>
                      <strong>{m?.detection_quality.false_positives}</strong>
                    </div>
                    <div className="health-row">
                      <span>True Negatives (TN):</span>
                      <strong>{m?.detection_quality.true_negatives}</strong>
                    </div>
                    <div className="health-row">
                      <span>False Negatives (FN):</span>
                      <strong>{m?.detection_quality.false_negatives}</strong>
                    </div>
                    <div className="health-row">
                      <span>Negative Control Alert Rate:</span>
                      <strong>
                        {m?.detection_quality.negative_control_alert_rate !== null && m?.detection_quality.negative_control_alert_rate !== undefined
                          ? `${(m.detection_quality.negative_control_alert_rate * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                    <div className="health-row">
                      <span>Incident Creation Accuracy:</span>
                      <strong>
                        {m?.detection_quality.incident_creation_accuracy !== null && m?.detection_quality.incident_creation_accuracy !== undefined
                          ? `${(m.detection_quality.incident_creation_accuracy * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                  </div>
                </article>

                {/* Investigation Quality & Safety */}
                <article className="panel">
                  <div className="panel-heading">
                    <h3>Investigation & Safety Invariants</h3>
                    <Badge label="Grounded Citations" variant="healthy" />
                  </div>
                  <div className="health-details">
                    <div className="health-row">
                      <span>Evidence Completeness:</span>
                      <strong>
                        {m?.investigation_quality.evidence_completeness !== null && m?.investigation_quality.evidence_completeness !== undefined
                          ? `${(m.investigation_quality.evidence_completeness * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                    <div className="health-row">
                      <span>Citation Validity Rate:</span>
                      <strong>
                        {m?.investigation_quality.citation_validity_rate !== null && m?.investigation_quality.citation_validity_rate !== undefined
                          ? `${(m.investigation_quality.citation_validity_rate * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                    <div className="health-row">
                      <span>Supported Claim Rate:</span>
                      <strong>
                        {m?.investigation_quality.supported_claim_rate !== null && m?.investigation_quality.supported_claim_rate !== undefined
                          ? `${(m.investigation_quality.supported_claim_rate * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                    <div className="health-row">
                      <span>Unsupported Claim Rate:</span>
                      <strong className={m?.investigation_quality.unsupported_claim_rate === 0 ? "text-healthy" : "text-critical"}>
                        {m?.investigation_quality.unsupported_claim_rate !== null && m?.investigation_quality.unsupported_claim_rate !== undefined
                          ? `${(m.investigation_quality.unsupported_claim_rate * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                    <div className="health-row">
                      <span>Unauthorized Tool Denial:</span>
                      <strong>
                        {m?.security_policy.unauthorized_tool_denial_rate !== null && m?.security_policy.unauthorized_tool_denial_rate !== undefined
                          ? `${(m.security_policy.unauthorized_tool_denial_rate * 100).toFixed(1)}%`
                          : "N/A"}
                      </strong>
                    </div>
                  </div>
                </article>
              </div>

              {/* Per-Scenario Results Table */}
              {runResult.per_scenario_results && Object.keys(runResult.per_scenario_results).length > 0 && (
                <section className="panel" style={{ marginTop: "16px" }}>
                  <div className="panel-heading">
                    <h3>Per-Scenario Evaluation Breakdown ({Object.keys(runResult.per_scenario_results).length})</h3>
                    <span className="muted">Expected vs Observed Detections</span>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Scenario ID</th>
                          <th>Result</th>
                          <th>Observed Detections</th>
                          <th>Expected Detections</th>
                          <th>Hallucination Flag</th>
                          <th>Duration</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.values(runResult.per_scenario_results).map((sc) => (
                          <tr key={sc.scenario_id}>
                            <td><code>{sc.scenario_id}</code></td>
                            <td>
                              <Badge
                                label={sc.passed ? "PASS" : "FAIL"}
                                variant={sc.passed ? "healthy" : "error"}
                                size="small"
                              />
                            </td>
                            <td><small>{sc.observed_detections.join(", ") || "None"}</small></td>
                            <td><small className="muted">{sc.expected_detections.join(", ") || "None"}</small></td>
                            <td>
                              {sc.hallucination_detected ? (
                                <Badge label="HALLUCINATION" variant="critical" size="small" />
                              ) : (
                                <span className="muted">None</span>
                              )}
                            </td>
                            <td><small>{sc.duration_ms.toFixed(1)} ms</small></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Ground Truth Dataset */}
      {tab === "ground_truth" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Authoritative Ground-Truth Dataset ({groundTruth?.version || "v1.0.0"})</h2>
              <span className="muted">{groundTruth?.description || "Curated defensive benchmark scenarios"}</span>
            </div>
          </div>

          {!groundTruth ? (
            <EmptyState text="Loading ground truth scenarios…" loading={loading} />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Scenario ID</th>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Expected Detections</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {(groundTruth.labels || groundTruth.scenarios || []).map((sc) => (
                    <tr key={sc.scenario_id}>
                      <td><code>{sc.scenario_id}</code></td>
                      <td><Badge label={sc.category} variant="neutral" size="small" /></td>
                      <td>{sc.description}</td>
                      <td><code>{(sc.expected_detections || []).join(", ") || "None"}</code></td>
                      <td>{sc.expected_incident_severity ? <Badge label={sc.expected_incident_severity} variant="neutral" size="small" /> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* Tab 3: Baseline Comparison */}
      {tab === "comparison" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Baseline Comparison & Regression Prevention</h2>
              <span className="muted">Compare current run results against approved reference baselines</span>
            </div>
            <div className="runner-controls">
              <select
                className="filter-select"
                value={selectedBaseline}
                onChange={(e) => setSelectedBaseline(e.target.value)}
              >
                {baselines.map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </select>
              <button
                className="button-primary"
                onClick={handleCompare}
                disabled={!runResult || isRunning}
                type="button"
              >
                Compare Run
              </button>
            </div>
          </div>

          {!comparison ? (
            <EmptyState
              text={
                runResult
                  ? "Select a reference baseline and click 'Compare Run' to analyze deltas."
                  : "Run a benchmark evaluation first, then compare against stored baselines."
              }
            />
          ) : (
            <div>
              <div className="comparison-header">
                <div>
                  <strong>Status: </strong>
                  <Badge
                    label={comparison.status}
                    variant={comparison.status === "STABLE" || comparison.status === "IMPROVED" ? "healthy" : "critical"}
                  />
                </div>
                <span className="muted">Reference Baseline: <code>{comparison.baseline_id}</code></span>
              </div>

              <div className="table-wrap" style={{ marginTop: "14px" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Current Run</th>
                      <th>Baseline Value</th>
                      <th>Delta</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(comparison.deltas).map(([k, d]) => (
                      <tr key={k}>
                        <td><strong>{d.metric}</strong></td>
                        <td>{d.current !== null ? d.current.toFixed(4) : "N/A"}</td>
                        <td>{d.baseline !== null ? d.baseline.toFixed(4) : "N/A"}</td>
                        <td>
                          {d.delta !== null ? (
                            <span className={d.delta >= 0 ? "text-healthy" : "text-critical"}>
                              {d.delta > 0 ? `+${d.delta.toFixed(4)}` : d.delta.toFixed(4)}
                            </span>
                          ) : "—"}
                        </td>
                        <td>
                          <Badge
                            label={d.status}
                            variant={d.status === "PASS" ? "healthy" : d.status === "WARN" ? "warning" : "error"}
                            size="small"
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
