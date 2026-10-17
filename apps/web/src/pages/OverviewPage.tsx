import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, EmptyState, SafetyBanner, SeverityBadge, StateBadge } from "../components/common";
import { Detection, HealthResponse, Incident, InvestigationRun, ReadinessResponse } from "../types";

export function OverviewPage({ onNavigate }: { onNavigate: (page: string, id?: string) => void }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, r, incList, detList, invList] = await Promise.allSettled([
        api.getHealth(),
        api.getReadiness(),
        api.getIncidents(),
        api.getDetections(),
        api.getInvestigations(),
      ]);

      if (h.status === "fulfilled") setHealth(h.value);
      if (r.status === "fulfilled") setReadiness(r.value);
      if (incList.status === "fulfilled") setIncidents(incList.value);
      if (detList.status === "fulfilled") setDetections(detList.value);
      if (invList.status === "fulfilled") setInvestigations(invList.value);

      // If all failed, show error
      if (
        h.status === "rejected" &&
        r.status === "rejected" &&
        incList.status === "rejected"
      ) {
        setError("Unable to connect to backend APIs. Ensure backend server is running.");
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Error loading overview data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const openIncidents = incidents.filter(
    (i) => i.status !== "CLOSED" && i.status !== "REMEDIATED"
  );
  const criticalOrHighIncidents = incidents.filter(
    (i) => i.severity === "CRITICAL" || i.severity === "HIGH"
  );
  const activeInvestigations = investigations.filter(
    (inv) => inv.state === "RUNNING" || inv.state === "QUEUED" || inv.state === "AWAITING_REVIEW"
  );

  return (
    <div className="overview-page">
      <SafetyBanner />

      {error && <EmptyState text={error} error retry={fetchData} />}

      <section className="metric-grid" aria-label="Operational SOC metrics">
        <div
          className="metric-card clickable"
          onClick={() => onNavigate("Incidents")}
          role="button"
          tabIndex={0}
        >
          <span className="metric-label">Open Incidents</span>
          <strong>{loading ? "…" : openIncidents.length}</strong>
          <span className="metric-link">View all {incidents.length} incidents →</span>
        </div>

        <div
          className="metric-card clickable"
          onClick={() => onNavigate("Incidents")}
          role="button"
          tabIndex={0}
        >
          <span className="metric-label">Critical / High Severity</span>
          <strong className="text-critical">{loading ? "…" : criticalOrHighIncidents.length}</strong>
          <span className="metric-link">Requires immediate triage →</span>
        </div>

        <div
          className="metric-card clickable"
          onClick={() => onNavigate("Detections")}
          role="button"
          tabIndex={0}
        >
          <span className="metric-label">Active Detections</span>
          <strong>{loading ? "…" : detections.length}</strong>
          <span className="metric-link">Explore alert feed →</span>
        </div>

        <div
          className="metric-card clickable"
          onClick={() => onNavigate("Investigations")}
          role="button"
          tabIndex={0}
        >
          <span className="metric-label">Active Investigations</span>
          <strong>{loading ? "…" : activeInvestigations.length}</strong>
          <span className="metric-link">Review agent findings →</span>
        </div>
      </section>

      <section className="panel-grid">
        <article className="panel">
          <div className="panel-heading">
            <div>
              <h2>Platform Health & Data Freshness</h2>
              <span className="muted">Live verification via /health and /ready</span>
            </div>
            {health && (
              <Badge
                label={health.status.toUpperCase()}
                variant={health.status === "healthy" ? "healthy" : "degraded"}
              />
            )}
          </div>

          {loading ? (
            <EmptyState text="Verifying system health…" loading />
          ) : (
            <div className="health-details">
              <div className="health-row">
                <span>API Version:</span>
                <strong>{health?.version || "Unknown"}</strong>
              </div>
              <div className="health-row">
                <span>Database Connectivity:</span>
                <Badge
                  label={health?.checks?.database || "unknown"}
                  variant={health?.checks?.database === "ok" ? "healthy" : "error"}
                />
              </div>
              <div className="health-row">
                <span>Ingestion Pipeline:</span>
                <Badge
                  label={health?.checks?.ingestion || "unknown"}
                  variant={health?.checks?.ingestion === "ok" ? "healthy" : "degraded"}
                />
              </div>
              <div className="health-row">
                <span>Readiness State:</span>
                <Badge
                  label={readiness?.ready ? "READY" : "NOT READY"}
                  variant={readiness?.ready ? "healthy" : "warning"}
                />
              </div>
              <p className="muted small-note">
                Live operational status only. Unavailable components display truthful degraded or offline states.
              </p>
            </div>
          )}
        </article>

        <article className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent Investigation Runs</h2>
              <span className="muted">AI-assisted bounded investigative runs</span>
            </div>
            <button
              className="button-link"
              onClick={() => onNavigate("Investigations")}
              type="button"
            >
              All Runs →
            </button>
          </div>

          {loading ? (
            <EmptyState text="Loading investigation runs…" loading />
          ) : investigations.length === 0 ? (
            <EmptyState text="No investigation runs recorded yet." />
          ) : (
            <div className="mini-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Run ID</th>
                    <th>Task</th>
                    <th>State</th>
                    <th>Started</th>
                  </tr>
                </thead>
                <tbody>
                  {investigations.slice(0, 5).map((inv) => (
                    <tr
                      key={inv.id}
                      className="clickable-row"
                      onClick={() => onNavigate("Investigations", inv.id)}
                    >
                      <td><code>{inv.id.substring(0, 8)}…</code></td>
                      <td>{inv.task_type}</td>
                      <td><StateBadge state={inv.state} /></td>
                      <td><small>{new Date(inv.started_at).toLocaleTimeString()}</small></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>
      </section>

      <section className="panel" style={{ marginTop: "16px" }}>
        <div className="panel-heading">
          <div>
            <h2>Active Incidents Requiring Attention</h2>
            <span className="muted">Prioritized by severity and status</span>
          </div>
          <button
            className="button-link"
            onClick={() => onNavigate("Incidents")}
            type="button"
          >
            Manage All Incidents →
          </button>
        </div>

        {loading ? (
          <EmptyState text="Loading incidents…" loading />
        ) : incidents.length === 0 ? (
          <EmptyState text="No active security incidents found." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Confidence</th>
                  <th>Updated</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {incidents.slice(0, 6).map((inc) => (
                  <tr key={inc.id}>
                    <td><code>{inc.id.substring(0, 8)}…</code></td>
                    <td><strong>{inc.title}</strong></td>
                    <td><SeverityBadge severity={inc.severity} /></td>
                    <td><StateBadge state={inc.status} /></td>
                    <td>{(inc.confidence * 100).toFixed(0)}%</td>
                    <td><small>{new Date(inc.updated_at).toLocaleString()}</small></td>
                    <td>
                      <button
                        className="table-action"
                        onClick={() => onNavigate("Incidents", inc.id)}
                        type="button"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
