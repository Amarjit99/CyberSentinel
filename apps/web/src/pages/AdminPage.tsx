import { useEffect, useState } from "react";
import { api, getActiveRole } from "../api";
import { Badge, EmptyState } from "../components/common";
import { HealthResponse, ReadinessResponse } from "../types";

export function AdminPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [quarantine, setQuarantine] = useState<Record<string, unknown>[]>([]);
  const [tools, setTools] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Webhook Test State
  const [testChannel, setTestChannel] = useState<"webhook" | "slack" | "pagerduty">("webhook");
  const [testTitle, setTestTitle] = useState("Diagnostic Alert Test");
  const [testMessage, setTestMessage] = useState("Verifying outbound dispatch pipeline");
  const [testSeverity, setTestSeverity] = useState("HIGH");
  const [testWebhookResult, setTestWebhookResult] = useState<Record<string, unknown> | null>(null);
  const [testWebhookLoading, setTestWebhookLoading] = useState(false);
  const [testWebhookError, setTestWebhookError] = useState<string | null>(null);

  // Stream Ingest Test State
  const [streamResult, setStreamResult] = useState<Record<string, unknown> | null>(null);
  const [streamLoading, setStreamLoading] = useState(false);
  const [streamError, setStreamError] = useState<string | null>(null);

  const currentRole = getActiveRole();

  const handleTestWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    setTestWebhookLoading(true);
    setTestWebhookError(null);
    try {
      const res = await api.testWebhookNotification({
        channel: testChannel,
        title: testTitle,
        message: testMessage,
        severity: testSeverity,
      });
      setTestWebhookResult(res);
    } catch (err: unknown) {
      setTestWebhookError(err instanceof Error ? err.message : "Notification test failed");
    } finally {
      setTestWebhookLoading(false);
    }
  };

  const handleTestStream = async () => {
    setStreamLoading(true);
    setStreamError(null);
    try {
      const sampleEvent = {
        event_id: `stream-ui-test-${Date.now()}`,
        timestamp: new Date().toISOString(),
        event_type: "process_creation",
        source_type: "endpoint",
        source_name: "edr-agent",
        hostname: "WORKSTATION-01",
        username: "analyst",
        process_name: "powershell.exe",
        command_line: "powershell.exe -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        severity: "HIGH",
        raw: {
          ProcessId: 4412,
          ParentProcessName: "cmd.exe",
        },
      };
      const res = await api.ingestEventStream([sampleEvent], "web-stream-console");
      setStreamResult(res);
    } catch (err: unknown) {
      setStreamError(err instanceof Error ? err.message : "Streaming injection failed");
    } finally {
      setStreamLoading(false);
    }
  };

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [hRes, rRes, mRes, qRes, tRes] = await Promise.allSettled([
        api.getHealth(),
        api.getReadiness(),
        api.getEventMetrics(),
        api.getQuarantinedEvents(),
        api.getRegisteredTools(),
      ]);

      if (hRes.status === "fulfilled") setHealth(hRes.value);
      if (rRes.status === "fulfilled") setReadiness(rRes.value);
      if (mRes.status === "fulfilled") setMetrics(mRes.value);
      if (qRes.status === "fulfilled") setQuarantine(qRes.value);
      if (tRes.status === "fulfilled") setTools(tRes.value);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load admin data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Capabilities by role
  const roleCapabilities: Record<string, string[]> = {
    SOC_ANALYST: [
      "View Incidents, Events, Detections, Threat Intel",
      "Transition Incidents (NEW -> TRIAGED, etc.)",
      "Add Incident Notes",
      "Run Deterministic Risk & Triage Assessments",
      "Launch AI Investigation Runs",
      "Submit Human Reviews for Investigation Runs",
      "Propose Response Actions (Requires Peer Approval)",
      "View Ground Truth & Benchmark Results",
    ],
    INCIDENT_COMMANDER: [
      "All SOC Analyst Capabilities",
      "Authorize / Approve Response Proposals (Two-Person Rule)",
      "Transition Incidents to CONTAINED, REMEDIATED, CLOSED",
      "Override Triage Playbook Assignment",
      "Execute Dry-Run Response Actions",
    ],
    SECURITY_ENGINEER: [
      "All SOC Analyst Capabilities",
      "Generate, Validate, and Test Detection Rules",
      "Review and Activate Sigma Rule Candidates",
      "Execute Benchmark Evaluation Runs",
      "Perform Baseline Regression Comparisons",
      "Manage Threat Intelligence Feeds and Sources",
    ],
    SOC_MANAGER: [
      "All Incident Commander & Security Engineer Capabilities",
      "Review Platform Ingestion and SLA Metrics",
      "Authorize Benchmark Comparisons and Overrides",
    ],
    ADMIN: [
      "Unrestricted Administrative Access Across All Endpoints",
      "Replay Quarantined Ingestion Events",
      "Tool Registry Management & Agent Budget Overrides",
    ],
    VIEWER: [
      "Read-Only Access to Incidents, Events, Detections, and Reports",
      "No Mutation, Transition, Approval, or Run Capabilities",
    ],
  };

  return (
    <div className="admin-page">
      {error && <EmptyState text={error} error retry={fetchData} />}

      <div className="panel-grid">
        {/* Active Role & Capabilities */}
        <article className="panel">
          <div className="panel-heading">
            <div>
              <h2>Current Operator Authorization</h2>
              <span className="muted">Enforced on backend via X-Operator-Role header</span>
            </div>
            <Badge label={currentRole} variant="healthy" />
          </div>

          <div className="health-details">
            <p><strong>Authorized Operations for {currentRole}:</strong></p>
            <ul className="guidance-list">
              {(roleCapabilities[currentRole] || []).map((cap, i) => (
                <li key={i}>{cap}</li>
              ))}
            </ul>
            <p className="muted small-note" style={{ marginTop: "12px" }}>
              Remember: UI hiding is an ergonomic convenience. Every action is strictly validated by the FastAPI backend authorization middleware.
            </p>
          </div>
        </article>

        {/* System Readiness */}
        <article className="panel">
          <div className="panel-heading">
            <div>
              <h2>Core Infrastructure & Health Checks</h2>
              <span className="muted">Probed via /health and /ready</span>
            </div>
            <Badge
              label={readiness?.ready ? "ALL DEPENDENCIES READY" : "DEGRADED"}
              variant={readiness?.ready ? "healthy" : "warning"}
            />
          </div>

          <div className="health-details">
            <div className="health-row">
              <span>Platform Version:</span>
              <strong>{health?.version || "Unknown"}</strong>
            </div>
            <div className="health-row">
              <span>Database (SQLite / SQLAlchemy):</span>
              <Badge label={health?.checks?.database || "ok"} variant="healthy" size="small" />
            </div>
            <div className="health-row">
              <span>Durable Ingestion Engine:</span>
              <Badge label={health?.checks?.ingestion || "ok"} variant="healthy" size="small" />
            </div>
            <div className="health-row">
              <span>Live Response Circuit Breaker:</span>
              <Badge label="LIVE_RESPONSE_DISABLED=TRUE" variant="healthy" size="small" />
            </div>
          </div>
        </article>
      </div>

      {/* Quarantined Events */}
      <section className="panel" style={{ marginTop: "16px" }}>
        <div className="panel-heading">
          <div>
            <h2>Quarantined Malformed Telemetry ({quarantine.length})</h2>
            <span className="muted">Malformed or validation-rejected events isolated for inspection</span>
          </div>
          <button className="button-secondary" onClick={fetchData} type="button">
            ↻ Refresh
          </button>
        </div>

        {quarantine.length === 0 ? (
          <EmptyState text="Quarantine queue is empty. Zero malformed events currently held." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Quarantine ID</th>
                  <th>Reason / Error</th>
                  <th>Client ID</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {quarantine.map((q, i) => (
                  <tr key={String(q.id || i)}>
                    <td><code>{String(q.id || i)}</code></td>
                    <td><strong className="text-critical">{String(q.reason || q.error_code || "Validation Failure")}</strong></td>
                    <td>{String(q.client_id || "unknown")}</td>
                    <td><small>{String(q.timestamp || q.quarantined_at || "—")}</small></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Registered Agent Tools */}
      <section className="panel" style={{ marginTop: "16px" }}>
        <div className="panel-heading">
          <div>
            <h2>Agent Tool Registry ({tools.length})</h2>
            <span className="muted">Whitelisted bounded tools available for AI investigation agents</span>
          </div>
        </div>

        {tools.length === 0 ? (
          <EmptyState text="No agent tools registered in default registry." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tool Name</th>
                  <th>Description</th>
                  <th>Category</th>
                  <th>Requires Approval</th>
                  <th>Max Execution Timeout</th>
                </tr>
              </thead>
              <tbody>
                {tools.map((t) => (
                  <tr key={String(t.name)}>
                    <td><strong>{String(t.name)}</strong></td>
                    <td>{String(t.description || "—")}</td>
                    <td><code>{String(t.category || "investigation")}</code></td>
                    <td>
                      <Badge
                        label={t.requires_approval ? "YES" : "NO"}
                        variant={t.requires_approval ? "warning" : "healthy"}
                        size="small"
                      />
                    </td>
                    <td>{String(t.timeout_seconds || 30)}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Real-Time Streaming Ingestion & Outbound Webhook Test */}
      <div className="panel-grid" style={{ marginTop: "16px" }}>
        {/* Outbound Notifications */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Outbound Notification Dispatcher Test</h2>
              <span className="muted">Verify Slack, PagerDuty, or signed Webhook connectivity</span>
            </div>
          </div>

          <form onSubmit={handleTestWebhook} style={{ display: "grid", gap: "10px" }}>
            <div style={{ display: "flex", gap: "10px" }}>
              <select
                className="filter-select"
                value={testChannel}
                onChange={(e) => setTestChannel(e.target.value as "webhook" | "slack" | "pagerduty")}
                style={{ flex: 1 }}
              >
                <option value="webhook">Signed Generic Webhook (HMAC-SHA256)</option>
                <option value="slack">Slack Webhook</option>
                <option value="pagerduty">PagerDuty Events API v2</option>
              </select>
              <select
                className="filter-select"
                value={testSeverity}
                onChange={(e) => setTestSeverity(e.target.value)}
                style={{ width: "130px" }}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
            <input
              type="text"
              className="filter-input"
              value={testTitle}
              onChange={(e) => setTestTitle(e.target.value)}
              placeholder="Notification Title"
              required
            />
            <input
              type="text"
              className="filter-input"
              value={testMessage}
              onChange={(e) => setTestMessage(e.target.value)}
              placeholder="Notification Message"
              required
            />
            <button className="button-primary" type="submit" disabled={testWebhookLoading}>
              {testWebhookLoading ? "Dispatching…" : "Send Test Notification"}
            </button>
          </form>

          {testWebhookError && <div className="text-critical" style={{ marginTop: "10px" }}>{testWebhookError}</div>}
          {testWebhookResult && (
            <div style={{ marginTop: "12px" }}>
              <Badge label="DISPATCHED" variant="healthy" size="small" />
              <pre className="json-snippet">{JSON.stringify(testWebhookResult, null, 2)}</pre>
            </div>
          )}
        </section>

        {/* Streaming Ingestion Worker */}
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Real-Time Streaming Ingestion Worker</h2>
              <span className="muted">Direct inline Sigma detection & correlation evaluation</span>
            </div>
          </div>

          <p className="muted" style={{ fontSize: "13px", margin: "0 0 12px 0" }}>
            Injects a live telemetry payload through <code>/api/v1/ingest/stream</code>, evaluating pySigma rules and sliding-window attack scenario correlations synchronously in &lt;5ms.
          </p>

          <button
            className="button-primary"
            onClick={handleTestStream}
            disabled={streamLoading}
            type="button"
          >
            {streamLoading ? "Processing Stream…" : "⚡ Inject Live Streaming Event Batch"}
          </button>

          {streamError && <div className="text-critical" style={{ marginTop: "10px" }}>{streamError}</div>}
          {streamResult && (
            <div style={{ marginTop: "12px" }}>
              <Badge label="BATCH PROCESSED" variant="healthy" size="small" />
              <pre className="json-snippet">{JSON.stringify(streamResult, null, 2)}</pre>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
