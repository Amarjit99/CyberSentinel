import { useEffect, useState } from "react";
import { api } from "../api";
import { Detection } from "../types";

const transitions = ["acknowledged", "assigned", "escalated", "suppressed", "closed", "open"];

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Detection[]>([]);
  const [selected, setSelected] = useState<Detection | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = async () => {
    try {
      setAlerts(await api.getDetections());
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load alerts");
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const update = async (status: string) => {
    if (!selected) return;
    try {
      await api.updateDetectionLifecycle(selected.id, { status, reason: `Analyst selected ${status}` });
      setMessage(`Alert ${selected.id} moved to ${status}.`);
      setSelected(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update alert");
    }
  };

  return (
    <div className="stack">
      {error && <div className="alert-box error" role="alert">{error}</div>}
      {message && <div className="alert-box success" role="status">{message}</div>}
      <section className="panel">
        <div className="section-heading">
          <div>
            <span className="eyebrow">DETECTION ALERTS</span>
            <h2>Alert lifecycle</h2>
          </div>
          <button type="button" className="secondary-button" onClick={() => void load()}>Refresh</button>
        </div>
        {alerts.length === 0 ? (
          <p className="muted">No alerts match the current view.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Rule</th><th>Severity</th><th>Status</th><th>First seen</th><th>Action</th></tr></thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td><code>{alert.rule_id}</code></td>
                    <td>{alert.severity}</td>
                    <td>{alert.status}</td>
                    <td>{new Date(alert.first_seen).toLocaleString()}</td>
                    <td><button type="button" className="secondary-button" onClick={() => setSelected(alert)}>Manage</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {selected && (
        <section className="panel" aria-labelledby="alert-actions-title">
          <div className="section-heading">
            <div><span className="eyebrow">SELECTED ALERT</span><h2 id="alert-actions-title">{selected.id}</h2></div>
            <button type="button" className="secondary-button" onClick={() => setSelected(null)}>Cancel</button>
          </div>
          <p className="muted">Transitions are validated and audited by the API. Consequential response actions remain separate.</p>
          <div className="button-row">
            {transitions.map((status) => (
              <button key={status} type="button" className="secondary-button" onClick={() => void update(status)}>{status}</button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
