import { useEffect, useState } from "react";
import { api } from "../api";
import { EmptyState, Modal, SeverityBadge } from "../components/common";
import { EventSearchParams, TelemetryEvent } from "../types";

export function EventsPage() {
  const [params, setParams] = useState<EventSearchParams>({
    q: "",
    event_type: "",
    hostname: "",
    username: "",
    src_ip: "",
    dst_ip: "",
    severity: "",
    limit: 50,
    offset: 0,
  });

  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedEvent, setSelectedEvent] = useState<TelemetryEvent | null>(null);

  const searchEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.searchEvents(params);
      setEvents(res.events);
      setTotal(res.total);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Event search failed.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    searchEvents();
  }, [params.offset, params.limit]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setParams((p) => ({ ...p, offset: 0 }));
    searchEvents();
  };

  return (
    <div className="events-page">
      <section className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-heading">
          <div>
            <h2>Telemetry Event Search & Investigation</h2>
            <span className="muted">Query normalized events with source, provenance, and host context</span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="event-filter-grid">
          <input
            type="text"
            className="filter-input"
            placeholder="Full-text search (q)…"
            value={params.q || ""}
            onChange={(e) => setParams({ ...params, q: e.target.value })}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Event type (e.g., process_creation)…"
            value={params.event_type || ""}
            onChange={(e) => setParams({ ...params, event_type: e.target.value })}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Hostname…"
            value={params.hostname || ""}
            onChange={(e) => setParams({ ...params, hostname: e.target.value })}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Username…"
            value={params.username || ""}
            onChange={(e) => setParams({ ...params, username: e.target.value })}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Source IP…"
            value={params.src_ip || ""}
            onChange={(e) => setParams({ ...params, src_ip: e.target.value })}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Destination IP…"
            value={params.dst_ip || ""}
            onChange={(e) => setParams({ ...params, dst_ip: e.target.value })}
          />
          <select
            className="filter-select"
            value={params.severity || ""}
            onChange={(e) => setParams({ ...params, severity: e.target.value })}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>

          <div style={{ display: "flex", gap: "8px" }}>
            <button className="button-primary" type="submit" disabled={loading}>
              {loading ? "Searching…" : "Search Events"}
            </button>
            <button
              className="button-secondary"
              type="button"
              onClick={() => {
                setParams({
                  q: "",
                  event_type: "",
                  hostname: "",
                  username: "",
                  src_ip: "",
                  dst_ip: "",
                  severity: "",
                  limit: 50,
                  offset: 0,
                });
                setTimeout(searchEvents, 0);
              }}
            >
              Reset
            </button>
          </div>
        </form>
      </section>

      {error && <EmptyState text={error} error retry={searchEvents} />}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Matching Events ({total})</h2>
            <span className="muted">Showing up to {params.limit} records per page</span>
          </div>
        </div>

        {loading ? (
          <EmptyState text="Querying telemetry event store…" loading />
        ) : events.length === 0 ? (
          <EmptyState text="No telemetry events matched the search query." />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source / Type</th>
                  <th>Host / User</th>
                  <th>Network Flow</th>
                  <th>Process / Command</th>
                  <th>Severity</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr key={ev.id || i}>
                    <td><small>{new Date(ev.timestamp).toLocaleString()}</small></td>
                    <td>
                      <strong>{ev.event_type}</strong>
                      <div className="small-code">{ev.source_type} / {ev.source_name}</div>
                    </td>
                    <td>
                      <div>{ev.hostname || "—"}</div>
                      <small className="muted">{ev.username || "—"}</small>
                    </td>
                    <td>
                      <small>{ev.src_ip || "—"} → {ev.dst_ip || "—"}</small>
                    </td>
                    <td>
                      <code>{ev.process_name || ev.command_line || "—"}</code>
                    </td>
                    <td><SeverityBadge severity={ev.severity} /></td>
                    <td>
                      <button
                        className="table-action"
                        onClick={() => setSelectedEvent(ev)}
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

        {/* Pagination */}
        {total > (params.limit || 50) && (
          <div className="pagination-bar">
            <button
              className="button-secondary"
              disabled={(params.offset || 0) <= 0 || loading}
              onClick={() => setParams((p) => ({ ...p, offset: Math.max(0, (p.offset || 0) - (p.limit || 50)) }))}
              type="button"
            >
              ← Previous
            </button>
            <span className="muted">
              Offset {params.offset || 0} to {Math.min(total, (params.offset || 0) + (params.limit || 50))} of {total}
            </span>
            <button
              className="button-secondary"
              disabled={(params.offset || 0) + (params.limit || 50) >= total || loading}
              onClick={() => setParams((p) => ({ ...p, offset: (p.offset || 0) + (p.limit || 50) }))}
              type="button"
            >
              Next →
            </button>
          </div>
        )}
      </section>

      {/* Modal: Event JSON Inspect */}
      <Modal
        title="Telemetry Event Detail"
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
      >
        {selectedEvent && (
          <div>
            <div className="metric-row">
              <span>Event ID:</span>
              <code>{selectedEvent.id}</code>
            </div>
            <div className="metric-row">
              <span>Timestamp:</span>
              <span>{selectedEvent.timestamp}</span>
            </div>
            <div className="metric-row">
              <span>Event Type:</span>
              <strong>{selectedEvent.event_type}</strong>
            </div>
            <pre className="json-snippet">{JSON.stringify(selectedEvent.raw || selectedEvent, null, 2)}</pre>
          </div>
        )}
      </Modal>
    </div>
  );
}
