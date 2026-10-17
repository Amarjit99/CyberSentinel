import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Badge, EmptyState, Modal, SeverityBadge, StateBadge } from "../components/common";
import {
  Incident,
  IncidentRiskAssessment,
  IncidentTimelineEntry,
  IncidentTriageAssessment,
} from "../types";

export function IncidentsPage({
  initialIncidentId,
  onNavigateToInvestigation,
}: {
  initialIncidentId?: string | null;
  onNavigateToInvestigation?: (runId: string) => void;
}) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Selection & Detail
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimelineEntry[]>([]);
  const [triage, setTriage] = useState<IncidentTriageAssessment | null>(null);
  const [risk, setRisk] = useState<IncidentRiskAssessment | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Action modals & inputs
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [noteModalOpen, setNoteModalOpen] = useState(false);
  const [noteText, setNoteText] = useState("");

  const [transitionModalOpen, setTransitionModalOpen] = useState(false);
  const [targetState, setTargetState] = useState("");
  const [transitionReason, setTransitionReason] = useState("");

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.getIncidents();
      setIncidents(list);
      if (initialIncidentId) {
        const found = list.find((i) => i.id === initialIncidentId);
        if (found) loadIncidentDetail(found);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [initialIncidentId]);

  const loadIncidentDetail = async (inc: Incident) => {
    setSelectedIncident(inc);
    setDetailLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const [fullInc, tl, tr, rk] = await Promise.allSettled([
        api.getIncident(inc.id),
        api.getIncidentTimeline(inc.id),
        api.getIncidentTriage(inc.id),
        api.getIncidentRiskAssessment(inc.id),
      ]);

      if (fullInc.status === "fulfilled") setSelectedIncident(fullInc.value);
      if (tl.status === "fulfilled") setTimeline(tl.value);
      else setTimeline([]);
      if (tr.status === "fulfilled") setTriage(tr.value);
      else setTriage(null);
      if (rk.status === "fulfilled") setRisk(rk.value);
      else setRisk(null);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed loading incident detail.");
    } finally {
      setDetailLoading(false);
    }
  };

  // Actions
  const handleTransitionSubmit = async () => {
    if (!selectedIncident || !targetState) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await api.transitionIncident(
        selectedIncident.id,
        targetState,
        selectedIncident.version,
        transitionReason
      );
      setSelectedIncident(updated);
      setIncidents((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
      setActionSuccess(`Incident successfully transitioned to ${targetState}.`);
      setTransitionModalOpen(false);
      setTransitionReason("");
      loadIncidentDetail(updated);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "State transition failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleNoteSubmit = async () => {
    if (!selectedIncident || !noteText.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.addIncidentNote(selectedIncident.id, noteText.trim());
      setActionSuccess("Note added to incident log.");
      setNoteModalOpen(false);
      setNoteText("");
      loadIncidentDetail(selectedIncident);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed to add note.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTriggerTriage = async () => {
    if (!selectedIncident) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const tr = await api.triggerIncidentTriage(selectedIncident.id);
      setTriage(tr);
      setActionSuccess("Deterministic & AI triage refreshed successfully.");
      loadIncidentDetail(selectedIncident);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Triage trigger failed.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTriggerRisk = async () => {
    if (!selectedIncident) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const rk = await api.triggerRiskAssessment(selectedIncident.id);
      setRisk(rk);
      setActionSuccess("Deterministic risk assessment refreshed.");
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Risk calculation failed.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStartInvestigation = async () => {
    if (!selectedIncident) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const run = await api.startInvestigation(selectedIncident.id);
      setActionSuccess(`Investigation run initiated (${run.id}).`);
      if (onNavigateToInvestigation) {
        onNavigateToInvestigation(run.id);
      }
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed to launch investigation run.");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Filtered incidents
  const filtered = incidents.filter((inc) => {
    const matchesSearch =
      search.trim() === "" ||
      inc.title.toLowerCase().includes(search.toLowerCase()) ||
      inc.id.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "ALL" || inc.severity === severityFilter;
    const matchesStatus = statusFilter === "ALL" || inc.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="incidents-page">
      <div className="panel-controls">
        <input
          type="text"
          className="filter-input search-input"
          placeholder="Search by title or ID…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Informational</option>
        </select>
        <select
          className="filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="ALL">All Lifecycle States</option>
          <option value="NEW">NEW</option>
          <option value="TRIAGED">TRIAGED</option>
          <option value="INVESTIGATING">INVESTIGATING</option>
          <option value="CONTAINMENT_PROPOSED">CONTAINMENT_PROPOSED</option>
          <option value="CONTAINED">CONTAINED</option>
          <option value="REMEDIATED">REMEDIATED</option>
          <option value="CLOSED">CLOSED</option>
        </select>
        <button className="button-secondary" onClick={fetchIncidents} type="button">
          ↻ Refresh
        </button>
      </div>

      {error && <EmptyState text={error} error retry={fetchIncidents} />}

      <div className="two-column-layout">
        {/* Left column: Incident table */}
        <div className="panel incident-list-panel">
          <div className="panel-heading">
            <div>
              <h2>Incident Queue ({filtered.length})</h2>
              <span className="muted">Select an incident to review evidence and actions</span>
            </div>
          </div>

          {loading ? (
            <EmptyState text="Loading incidents…" loading />
          ) : filtered.length === 0 ? (
            <EmptyState text="No incidents match the active filters." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Confidence</th>
                    <th>Version</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((inc) => (
                    <tr
                      key={inc.id}
                      className={`clickable-row ${selectedIncident?.id === inc.id ? "selected-row" : ""}`}
                      onClick={() => loadIncidentDetail(inc)}
                    >
                      <td>
                        <strong>{inc.title}</strong>
                        <div className="small-code">{inc.id.substring(0, 8)}…</div>
                      </td>
                      <td><SeverityBadge severity={inc.severity} /></td>
                      <td><StateBadge state={inc.status} /></td>
                      <td>{(inc.confidence * 100).toFixed(0)}%</td>
                      <td><code>v{inc.version}</code></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right column: Selected Incident Workspace */}
        <div className="panel incident-workspace-panel">
          {!selectedIncident ? (
            <EmptyState text="Select an incident from the queue to inspect details and actions." />
          ) : detailLoading ? (
            <EmptyState text="Loading incident details…" loading />
          ) : (
            <div>
              <div className="panel-heading">
                <div>
                  <h2>{selectedIncident.title}</h2>
                  <span className="muted">ID: <code>{selectedIncident.id}</code> (v{selectedIncident.version})</span>
                </div>
                <div className="badge-group">
                  <SeverityBadge severity={selectedIncident.severity} />
                  <StateBadge state={selectedIncident.status} />
                </div>
              </div>

              {actionError && (
                <div className="alert-box error" role="alert">
                  <strong>Action Failed:</strong> {actionError}
                </div>
              )}
              {actionSuccess && (
                <div className="alert-box success" role="status">
                  {actionSuccess}
                </div>
              )}

              {/* Action Toolbar */}
              <div className="action-toolbar">
                <button
                  className="button-primary"
                  onClick={() => {
                    setTargetState("");
                    setTransitionReason("");
                    setTransitionModalOpen(true);
                  }}
                  disabled={isSubmitting}
                  type="button"
                >
                  ⚡ Transition Lifecycle…
                </button>
                <button
                  className="button-secondary"
                  onClick={() => setNoteModalOpen(true)}
                  disabled={isSubmitting}
                  type="button"
                >
                  ✎ Add Note
                </button>
                <button
                  className="button-secondary"
                  onClick={handleTriggerTriage}
                  disabled={isSubmitting}
                  type="button"
                >
                  ⚖ Run Triage
                </button>
                <button
                  className="button-secondary"
                  onClick={handleTriggerRisk}
                  disabled={isSubmitting}
                  type="button"
                >
                  📈 Assess Risk
                </button>
                <button
                  className="button-secondary"
                  onClick={handleStartInvestigation}
                  disabled={isSubmitting}
                  type="button"
                >
                  🔍 Launch AI Run
                </button>
              </div>

              {/* Risk & Triage Cards */}
              <div className="sub-panel-grid">
                <div className="sub-card">
                  <h4>Deterministic Risk Assessment</h4>
                  {risk ? (
                    <div>
                      <div className="metric-row">
                        <span>Risk Score:</span>
                        <strong>{risk.risk_score.toFixed(1)} / 100</strong>
                      </div>
                      <div className="metric-row">
                        <span>Assessed Severity:</span>
                        <SeverityBadge severity={risk.severity_level} />
                      </div>
                      <div className="metric-row">
                        <span>Confidence:</span>
                        <strong>{(risk.confidence_score * 100).toFixed(0)}%</strong>
                      </div>
                    </div>
                  ) : (
                    <span className="muted">No risk assessment calculated.</span>
                  )}
                </div>

                <div className="sub-card">
                  <h4>Triage Assessment</h4>
                  {triage ? (
                    <div>
                      <p className="summary-text">{triage.triage_summary}</p>
                      {triage.recommended_playbook && (
                        <div className="small-note">
                          Playbook: <code>{triage.recommended_playbook}</code>
                        </div>
                      )}
                    </div>
                  ) : (
                    <span className="muted">Not triaged yet. Click 'Run Triage' above.</span>
                  )}
                </div>
              </div>

              {/* Entities & Evidence */}
              <div className="detail-section">
                <h3>Associated Entities ({selectedIncident.entities?.length || 0})</h3>
                {!selectedIncident.entities || selectedIncident.entities.length === 0 ? (
                  <span className="muted">No entities extracted yet.</span>
                ) : (
                  <div className="entity-chips">
                    {selectedIncident.entities.map((ent, idx) => (
                      <span key={ent.id || idx} className="entity-chip">
                        <small>{ent.entity_type}:</small>
                        <strong>{ent.entity_value}</strong>
                        {ent.role && <em>({ent.role})</em>}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="detail-section">
                <h3>Grounded Evidence Records ({selectedIncident.evidence?.length || 0})</h3>
                {!selectedIncident.evidence || selectedIncident.evidence.length === 0 ? (
                  <span className="muted">No evidence records attached.</span>
                ) : (
                  <div className="evidence-list">
                    {selectedIncident.evidence.map((ev, idx) => (
                      <div key={ev.id || idx} className="evidence-item">
                        <div className="evidence-header">
                          <span className="evidence-type">{ev.evidence_type}</span>
                          <span className="small-code">{ev.id}</span>
                        </div>
                        <pre className="json-snippet">{JSON.stringify(ev.content, null, 2)}</pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div className="detail-section">
                <h3>Incident Activity Timeline ({timeline.length})</h3>
                {timeline.length === 0 ? (
                  <span className="muted">No timeline entries recorded.</span>
                ) : (
                  <ul className="timeline-list">
                    {timeline.map((entry, idx) => (
                      <li key={entry.id || idx} className="timeline-item">
                        <span className="timeline-time">
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                        <div className="timeline-content">
                          <strong>{entry.event_type}</strong>: {entry.summary}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Add Note */}
      <Modal
        title="Add Incident Note"
        isOpen={noteModalOpen}
        onClose={() => setNoteModalOpen(false)}
      >
        <div className="modal-form">
          <label htmlFor="note-text">Note content (will be logged to immutable audit history):</label>
          <textarea
            id="note-text"
            rows={4}
            className="form-textarea"
            placeholder="Document analyst observations, hypothesis verification, or external communications…"
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
          />
          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setNoteModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              onClick={handleNoteSubmit}
              disabled={isSubmitting || !noteText.trim()}
              type="button"
            >
              {isSubmitting ? "Saving…" : "Save Note"}
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Transition State */}
      <Modal
        title="Transition Incident Lifecycle"
        isOpen={transitionModalOpen}
        onClose={() => setTransitionModalOpen(false)}
      >
        <div className="modal-form">
          <p className="small-note">
            Current version: <code>v{selectedIncident?.version}</code>. Server-side optimistic concurrency control protects against concurrent modification.
          </p>
          <label htmlFor="target-state">Select Target State:</label>
          <select
            id="target-state"
            className="filter-select"
            value={targetState}
            onChange={(e) => setTargetState(e.target.value)}
          >
            <option value="">-- Choose State --</option>
            <option value="TRIAGED">TRIAGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINMENT_PROPOSED">CONTAINMENT_PROPOSED</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="REMEDIATED">REMEDIATED</option>
            <option value="CLOSED">CLOSED</option>
          </select>

          <label htmlFor="transition-reason" style={{ marginTop: "12px" }}>
            Operational Rationale:
          </label>
          <textarea
            id="transition-reason"
            rows={3}
            className="form-textarea"
            placeholder="Explain why this transition is warranted based on verified evidence…"
            value={transitionReason}
            onChange={(e) => setTransitionReason(e.target.value)}
          />

          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setTransitionModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              onClick={handleTransitionSubmit}
              disabled={isSubmitting || !targetState}
              type="button"
            >
              {isSubmitting ? "Applying…" : `Confirm Transition → ${targetState || "…"}`}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
