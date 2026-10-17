import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Badge, EmptyState, Modal, StateBadge } from "../components/common";
import {
  InvestigationFinding,
  InvestigationRun,
  InvestigationSummary,
} from "../types";

export function InvestigationsPage({
  initialRunId,
  onNavigateToIncident,
}: {
  initialRunId?: string | null;
  onNavigateToIncident?: (incidentId: string) => void;
}) {
  const [runs, setRuns] = useState<InvestigationRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<InvestigationRun | null>(null);
  const [findings, setFindings] = useState<InvestigationFinding[]>([]);
  const [summary, setSummary] = useState<InvestigationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Review modal
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [reviewDecision, setReviewDecision] = useState<"ACCEPTED" | "REJECTED" | "MODIFIED">("ACCEPTED");
  const [reviewNotes, setReviewNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchRuns = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.getInvestigations();
      setRuns(list);
      if (initialRunId) {
        const found = list.find((r) => r.id === initialRunId);
        if (found) loadRunDetail(found);
      } else if (list.length > 0 && !selectedRun) {
        loadRunDetail(list[0]);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load investigations");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, [initialRunId]);

  const loadRunDetail = async (run: InvestigationRun) => {
    setSelectedRun(run);
    setDetailLoading(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const [fList, sObj] = await Promise.allSettled([
        api.getInvestigationFindings(run.id),
        api.getInvestigationSummary(run.id),
      ]);

      if (fList.status === "fulfilled") setFindings(fList.value);
      else setFindings([]);
      if (sObj.status === "fulfilled") setSummary(sObj.value);
      else setSummary(null);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed loading run details.");
    } finally {
      setDetailLoading(false);
    }
  };

  const handleReviewSubmit = async () => {
    if (!selectedRun || !reviewNotes.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.reviewInvestigation(selectedRun.id, reviewDecision, reviewNotes.trim());
      setActionSuccess(`Review submitted successfully: ${reviewDecision}.`);
      setReviewModalOpen(false);
      setReviewNotes("");
      fetchRuns();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Review submission failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancelRun = async () => {
    if (!selectedRun) return;
    setIsSubmitting(true);
    setActionError(null);
    try {
      await api.cancelInvestigation(selectedRun.id);
      setActionSuccess("Investigation run cancelled.");
      fetchRuns();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Failed to cancel run.");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Group findings by claim_type to enforce clear distinction between facts and hypotheses
  const confirmedFacts = findings.filter((f) => f.claim_type === "CONFIRMED_FACT");
  const hypotheses = findings.filter((f) => f.claim_type === "HYPOTHESIS");
  const unknowns = findings.filter((f) => f.claim_type === "UNKNOWN");
  const contradictions = findings.filter((f) => f.claim_type === "CONTRADICTION");

  return (
    <div className="investigations-page">
      {error && <EmptyState text={error} error retry={fetchRuns} />}

      <div className="two-column-layout">
        {/* Left Column: Investigation Runs List */}
        <div className="panel investigation-list-panel">
          <div className="panel-heading">
            <div>
              <h2>Investigation Runs ({runs.length})</h2>
              <span className="muted">Bounded, accountable agentic execution logs</span>
            </div>
            <button className="button-secondary" onClick={fetchRuns} type="button">
              ↻ Refresh
            </button>
          </div>

          {loading ? (
            <EmptyState text="Loading runs…" loading />
          ) : runs.length === 0 ? (
            <EmptyState text="No investigation runs found. Launch an investigation from any incident." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Run ID / Task</th>
                    <th>State</th>
                    <th>Model</th>
                    <th>Started</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <tr
                      key={run.id}
                      className={`clickable-row ${selectedRun?.id === run.id ? "selected-row" : ""}`}
                      onClick={() => loadRunDetail(run)}
                    >
                      <td>
                        <strong>{run.task_type}</strong>
                        <div className="small-code">{run.id.substring(0, 10)}…</div>
                      </td>
                      <td><StateBadge state={run.state} /></td>
                      <td><small>{run.model_ref}</small></td>
                      <td><small>{new Date(run.started_at).toLocaleTimeString()}</small></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column: Run Workspace & Grounded Findings */}
        <div className="panel investigation-detail-panel">
          {!selectedRun ? (
            <EmptyState text="Select an investigation run to view findings and evidence citations." />
          ) : detailLoading ? (
            <EmptyState text="Loading run findings and summary…" loading />
          ) : (
            <div>
              <div className="panel-heading">
                <div>
                  <h2>Run: <code>{selectedRun.id}</code></h2>
                  <span className="muted">
                    Target Incident:{" "}
                    <button
                      className="button-link"
                      onClick={() => onNavigateToIncident && onNavigateToIncident(selectedRun.incident_id)}
                      type="button"
                    >
                      <code>{selectedRun.incident_id}</code> →
                    </button>
                  </span>
                </div>
                <div className="badge-group">
                  <StateBadge state={selectedRun.state} />
                  <Badge label={`Budget: $${selectedRun.budget_limit_usd ?? "1.00"}`} variant="neutral" />
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
                  onClick={() => setReviewModalOpen(true)}
                  disabled={isSubmitting}
                  type="button"
                >
                  ✓ Submit Human Review…
                </button>
                {(selectedRun.state === "RUNNING" || selectedRun.state === "QUEUED") && (
                  <button
                    className="button-danger"
                    onClick={handleCancelRun}
                    disabled={isSubmitting}
                    type="button"
                  >
                    ✕ Cancel Run
                  </button>
                )}
              </div>

              {/* Separation of Confirmed Facts vs Hypotheses Notice */}
              <div className="info-callout">
                <strong>Grounding Distinction Principle:</strong> Confirmed facts are linked to verified telemetry evidence records. Hypotheses represent AI probabilistic interpretations and must not be treated as confirmed facts.
              </div>

              {/* Structured Summary if available */}
              {summary && (
                <div className="summary-box">
                  <h3>Structured Investigation Summary</h3>
                  <p className="summary-narrative">{summary.summary}</p>
                  
                  {summary.evidence_gaps && summary.evidence_gaps.length > 0 && (
                    <div className="gap-box">
                      <strong>Identified Evidence Gaps:</strong>
                      <ul>
                        {summary.evidence_gaps.map((gap, i) => (
                          <li key={i}>{gap}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {summary.citations && summary.citations.length > 0 && (
                    <div className="citations-box">
                      <strong>Supporting Evidence Citations ({summary.citations.length}):</strong>
                      <div className="citations-grid">
                        {summary.citations.map((c, i) => (
                          <div key={i} className="citation-card">
                            <div className="citation-claim">"{c.claim}"</div>
                            <div className="citation-source">Evidence Ref: <code>{c.evidence_id}</code></div>
                            {c.excerpt && <div className="citation-excerpt">{c.excerpt}</div>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Categorized Findings */}
              <div className="findings-container">
                {/* 1. Confirmed Facts */}
                <div className="findings-group">
                  <div className="group-header text-healthy">
                    <h4>✓ Confirmed Facts ({confirmedFacts.length})</h4>
                    <span className="muted">Directly verified by cited evidence</span>
                  </div>
                  {confirmedFacts.length === 0 ? (
                    <span className="muted small">No confirmed facts identified in this run.</span>
                  ) : (
                    confirmedFacts.map((f) => (
                      <div key={f.id} className="finding-card fact-card">
                        <div className="finding-body">{f.claim}</div>
                        <div className="finding-meta">
                          <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                          {f.supporting_evidence_ids.length > 0 && (
                            <span>Evidence IDs: {f.supporting_evidence_ids.join(", ")}</span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* 2. Hypotheses */}
                <div className="findings-group" style={{ marginTop: "14px" }}>
                  <div className="group-header text-medium">
                    <h4>? Hypotheses ({hypotheses.length})</h4>
                    <span className="muted">Plausible explanations requiring human analyst validation</span>
                  </div>
                  {hypotheses.length === 0 ? (
                    <span className="muted small">No active hypotheses recorded.</span>
                  ) : (
                    hypotheses.map((f) => (
                      <div key={f.id} className="finding-card hypothesis-card">
                        <div className="finding-body">{f.claim}</div>
                        <div className="finding-meta">
                          <span>Plausibility Score: {(f.confidence * 100).toFixed(0)}%</span>
                          {f.rationale && <span>Rationale: {f.rationale}</span>}
                        </div>
                      </div>
                    ))
                  )}
                </div>

                {/* 3. Unknowns & Contradictions */}
                {(unknowns.length > 0 || contradictions.length > 0) && (
                  <div className="findings-group" style={{ marginTop: "14px" }}>
                    <div className="group-header text-critical">
                      <h4>⚠ Unknowns & Contradictions ({unknowns.length + contradictions.length})</h4>
                    </div>
                    {contradictions.map((f) => (
                      <div key={f.id} className="finding-card contradiction-card">
                        <strong>Contradiction:</strong> {f.claim}
                      </div>
                    ))}
                    {unknowns.map((f) => (
                      <div key={f.id} className="finding-card unknown-card">
                        <strong>Unknown:</strong> {f.claim}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Human Review Submission */}
      <Modal
        title="Submit Human Review Decision"
        isOpen={reviewModalOpen}
        onClose={() => setReviewModalOpen(false)}
      >
        <div className="modal-form">
          <p className="small-note">
            Required Human-in-the-Loop Governance: Formalize human analyst agreement, rejection, or modification of the AI investigation results.
          </p>
          <label htmlFor="review-decision">Review Decision:</label>
          <select
            id="review-decision"
            className="filter-select"
            value={reviewDecision}
            onChange={(e) => setReviewDecision(e.target.value as "ACCEPTED" | "REJECTED" | "MODIFIED")}
          >
            <option value="ACCEPTED">ACCEPTED — Findings fully validated against evidence</option>
            <option value="REJECTED">REJECTED — Findings unverified or halluncinatory</option>
            <option value="MODIFIED">MODIFIED — Accepted with human analyst corrections</option>
          </select>

          <label htmlFor="review-notes" style={{ marginTop: "12px" }}>
            Analyst Review Notes & Justification:
          </label>
          <textarea
            id="review-notes"
            rows={4}
            className="form-textarea"
            placeholder="Explain review decision with specific references to observed telemetry or external verification…"
            value={reviewNotes}
            onChange={(e) => setReviewNotes(e.target.value)}
          />

          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setReviewModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              onClick={handleReviewSubmit}
              disabled={isSubmitting || !reviewNotes.trim()}
              type="button"
            >
              {isSubmitting ? "Submitting…" : `Submit Review: ${reviewDecision}`}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
