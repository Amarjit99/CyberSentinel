import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Badge, EmptyState, Modal, SeverityBadge, StateBadge } from "../components/common";
import { DetectionCandidate, DetectionRule } from "../types";

export function DetectionRulesPage() {
  const [tab, setTab] = useState<"candidates" | "active">("candidates");
  const [candidates, setCandidates] = useState<DetectionCandidate[]>([]);
  const [activeRules, setActiveRules] = useState<DetectionRule[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<DetectionCandidate | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Actions state
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Generate modal
  const [genModalOpen, setGenModalOpen] = useState(false);
  const [genTitle, setGenTitle] = useState("");
  const [genObjective, setGenObjective] = useState("");
  const [genSeverity, setGenSeverity] = useState("medium");
  const [genCategory, setGenCategory] = useState("process_creation");

  // Review modal
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [reviewDecision, setReviewDecision] = useState<"APPROVE" | "REJECT">("APPROVE");
  const [reviewNotes, setReviewNotes] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [candRes, actRes] = await Promise.allSettled([
        api.getDetectionCandidates(),
        api.getActiveRules(),
      ]);

      if (candRes.status === "fulfilled") {
        setCandidates(candRes.value);
        if (candRes.value.length > 0 && !selectedCandidate) {
          setSelectedCandidate(candRes.value[0]);
        }
      }
      if (actRes.status === "fulfilled") setActiveRules(actRes.value);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed loading rules.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!genTitle.trim() || !genObjective.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const created = await api.generateDetectionCandidate({
        title: genTitle.trim(),
        objective: genObjective.trim(),
        severity: genSeverity,
        category: genCategory,
      });
      setActionSuccess(`Rule candidate generated: ${created.title}`);
      setGenModalOpen(false);
      setGenTitle("");
      setGenObjective("");
      fetchData();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Generation failed.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleValidate = async () => {
    if (!selectedCandidate) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.validateDetectionCandidate(selectedCandidate.id);
      setActionSuccess("Candidate rule passed validation check.");
      fetchData();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Validation failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTest = async () => {
    if (!selectedCandidate) return;
    setIsSubmitting(true);
    setActionError(null);
    try {
      const yaml = selectedCandidate.raw_yaml || selectedCandidate.rule_yaml || "";
      await api.testDetectionCandidate(selectedCandidate.id, yaml);
      setActionSuccess("Candidate rule test execution completed.");
      fetchData();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Rule testing failed.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReviewSubmit = async () => {
    if (!selectedCandidate || !reviewNotes.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.reviewDetectionCandidate(selectedCandidate.id, reviewDecision, reviewNotes.trim());
      setActionSuccess(`Human review decision recorded: ${reviewDecision}.`);
      setReviewModalOpen(false);
      setReviewNotes("");
      fetchData();
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

  const handleActivate = async () => {
    if (!selectedCandidate) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.activateDetectionCandidate(selectedCandidate.id);
      setActionSuccess(`Candidate ${selectedCandidate.id} activated into production rule set.`);
      fetchData();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Activation failed. Enforce human review first.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="detection-rules-page">
      <div className="tab-bar">
        <button
          className={`tab-item ${tab === "candidates" ? "active" : ""}`}
          onClick={() => setTab("candidates")}
          type="button"
        >
          ◇ Rule Candidate Lifecycle ({candidates.length})
        </button>
        <button
          className={`tab-item ${tab === "active" ? "active" : ""}`}
          onClick={() => setTab("active")}
          type="button"
        >
          ✓ Active Production Rules ({activeRules.length})
        </button>
      </div>

      {error && <EmptyState text={error} error retry={fetchData} />}

      {tab === "candidates" && (
        <div className="two-column-layout">
          {/* Left Column: Candidate List */}
          <div className="panel candidate-list-panel">
            <div className="panel-heading">
              <div>
                <h2>Rule Candidates ({candidates.length})</h2>
                <span className="muted">Draft, validate, test, review, and activate</span>
              </div>
              <button
                className="button-primary"
                onClick={() => setGenModalOpen(true)}
                type="button"
              >
                + Generate Rule…
              </button>
            </div>

            {loading ? (
              <EmptyState text="Loading candidates…" loading />
            ) : candidates.length === 0 ? (
              <EmptyState text="No detection candidates. Click 'Generate Rule' to create one." />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Title</th>
                      <th>Status</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {candidates.map((cand) => (
                      <tr
                        key={cand.id}
                        className={`clickable-row ${selectedCandidate?.id === cand.id ? "selected-row" : ""}`}
                        onClick={() => setSelectedCandidate(cand)}
                      >
                        <td>
                          <strong>{cand.title}</strong>
                          <div className="small-code">{cand.id.substring(0, 8)}…</div>
                        </td>
                        <td><StateBadge state={cand.status} /></td>
                        <td><SeverityBadge severity={cand.severity} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right Column: Candidate Workspace */}
          <div className="panel candidate-detail-panel">
            {!selectedCandidate ? (
              <EmptyState text="Select a rule candidate to inspect or progress." />
            ) : (
              <div>
                <div className="panel-heading">
                  <div>
                    <h2>{selectedCandidate.title}</h2>
                    <span className="muted">ID: <code>{selectedCandidate.id}</code></span>
                  </div>
                  <div className="badge-group">
                    <StateBadge state={selectedCandidate.status} />
                    <SeverityBadge severity={selectedCandidate.severity} />
                  </div>
                </div>

                {actionError && (
                  <div className="alert-box error" role="alert">
                    <strong>Error:</strong> {actionError}
                  </div>
                )}
                {actionSuccess && (
                  <div className="alert-box success" role="status">
                    {actionSuccess}
                  </div>
                )}

                {/* Candidate Lifecycle Toolbar */}
                <div className="action-toolbar">
                  <button
                    className="button-secondary"
                    onClick={handleValidate}
                    disabled={isSubmitting}
                    type="button"
                    title="Validate Sigma syntax and schema"
                  >
                    1. Validate Syntax
                  </button>
                  <button
                    className="button-secondary"
                    onClick={handleTest}
                    disabled={isSubmitting}
                    type="button"
                    title="Run against fixture events"
                  >
                    2. Test on Fixtures
                  </button>
                  <button
                    className="button-secondary"
                    onClick={() => setReviewModalOpen(true)}
                    disabled={isSubmitting}
                    type="button"
                    title="Record authorized human review"
                  >
                    3. Human Review…
                  </button>
                  <button
                    className="button-primary"
                    onClick={handleActivate}
                    disabled={isSubmitting}
                    type="button"
                    title="Activate into production rule set (Requires prior review)"
                  >
                    4. Activate Rule
                  </button>
                </div>

                <div className="info-callout">
                  <strong>Detection Engineering Rule:</strong> Detection rules are never auto-activated. Every candidate must pass syntax validation, deterministic fixture testing, and authorized human analyst review before activation into the production detection engine.
                </div>

                {selectedCandidate.validation_errors && selectedCandidate.validation_errors.length > 0 && (
                  <div className="alert-box error" style={{ marginTop: "12px" }}>
                    <strong>Validation Failures Detected:</strong>
                    <ul>
                      {selectedCandidate.validation_errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {selectedCandidate.review_notes && (
                  <div className="review-box" style={{ marginTop: "12px" }}>
                    <h4>Analyst Review Log:</h4>
                    <p className="summary-text">{selectedCandidate.review_notes}</p>
                    <small className="muted">Reviewer: {selectedCandidate.reviewer_id || "Analyst"}</small>
                  </div>
                )}

                {/* Rule YAML Preview */}
                <div className="detail-section">
                  <h3>Generated Sigma YAML</h3>
                  <pre className="yaml-view">{selectedCandidate.raw_yaml || selectedCandidate.rule_yaml || "No YAML content"}</pre>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "active" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Active Detection Rules ({activeRules.length})</h2>
              <span className="muted">Loaded in memory by the Sigma Detection Engine</span>
            </div>
            <button className="button-secondary" onClick={fetchData} type="button">
              ↻ Refresh
            </button>
          </div>

          {loading ? (
            <EmptyState text="Loading active rules…" loading />
          ) : activeRules.length === 0 ? (
            <EmptyState text="No active detection rules loaded in the engine." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule ID / Title</th>
                    <th>Category</th>
                    <th>Product</th>
                    <th>Severity</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {activeRules.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <strong>{r.title}</strong>
                        <div className="small-code">{r.id}</div>
                      </td>
                      <td><code>{r.category || "generic"}</code></td>
                      <td><code>{r.product || "windows"}</code></td>
                      <td><SeverityBadge severity={r.severity} /></td>
                      <td><Badge label={r.status.toUpperCase()} variant="healthy" size="small" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* Modal: Generate Candidate */}
      <Modal
        title="Generate New Sigma Rule Candidate"
        isOpen={genModalOpen}
        onClose={() => setGenModalOpen(false)}
      >
        <form onSubmit={handleGenerate} className="modal-form">
          <label htmlFor="gen-title">Rule Title:</label>
          <input
            id="gen-title"
            type="text"
            className="filter-input"
            style={{ width: "100%" }}
            placeholder="e.g., Suspicious PowerShell Encoded Command Execution"
            value={genTitle}
            onChange={(e) => setGenTitle(e.target.value)}
            required
          />

          <label htmlFor="gen-obj" style={{ marginTop: "10px" }}>Detection Objective:</label>
          <textarea
            id="gen-obj"
            rows={3}
            className="form-textarea"
            placeholder="Describe the malicious behavior, techniques, and expected indicators…"
            value={genObjective}
            onChange={(e) => setGenObjective(e.target.value)}
            required
          />

          <div className="form-row" style={{ marginTop: "10px" }}>
            <div>
              <label htmlFor="gen-sev">Severity:</label>
              <select
                id="gen-sev"
                className="filter-select"
                value={genSeverity}
                onChange={(e) => setGenSeverity(e.target.value)}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label htmlFor="gen-cat">Log Category:</label>
              <select
                id="gen-cat"
                className="filter-select"
                value={genCategory}
                onChange={(e) => setGenCategory(e.target.value)}
              >
                <option value="process_creation">Process Creation (Sysmon 1 / 4688)</option>
                <option value="network_connection">Network Connection (Sysmon 3)</option>
                <option value="file_event">File Event (Sysmon 11)</option>
                <option value="authentication">Authentication (Syslog / 4624)</option>
              </select>
            </div>
          </div>

          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setGenModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              disabled={isSubmitting || !genTitle.trim() || !genObjective.trim()}
              type="submit"
            >
              {isSubmitting ? "Generating…" : "Generate Candidate"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Human Review */}
      <Modal
        title="Record Human Review Decision"
        isOpen={reviewModalOpen}
        onClose={() => setReviewModalOpen(false)}
      >
        <div className="modal-form">
          <label htmlFor="rev-decision">Review Decision:</label>
          <select
            id="rev-decision"
            className="filter-select"
            value={reviewDecision}
            onChange={(e) => setReviewDecision(e.target.value as "APPROVE" | "REJECT")}
          >
            <option value="APPROVE">APPROVE — Validated against test fixtures</option>
            <option value="REJECT">REJECT — High false positive risk or syntax error</option>
          </select>

          <label htmlFor="rev-notes" style={{ marginTop: "10px" }}>Engineering Review Notes:</label>
          <textarea
            id="rev-notes"
            rows={3}
            className="form-textarea"
            placeholder="Document why this rule candidate is ready for production activation…"
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
              {isSubmitting ? "Submitting…" : `Record ${reviewDecision}`}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
