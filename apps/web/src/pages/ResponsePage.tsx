import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Badge, EmptyState, Modal, SafetyBanner, StateBadge } from "../components/common";
import { Incident, ResponseActionCatalogueItem, ResponseProposal } from "../types";

export function ResponsePage({ onNavigateToIncident }: { onNavigateToIncident?: (id: string) => void }) {
  const [tab, setTab] = useState<"proposals" | "catalogue">("proposals");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [proposals, setProposals] = useState<ResponseProposal[]>([]);
  const [catalogue, setCatalogue] = useState<ResponseActionCatalogueItem[]>([]);
  const [selectedProposal, setSelectedProposal] = useState<ResponseProposal | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Approval modal
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [approvalReason, setApprovalReason] = useState("");

  // Revoke modal
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const [revokeReason, setRevokeReason] = useState("");

  // Create proposal modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [actionType, setActionType] = useState("");
  const [targetEntity, setTargetEntity] = useState("");
  const [proposalReason, setProposalReason] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [catList, incList] = await Promise.allSettled([
        api.getResponseCatalogue(),
        api.getIncidents(),
      ]);

      if (catList.status === "fulfilled") setCatalogue(catList.value);
      if (incList.status === "fulfilled") {
        setIncidents(incList.value);
        if (incList.value.length > 0) {
          const firstId = incList.value[0].id;
          setSelectedIncidentId(firstId);
          fetchIncidentProposals(firstId);
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load response data.");
    } finally {
      setLoading(false);
    }
  };

  const fetchIncidentProposals = async (incId: string) => {
    try {
      const pList = await api.getIncidentProposals(incId);
      setProposals(pList);
      if (pList.length > 0) setSelectedProposal(pList[0]);
      else setSelectedProposal(null);
    } catch {
      setProposals([]);
      setSelectedProposal(null);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleIncidentChange = (incId: string) => {
    setSelectedIncidentId(incId);
    setActionError(null);
    setActionSuccess(null);
    fetchIncidentProposals(incId);
  };

  const handleCreateProposal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncidentId || !actionType || !targetEntity.trim() || !proposalReason.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const created = await api.createProposal(selectedIncidentId, {
        action_type: actionType,
        target_entity: targetEntity.trim(),
        reason: proposalReason.trim(),
        evidence_refs: ["manual-analyst-proposal"],
        action_payload: { entity: targetEntity.trim(), operator_initiated: true },
      });
      setActionSuccess(`Response proposal created: ${created.id}`);
      setCreateModalOpen(false);
      setProposalReason("");
      setTargetEntity("");
      fetchIncidentProposals(selectedIncidentId);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Proposal creation failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleApprove = async () => {
    if (!selectedProposal || !approvalReason.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.approveProposal(selectedProposal.id, approvalReason.trim());
      setActionSuccess(`Proposal ${selectedProposal.id} approved.`);
      setApprovalModalOpen(false);
      setApprovalReason("");
      fetchIncidentProposals(selectedIncidentId);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Approval failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevoke = async () => {
    if (!selectedProposal || !revokeReason.trim()) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      await api.revokeProposal(selectedProposal.id, revokeReason.trim());
      setActionSuccess(`Proposal ${selectedProposal.id} revoked.`);
      setRevokeModalOpen(false);
      setRevokeReason("");
      fetchIncidentProposals(selectedIncidentId);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Revocation failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDryRunExecute = async () => {
    if (!selectedProposal) return;
    setIsSubmitting(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.executeProposalDryRun(selectedProposal.id);
      setActionSuccess(`Dry-run execution simulated successfully. Response: ${JSON.stringify(res)}`);
      fetchIncidentProposals(selectedIncidentId);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setActionError(`[${err.errorCode}] ${err.message}`);
      } else {
        setActionError(err instanceof Error ? err.message : "Execution failed.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="response-page">
      <SafetyBanner />

      <div className="tab-bar">
        <button
          className={`tab-item ${tab === "proposals" ? "active" : ""}`}
          onClick={() => setTab("proposals")}
          type="button"
        >
          🛡 Incident Response Proposals ({proposals.length})
        </button>
        <button
          className={`tab-item ${tab === "catalogue" ? "active" : ""}`}
          onClick={() => setTab("catalogue")}
          type="button"
        >
          📋 Governed Action Catalogue ({catalogue.length})
        </button>
      </div>

      {error && <EmptyState text={error} error retry={fetchData} />}

      {tab === "proposals" && (
        <div>
          {/* Incident Selector */}
          <div className="panel-controls" style={{ marginBottom: "12px" }}>
            <label htmlFor="inc-selector" style={{ fontWeight: 600 }}>Target Incident:</label>
            <select
              id="inc-selector"
              className="filter-select"
              style={{ minWidth: "320px" }}
              value={selectedIncidentId}
              onChange={(e) => handleIncidentChange(e.target.value)}
            >
              {incidents.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.title} ({i.id.substring(0, 8)}…) — {i.severity}
                </option>
              ))}
            </select>
            <button
              className="button-primary"
              onClick={() => setCreateModalOpen(true)}
              disabled={!selectedIncidentId}
              type="button"
            >
              + Create Proposal…
            </button>
          </div>

          <div className="two-column-layout">
            {/* Left Column: Proposals List */}
            <div className="panel proposal-list-panel">
              <div className="panel-heading">
                <div>
                  <h2>Proposals for Incident</h2>
                  <span className="muted">Multi-person approval tracking and integrity verification</span>
                </div>
              </div>

              {loading ? (
                <EmptyState text="Loading proposals…" loading />
              ) : proposals.length === 0 ? (
                <EmptyState text="No containment or remediation proposals for this incident." />
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Action</th>
                        <th>Target</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {proposals.map((p) => (
                        <tr
                          key={p.id}
                          className={`clickable-row ${selectedProposal?.id === p.id ? "selected-row" : ""}`}
                          onClick={() => setSelectedProposal(p)}
                        >
                          <td>
                            <strong>{p.action_type}</strong>
                            <div className="small-code">{p.id.substring(0, 8)}…</div>
                          </td>
                          <td><code>{p.target_entity}</code></td>
                          <td><StateBadge state={p.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Right Column: Proposal Detail & Approval Workspace */}
            <div className="panel proposal-detail-panel">
              {!selectedProposal ? (
                <EmptyState text="Select a response proposal to review approvals or simulate dry run." />
              ) : (
                <div>
                  <div className="panel-heading">
                    <div>
                      <h2>{selectedProposal.action_type}</h2>
                      <span className="muted">Proposal ID: <code>{selectedProposal.id}</code></span>
                    </div>
                    <StateBadge state={selectedProposal.status} />
                  </div>

                  {actionError && (
                    <div className="alert-box error" role="alert">
                      <strong>Action Blocked:</strong> {actionError}
                    </div>
                  )}
                  {actionSuccess && (
                    <div className="alert-box success" role="status">
                      {actionSuccess}
                    </div>
                  )}

                  {/* Actions Toolbar */}
                  <div className="action-toolbar">
                    <button
                      className="button-primary"
                      onClick={() => setApprovalModalOpen(true)}
                      disabled={isSubmitting || selectedProposal.status === "APPROVED" || selectedProposal.status === "EXECUTED"}
                      type="button"
                    >
                      ✓ Authorize / Approve…
                    </button>
                    <button
                      className="button-secondary"
                      onClick={() => setRevokeModalOpen(true)}
                      disabled={isSubmitting || selectedProposal.status === "REVOKED"}
                      type="button"
                    >
                      ✕ Revoke / Reject…
                    </button>
                    <button
                      className="button-secondary"
                      onClick={handleDryRunExecute}
                      disabled={isSubmitting}
                      type="button"
                      title="Simulate dry run. Live response is disabled."
                    >
                      🛡 Simulate Dry Run
                    </button>
                  </div>

                  <div className="detail-section">
                    <h3>Proposal Details & Integrity</h3>
                    <div className="metric-row">
                      <span>Target Entity:</span>
                      <strong><code>{selectedProposal.target_entity}</code></strong>
                    </div>
                    <div className="metric-row">
                      <span>Creator Principal:</span>
                      <span>{selectedProposal.creator_id}</span>
                    </div>
                    <div className="metric-row">
                      <span>Payload SHA-256 Hash:</span>
                      <code>{selectedProposal.payload_hash || "Calculated on submit"}</code>
                    </div>
                    <div className="metric-row">
                      <span>Operational Reason:</span>
                      <p className="summary-text">{selectedProposal.reason}</p>
                    </div>
                  </div>

                  {/* Approvals History */}
                  <div className="detail-section">
                    <h3>Multi-Person Approval Audit Trail</h3>
                    {!selectedProposal.approvals || selectedProposal.approvals.length === 0 ? (
                      <span className="muted">Awaiting required authorized peer approvals.</span>
                    ) : (
                      <ul className="timeline-list">
                        {selectedProposal.approvals.map((app) => (
                          <li key={app.id} className="timeline-item">
                            <span className="timeline-time">{new Date(app.approved_at).toLocaleString()}</span>
                            <div className="timeline-content">
                              <strong>{app.approver_id}</strong> voted{" "}
                              <Badge label={app.decision} variant={app.decision === "APPROVED" ? "healthy" : "critical"} size="small" />:{" "}
                              <em>"{app.reason}"</em>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {/* Action Payload JSON */}
                  <div className="detail-section">
                    <h3>Payload Data</h3>
                    <pre className="json-snippet">{JSON.stringify(selectedProposal.action_payload, null, 2)}</pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {tab === "catalogue" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Standardized Response Action Catalogue</h2>
              <span className="muted">Permitted containment, eradication, and forensic collection playbooks</span>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action Type</th>
                  <th>Description</th>
                  <th>Target Entities</th>
                  <th>Multi-Person Approval</th>
                  <th>Reversibility</th>
                  <th>Destructive</th>
                </tr>
              </thead>
              <tbody>
                {catalogue.map((act) => (
                  <tr key={act.action_type}>
                    <td><strong>{act.name || act.action_type}</strong><br /><small className="small-code">{act.action_type}</small></td>
                    <td>{act.description}</td>
                    <td><code>{(act.target_entity_types || []).join(", ")}</code></td>
                    <td>
                      <Badge
                        label={act.requires_multi_person_approval ? "REQUIRED (2-PERSON)" : "STANDARD"}
                        variant={act.requires_multi_person_approval ? "warning" : "neutral"}
                        size="small"
                      />
                    </td>
                    <td><code>{act.reversibility}</code></td>
                    <td>
                      <Badge
                        label={act.is_destructive ? "DESTRUCTIVE" : "NON-DESTRUCTIVE"}
                        variant={act.is_destructive ? "critical" : "healthy"}
                        size="small"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Modal: Create Proposal */}
      <Modal
        title="Create New Response Proposal"
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
      >
        <form onSubmit={handleCreateProposal} className="modal-form">
          <label htmlFor="prop-action">Action Type:</label>
          <select
            id="prop-action"
            className="filter-select"
            value={actionType}
            onChange={(e) => setActionType(e.target.value)}
            required
          >
            <option value="">-- Choose Catalogue Action --</option>
            {catalogue.map((c) => (
              <option key={c.action_type} value={c.action_type}>
                {c.name || c.action_type} ({c.action_type})
              </option>
            ))}
          </select>

          <label htmlFor="prop-target" style={{ marginTop: "10px" }}>Target Entity:</label>
          <input
            id="prop-target"
            type="text"
            className="filter-input"
            style={{ width: "100%" }}
            placeholder="e.g., 192.168.1.50 or DESKTOP-HR-01 or user@corp.local"
            value={targetEntity}
            onChange={(e) => setTargetEntity(e.target.value)}
            required
          />

          <label htmlFor="prop-reason" style={{ marginTop: "10px" }}>Operational Justification:</label>
          <textarea
            id="prop-reason"
            rows={3}
            className="form-textarea"
            placeholder="Document evidence grounding and containment necessity…"
            value={proposalReason}
            onChange={(e) => setProposalReason(e.target.value)}
            required
          />

          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setCreateModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              disabled={isSubmitting || !actionType || !targetEntity.trim()}
              type="submit"
            >
              {isSubmitting ? "Creating…" : "Submit Proposal"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal: Approve */}
      <Modal
        title="Authorize Response Proposal"
        isOpen={approvalModalOpen}
        onClose={() => setApprovalModalOpen(false)}
      >
        <div className="modal-form">
          <p className="small-note">
            Multi-person approval policy: The approver cannot be the same principal who proposed the action.
          </p>
          <label htmlFor="app-reason">Approval Justification & Policy Compliance:</label>
          <textarea
            id="app-reason"
            rows={3}
            className="form-textarea"
            placeholder="Confirm that target containment aligns with validated evidence and incident scope…"
            value={approvalReason}
            onChange={(e) => setApprovalReason(e.target.value)}
          />
          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setApprovalModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-primary"
              onClick={handleApprove}
              disabled={isSubmitting || !approvalReason.trim()}
              type="button"
            >
              {isSubmitting ? "Authorizing…" : "Confirm Approval"}
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal: Revoke */}
      <Modal
        title="Revoke Response Proposal"
        isOpen={revokeModalOpen}
        onClose={() => setRevokeModalOpen(false)}
      >
        <div className="modal-form">
          <label htmlFor="rev-reason">Revocation Reason:</label>
          <textarea
            id="rev-reason"
            rows={3}
            className="form-textarea"
            placeholder="Explain why this proposal is rejected (e.g. false positive, wrong host)…"
            value={revokeReason}
            onChange={(e) => setRevokeReason(e.target.value)}
          />
          <div className="modal-actions">
            <button
              className="button-secondary"
              onClick={() => setRevokeModalOpen(false)}
              disabled={isSubmitting}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button-danger"
              onClick={handleRevoke}
              disabled={isSubmitting || !revokeReason.trim()}
              type="button"
            >
              {isSubmitting ? "Revoking…" : "Revoke Proposal"}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
