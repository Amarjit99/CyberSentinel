import React from "react";
import { RBACRole } from "../types";

export function Badge({
  label,
  variant = "neutral",
  size = "normal",
}: {
  label: string | number | undefined | null;
  variant?: "neutral" | "healthy" | "critical" | "high" | "medium" | "low" | "degraded" | "error" | "warning";
  size?: "small" | "normal";
}) {
  const text = label === null || label === undefined ? "—" : String(label);
  const normalizedVariant = variant.toLowerCase();
  return (
    <span className={`pill pill-${normalizedVariant} ${size === "small" ? "pill-sm" : ""}`}>
      {text}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "INFORMATIONAL").toUpperCase();
  let variant: "critical" | "high" | "medium" | "low" | "neutral" = "neutral";
  if (s === "CRITICAL") variant = "critical";
  else if (s === "HIGH") variant = "high";
  else if (s === "MEDIUM") variant = "medium";
  else if (s === "LOW") variant = "low";
  return <Badge label={s} variant={variant} />;
}

export function StateBadge({ state }: { state?: string }) {
  const s = (state || "UNKNOWN").toUpperCase();
  let variant: "neutral" | "healthy" | "medium" | "low" | "critical" = "neutral";
  if (s === "CONTAINED" || s === "REMEDIATED" || s === "CLOSED" || s === "ACTIVATED" || s === "APPROVED") {
    variant = "healthy";
  } else if (s === "INVESTIGATING" || s === "RUNNING" || s === "TESTED") {
    variant = "medium";
  } else if (s === "FAILED" || s === "REJECTED" || s === "REVOKED") {
    variant = "critical";
  }
  return <Badge label={s} variant={variant} />;
}

export function EmptyState({
  text,
  loading = false,
  error = false,
  retry,
}: {
  text: string;
  loading?: boolean;
  error?: boolean;
  retry?: () => void;
}) {
  return (
    <div className={`empty-state ${error ? "error" : ""}`}>
      {loading ? (
        <span className="spinner" aria-label="Loading" />
      ) : (
        <span className="empty-icon">{error ? "⚠" : "∅"}</span>
      )}
      <p>{text}</p>
      {retry && (
        <button className="button-secondary" onClick={retry} type="button">
          Retry
        </button>
      )}
    </div>
  );
}

export function SafetyBanner({ message }: { message?: string }) {
  return (
    <div className="safety-banner" role="alert">
      <div className="safety-header">
        <span className="safety-icon">🛡</span>
        <strong>SAFETY GUARDRAIL ENFORCED: LIVE_RESPONSE_DISABLED=true</strong>
      </div>
      <p>
        {message ||
          "Direct execution on production targets is strictly blocked by the backend safety engine. All response actions remain dry-run only and require explicit human-in-the-loop authorization."}
      </p>
    </div>
  );
}

export function Modal({
  title,
  isOpen,
  onClose,
  children,
}: {
  title: string;
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
}) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title}</h3>
          <button className="modal-close" onClick={onClose} type="button" aria-label="Close modal">
            ✕
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function RoleSwitcher({
  currentRole,
  onRoleChange,
}: {
  currentRole: RBACRole;
  onRoleChange: (role: RBACRole) => void;
}) {
  const roles: RBACRole[] = [
    "SOC_ANALYST",
    "INCIDENT_COMMANDER",
    "SECURITY_ENGINEER",
    "SOC_MANAGER",
    "ADMIN",
    "VIEWER",
  ];

  return (
    <div className="role-switcher">
      <label htmlFor="role-select">Active Role:</label>
      <select
        id="role-select"
        value={currentRole}
        onChange={(e) => onRoleChange(e.target.value as RBACRole)}
        className="role-select"
      >
        {roles.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </div>
  );
}
