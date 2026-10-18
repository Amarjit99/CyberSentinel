import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, getActiveRole, setActiveRole } from "./api";
import { RoleSwitcher } from "./components/common";
import { AdminPage } from "./pages/AdminPage";
import { AlertsPage } from "./pages/AlertsPage";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { DetectionRulesPage } from "./pages/DetectionRulesPage";
import { EventsPage } from "./pages/EventsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ResponsePage } from "./pages/ResponsePage";
import { ThreatIntelPage } from "./pages/ThreatIntelPage";
import "./styles.css";
import { AnalystNotification, RBACRole } from "./types";

export type Page =
  | "Overview"
  | "Events"
  | "Alerts"
  | "Incidents"
  | "Investigations"
  | "Threat Intelligence"
  | "Detection Rules"
  | "Response Playbooks"
  | "Reports"
  | "Administration";

const pages: Page[] = [
  "Overview",
  "Events",
  "Alerts",
  "Incidents",
  "Investigations",
  "Threat Intelligence",
  "Detection Rules",
  "Response Playbooks",
  "Reports",
  "Administration",
];

function iconFor(page: Page) {
  const icons: Record<Page, string> = {
    Overview: "⌂",
    Events: "≋",
    Alerts: "!",
    Incidents: "◆",
    Investigations: "⌕",
    "Threat Intelligence": "◈",
    "Detection Rules": "◇",
    "Response Playbooks": "🛡",
    Reports: "▥",
    Administration: "⚙",
  };
  return icons[page] ?? "•";
}

function descriptions(page: Page): string {
  const map: Record<Page, string> = {
    Overview: "Operational triage dashboard: incident severity queues, detection alerts, and system health.",
    Events: "Telemetry event search and inspection with source provenance and host/network filtering.",
    Alerts: "Detection alert lifecycle, assignment, analyst notes, and audited state transitions.",
    Incidents: "Incident queue, timeline, entities, evidence grounding, deterministic risk, and lifecycle state transitions.",
    Investigations: "Bounded AI investigation agent runs, verified claims vs hypotheses, evidence citations, and human reviews.",
    "Threat Intelligence": "Active indicators of compromise, STIX/TAXII feeds, and MITRE ATT&CK coverage mapping.",
    "Detection Rules": "Sigma and correlation rules: draft candidate generation, syntax validation, fixture testing, review, and activation.",
    "Response Playbooks": "Governed containment proposals, multi-person authorization tracking, and dry-run safety simulation.",
    Reports: "Standardized benchmark framework: ground-truth validation, precision/recall/F1 metrics, and regression comparisons.",
    Administration: "Security operations controls, role authorization matrix, quarantine queue, and agent tool registry.",
  };
  return map[page] || "";
}

function App() {
  const [currentPage, setCurrentPage] = useState<Page>("Overview");
  const [activeRole, setRole] = useState<RBACRole>(getActiveRole());
  const [apiState, setApiState] = useState<"healthy" | "degraded" | "offline">("healthy");
  const [apiDetail, setApiDetail] = useState("Probing backend APIs…");
  const [notifications, setNotifications] = useState<AnalystNotification[]>([]);

  // Cross-page navigation parameters
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  const checkHealth = async () => {
    try {
      const [h, r] = await Promise.all([api.getHealth(), api.getReadiness()]);
      if (h.status === "healthy" && r.ready) {
        setApiState("healthy");
        setApiDetail("API healthy & all dependencies ready");
      } else {
        setApiState("degraded");
        setApiDetail(`Health: ${h.status}, Ready: ${r.ready}`);
      }
    } catch {
      setApiState("offline");
      setApiDetail("Backend API unreachable at /health or /ready");
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const loadNotifications = async () => {
      try {
        setNotifications(await api.getNotifications());
      } catch {
        setNotifications([]);
      }
    };
    void loadNotifications();
    const interval = setInterval(loadNotifications, 30000);
    return () => clearInterval(interval);
  }, [activeRole]);

  const handleRoleChange = (role: RBACRole) => {
    setActiveRole(role);
    setRole(role);
  };

  const navigateTo = (target: string, id?: string) => {
    const p = target as Page;
    if (pages.includes(p)) {
      if (p === "Incidents" && id) setSelectedIncidentId(id);
      if (p === "Investigations" && id) setSelectedRunId(id);
      setCurrentPage(p);
    }
  };

  return (
    <div className="app-shell">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">CS</span>
          <div>
            <strong>CyberSentinel</strong>
            <small>Security Operations AI</small>
          </div>
        </div>

        <nav aria-label="Primary navigation">
          {pages.map((p) => (
            <button
              key={p}
              type="button"
              className={`nav-item ${currentPage === p ? "active" : ""}`}
              aria-current={currentPage === p ? "page" : undefined}
              onClick={() => {
                if (p !== "Incidents") setSelectedIncidentId(null);
                if (p !== "Investigations") setSelectedRunId(null);
                setCurrentPage(p);
              }}
            >
              <span className="nav-icon" aria-hidden="true">{iconFor(p)}</span>
              {p}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <RoleSwitcher currentRole={activeRole} onRoleChange={handleRoleChange} />
          <span className="muted safety-note">
            Human approval required for all consequential operations
          </span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="content">
        <header className="topbar">
          <div>
            <span className="eyebrow">ANALYST WORKSPACE</span>
            <h1>{currentPage}</h1>
          </div>
          <div className="topbar-right">
            <div className="notification-menu" aria-label="Analyst notifications">
              <span aria-live="polite">
                Notifications{notifications.some((item) => !item.read) ? ` (${notifications.filter((item) => !item.read).length})` : ""}
              </span>
              {notifications.slice(0, 3).map((notification) => (
                <button
                  key={notification.id}
                  type="button"
                  className={`notification-item ${notification.read ? "" : "unread"}`}
                  onClick={() => {
                    void api.markNotificationRead(notification.id);
                    setNotifications((items) => items.map((item) => item.id === notification.id ? { ...item, read: true } : item));
                  }}
                >
                  <strong>{notification.title}</strong>
                  <small>{notification.message}</small>
                </button>
              ))}
            </div>
            <div className="system-status" title={apiDetail}>
              <span className={`status-dot ${apiState}`} />
              <span>{apiState === "healthy" ? "System Ready" : apiState}</span>
            </div>
          </div>
        </header>

        <section className="page-intro">
          <p>{descriptions(currentPage)}</p>
          <span className="time-context">UTC · Governed SOC Operations</span>
        </section>

        {/* Page Routing */}
        {currentPage === "Overview" && (
          <OverviewPage onNavigate={navigateTo} />
        )}
        {currentPage === "Events" && (
          <EventsPage />
        )}
        {currentPage === "Alerts" && (
          <AlertsPage />
        )}
        {currentPage === "Incidents" && (
          <IncidentsPage
            initialIncidentId={selectedIncidentId}
            onNavigateToInvestigation={(runId) => navigateTo("Investigations", runId)}
          />
        )}
        {currentPage === "Investigations" && (
          <InvestigationsPage
            initialRunId={selectedRunId}
            onNavigateToIncident={(incId) => navigateTo("Incidents", incId)}
          />
        )}
        {currentPage === "Threat Intelligence" && (
          <ThreatIntelPage />
        )}
        {currentPage === "Detection Rules" && (
          <DetectionRulesPage />
        )}
        {currentPage === "Response Playbooks" && (
          <ResponsePage onNavigateToIncident={(id) => navigateTo("Incidents", id)} />
        )}
        {currentPage === "Reports" && (
          <BenchmarkPage />
        )}
        {currentPage === "Administration" && (
          <AdminPage />
        )}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
