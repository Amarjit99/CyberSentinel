import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, EmptyState } from "../components/common";
import { ThreatIndicator, ThreatSource } from "../types";

export function ThreatIntelPage() {
  const [tab, setTab] = useState<"indicators" | "attack" | "sources">("indicators");
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [sources, setSources] = useState<ThreatSource[]>([]);
  const [tactics, setTactics] = useState<Record<string, unknown>[]>([]);
  const [coverage, setCoverage] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Indicator lookup
  const [lookupQuery, setLookupQuery] = useState("");
  const [lookupResult, setLookupResult] = useState<unknown>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Filter
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [searchFilter, setSearchFilter] = useState("");

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [indRes, srcRes, tacRes, covRes] = await Promise.allSettled([
        api.getThreatIndicators(),
        api.getThreatSources(),
        api.getAttackTactics(),
        api.getAttackCoverage(),
      ]);

      if (indRes.status === "fulfilled") setIndicators(indRes.value);
      if (srcRes.status === "fulfilled") setSources(srcRes.value);
      if (tacRes.status === "fulfilled") setTactics(tacRes.value);
      if (covRes.status === "fulfilled") setCoverage(covRes.value);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load threat intel.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;
    setLookupLoading(true);
    setLookupError(null);
    setLookupResult(null);
    try {
      const res = await api.lookupThreatIndicator(lookupQuery.trim());
      setLookupResult(res);
    } catch (err: unknown) {
      setLookupError(err instanceof Error ? err.message : "Lookup failed.");
    } finally {
      setLookupLoading(false);
    }
  };

  const filteredIndicators = indicators.filter((ind) => {
    const matchesSearch =
      searchFilter.trim() === "" ||
      ind.value.toLowerCase().includes(searchFilter.toLowerCase()) ||
      ind.source.toLowerCase().includes(searchFilter.toLowerCase());
    const matchesType = typeFilter === "ALL" || ind.type.toUpperCase() === typeFilter.toUpperCase();
    return matchesSearch && matchesType;
  });

  return (
    <div className="threat-intel-page">
      <div className="tab-bar">
        <button
          className={`tab-item ${tab === "indicators" ? "active" : ""}`}
          onClick={() => setTab("indicators")}
          type="button"
        >
          ◈ Indicators of Compromise ({indicators.length})
        </button>
        <button
          className={`tab-item ${tab === "attack" ? "active" : ""}`}
          onClick={() => setTab("attack")}
          type="button"
        >
          ⊞ MITRE ATT&CK Matrix & Coverage
        </button>
        <button
          className={`tab-item ${tab === "sources" ? "active" : ""}`}
          onClick={() => setTab("sources")}
          type="button"
        >
          🗂 Threat Intelligence Feeds ({sources.length})
        </button>
      </div>

      {error && <EmptyState text={error} error retry={fetchData} />}

      {/* Tab 1: Indicators */}
      {tab === "indicators" && (
        <div>
          {/* Quick Lookup Bar */}
          <section className="panel" style={{ marginBottom: "14px" }}>
            <div className="panel-heading">
              <div>
                <h2>IOC Exact-Match Lookup</h2>
                <span className="muted">Check IP, hash, or domain against active curated threat feeds</span>
              </div>
            </div>
            <form onSubmit={handleLookup} className="lookup-form">
              <input
                type="text"
                className="filter-input"
                style={{ width: "400px", marginBottom: 0 }}
                placeholder="Enter IP, SHA256, domain, or process name…"
                value={lookupQuery}
                onChange={(e) => setLookupQuery(e.target.value)}
              />
              <button
                className="button-primary"
                disabled={lookupLoading || !lookupQuery.trim()}
                type="submit"
              >
                {lookupLoading ? "Querying…" : "Check IOC"}
              </button>
            </form>

            {lookupError && (
              <div className="alert-box error" style={{ marginTop: "12px" }}>
                {lookupError}
              </div>
            )}
            {Boolean(lookupResult) && (
              <div className="lookup-result-box">
                <h4>Lookup Match Found:</h4>
                <pre className="json-snippet">{JSON.stringify(lookupResult, null, 2)}</pre>
              </div>
            )}
          </section>

          {/* Indicators List */}
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Active Threat Indicators ({filteredIndicators.length})</h2>
                <span className="muted">Truthful display of provenance, confidence, and expiration</span>
              </div>
              <div className="filter-group">
                <input
                  type="text"
                  className="filter-input search-input"
                  style={{ marginBottom: 0 }}
                  placeholder="Filter by value or source…"
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                />
                <select
                  className="filter-select"
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  <option value="ALL">All Types</option>
                  <option value="IPV4">IPv4</option>
                  <option value="IPV6">IPv6</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="FILE_HASH_SHA256">SHA-256</option>
                  <option value="FILE_HASH_MD5">MD5</option>
                </select>
              </div>
            </div>

            {loading ? (
              <EmptyState text="Loading threat indicators…" loading />
            ) : filteredIndicators.length === 0 ? (
              <EmptyState text="No threat indicators match the filter." />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Indicator Value</th>
                      <th>Confidence</th>
                      <th>Source</th>
                      <th>First Seen</th>
                      <th>Expires</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIndicators.slice(0, 50).map((ind) => (
                      <tr key={ind.id}>
                        <td><code>{ind.type}</code></td>
                        <td><strong>{ind.value}</strong></td>
                        <td>{(ind.confidence * 100).toFixed(0)}%</td>
                        <td>{ind.source}</td>
                        <td><small>{new Date(ind.first_seen).toLocaleDateString()}</small></td>
                        <td>
                          {ind.expires_at ? (
                            <small>{new Date(ind.expires_at).toLocaleDateString()}</small>
                          ) : (
                            <span className="muted">No expiry</span>
                          )}
                        </td>
                        <td>
                          {ind.revoked ? (
                            <Badge label="REVOKED" variant="error" size="small" />
                          ) : (
                            <Badge label="ACTIVE" variant="healthy" size="small" />
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {/* Tab 2: MITRE ATT&CK Matrix & Coverage */}
      {tab === "attack" && (
        <div>
          <section className="panel" style={{ marginBottom: "14px" }}>
            <div className="panel-heading">
              <div>
                <h2>Enterprise ATT&CK Detection Coverage</h2>
                <span className="muted">Calculated coverage based on active Sigma and correlation rules</span>
              </div>
              {coverage && (
                <Badge
                  label={`Overall Coverage: ${((coverage.overall_coverage_percentage as number) || 0).toFixed(1)}%`}
                  variant="healthy"
                />
              )}
            </div>

            {loading ? (
              <EmptyState text="Loading coverage metrics…" loading />
            ) : (
              <div className="tactics-grid">
                {tactics.map((tac) => {
                  const tid = String(tac.id || tac.tactic_id || "");
                  const name = String(tac.name || tid);
                  return (
                    <div key={tid} className="tactic-card">
                      <div className="tactic-header">
                        <code>{tid}</code>
                        <strong>{name}</strong>
                      </div>
                      <p className="tactic-desc">{String(tac.description || "").substring(0, 120)}…</p>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      )}

      {/* Tab 3: Threat Feeds & Sources */}
      {tab === "sources" && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Configured Threat Intelligence Feeds</h2>
              <span className="muted">STIX 2.1, TAXII, and JSON threat feeds</span>
            </div>
          </div>

          {loading ? (
            <EmptyState text="Loading threat sources…" loading />
          ) : sources.length === 0 ? (
            <EmptyState text="No threat sources configured." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Source Name</th>
                    <th>Feed Type</th>
                    <th>URL / Endpoint</th>
                    <th>Status</th>
                    <th>Last Ingested</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map((src) => (
                    <tr key={src.id}>
                      <td><strong>{src.name}</strong></td>
                      <td><code>{src.feed_type}</code></td>
                      <td><small className="muted">{src.url || "Local file source"}</small></td>
                      <td>
                        <Badge
                          label={src.enabled ? "ENABLED" : "DISABLED"}
                          variant={src.enabled ? "healthy" : "neutral"}
                          size="small"
                        />
                      </td>
                      <td>
                        <small>
                          {src.last_ingested_at
                            ? new Date(src.last_ingested_at).toLocaleString()
                            : "Never"}
                        </small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
