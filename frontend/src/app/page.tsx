"use client";

import { useEffect, useState, type FormEvent } from "react";

const API_BASE = "http://127.0.0.1:8000";

const modules = [
  ["⌕", "Domain Intelligence"],
  ["◈", "DNS Analysis"],
  ["⌘", "Subdomain Discovery"],
  ["◎", "Live Host Detection"],
  ["◇", "SSL / TLS"],
  ["▤", "Technology Stack"],
  ["◎", "Infrastructure"],
  ["⬡", "Security Headers"],
  ["✉", "Email Security"],
  ["◉", "Threat Intelligence"],
];
type ModuleResult = {
  status: string;
  data?: unknown;
  error?: string;
};

type ScanSummary = {
  domain: string;
  status: string;
  total_modules: number;
  successful_modules: number;
  results: Record<string, ModuleResult>;
};

type ScanResponse = {
  scan_id: number;
  domain: string;
  status: string;
  results: ScanSummary;
};
type HistoryItem = {
  scan_id: number;
  domain: string;
  status: string;
  created_at: string;
};

type HistoryResponse = {
  total: number;
  scans: HistoryItem[];
};

const moduleLabels: Record<string, string> = {
  domain_intelligence: "Domain Intelligence",
  dns_analysis: "DNS Analysis",
  subdomain_discovery: "Subdomain Discovery",
  live_host_detection: "Live Host Detection",
  ssl_tls: "SSL / TLS",
  technology_stack: "Technology Stack",
  infrastructure: "Infrastructure",
  security_headers: "Security Headers",
  email_security: "Email Security",
  threat_intelligence: "Threat Intelligence",
};

export default function Home() {
  const [domain, setDomain] = useState("");
  const [notice, setNotice] = useState("");
  const [active, setActive] = useState("Overview");
  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
    const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [selectedHistory, setSelectedHistory] = useState<unknown>(null);

  useEffect(() => {
    let mounted = true;

    async function checkBackend() {
      try {
        const response = await fetch(`${API_BASE}/api/v1/health`);
        if (!response.ok) throw new Error("API unavailable");

        const data = await response.json();

        if (mounted) {
          setConnected(data.status === "healthy");
        }
      } catch {
        if (mounted) setConnected(false);
      }
    }

    checkBackend();
    const interval = window.setInterval(checkBackend, 10000);

    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  async function handleScan(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();

    const value = domain
      .trim()
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .split(":")[0];

    if (!/^(?=.{1,253}$)([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(value)) {
      setNotice("Please enter a valid domain, e.g. example.com");
      return;
    }

    if (!connected) {
      setNotice("Backend is offline. Please start the Python API first.");
      return;
    }

    setScanning(true);
    setScanResult(null);
    setNotice(`Creating scan for ${value}...`);

    try {
      // Step 1: Create an authorized scan record.
      const createResponse = await fetch(`${API_BASE}/api/v1/scans`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          domain: value,
        }),
      });

      const createData = await createResponse.json();

      if (!createResponse.ok) {
        throw new Error(
          createData.detail || "Could not create scan."
        );
      }

      const scanId = createData.scan_id;

      if (!scanId) {
        throw new Error("Backend did not return a scan ID.");
      }

      setNotice(`Scan #${scanId} created. Running intelligence modules...`);

      // Step 2: Execute the scan using the Python engine.
      const runResponse = await fetch(
        `${API_BASE}/api/v1/scans/${scanId}/run`,
        {
          method: "POST",
        }
      );

      const runData: ScanResponse | { detail?: string } =
        await runResponse.json();

      if (!runResponse.ok) {
        throw new Error(
          "detail" in runData
            ? runData.detail || "Scan execution failed."
            : "Scan execution failed."
        );
      }

      const completedScan = runData as ScanResponse;

      setScanResult(completedScan);
      setDomain(value);
      setNotice(
        `Scan completed: ${completedScan.status.toUpperCase()} — ` +
          `${completedScan.results.successful_modules} of ` +
          `${completedScan.results.total_modules} modules successful.`
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error occurred.";

      setNotice(`Scan error: ${message}`);
    } finally {
      setScanning(false);
    }
  }

async function downloadReport(
  scanId: number,
  format: "clean" | "json"
) {
  try {
    setHistoryError("");

    const response = await fetch(
      `${API_BASE}/api/v1/scans/${scanId}/report?format=${format}`
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.detail || "Could not download PDF report"
      );
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = `cybrot_scan_${scanId}_${format}.pdf`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => URL.revokeObjectURL(url), 1000);

  } catch (error) {
    setHistoryError(
      error instanceof Error ? error.message : "PDF download failed"
    );
  }
}


async function loadHistory() {
  setHistoryLoading(true);
  setHistoryError("");

  try {
    const response = await fetch(`${API_BASE}/api/v1/scans`);

    if (!response.ok) {
      throw new Error("Could not load scan history");
    }

    const data: HistoryResponse = await response.json();
    setHistory(data.scans);
  } catch (error) {
    setHistoryError(
      error instanceof Error ? error.message : "History loading failed"
    );
  } finally {
    setHistoryLoading(false);
  }
}

async function openHistoryScan(scanId: number) {
  try {
    setSelectedHistory(null);

    const response = await fetch(
      `${API_BASE}/api/v1/scans/${scanId}/results`
    );

    if (!response.ok) {
      throw new Error("Could not load scan details");
    }

    const data = await response.json();
    setSelectedHistory(data);
  } catch (error) {
    setHistoryError(
      error instanceof Error ? error.message : "Could not open scan"
    );
  }
}
  const moduleResults = scanResult?.results?.results
    ? Object.entries(scanResult.results.results)
    : [];

  const successfulModules = moduleResults.filter(
    ([, result]) => result.status === "success"
  ).length;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">C</div>
          <div>
            <h2>
              CYBROT<span> OSINT</span>
            </h2>
            <small>WEBSITE INTELLIGENCE</small>
          </div>
        </div>

        <div className="side-label">WORKSPACE</div>

        <button
          className={`nav-item ${active === "Overview" ? "selected" : ""}`}
          onClick={() => setActive("Overview")}
        >
          ▦ <span>Overview</span>
        </button>

        <button
          className={`nav-item ${active === "New Scan" ? "selected" : ""}`}
          onClick={() => setActive("New Scan")}
        >
          ＋ <span>New Scan</span>
        </button>

        <div className="side-label">INTELLIGENCE MODULES</div>

        {modules.map(([icon, name]) => (
          <button
            key={name}
            className={`nav-item ${active === name ? "selected" : ""}`}
            onClick={() => setActive(name)}
          >
            {icon}
            <span>{name}</span>
          </button>
        ))}

        <div className="side-label">MANAGEMENT</div>

       {["Reports", "Scan History", "Settings"].map((name) => (
  <button
    key={name}
    className={`nav-item ${active === name ? "selected" : ""}`}
    onClick={() => {
      setActive(name);

      if (name === "Scan History") {
        setSelectedHistory(null);
        loadHistory();
      }
    }}
  >
    ◫ <span>{name}</span>
  </button>
))}

        <div className="sidebar-bottom">
          <div className="engine-status">
            <span className="status-dot" />
            Local engine <b>{connected ? "Online" : "Offline"}</b>
          </div>
          <small>CYBROT OSINT · v0.1.0</small>
        </div>
      </aside>

      <section className="main-area">
        <header className="topbar">
          <div>
            <div className="breadcrumb">
              CYBROT OSINT / <span>{active}</span>
            </div>
            <h1>{active}</h1>
          </div>

          <div className="top-right">
            <span className="environment">
              <span className="status-dot" />
              LOCAL ENVIRONMENT
            </span>
            <div className="avatar">C</div>
          </div>
        </header>

<div className="content">
        {active === "DNS Analysis" && (
          <section className="panel dns-page-panel">
            {scanResult?.results?.results?.dns_analysis?.data !== undefined ? (
              <DNSIntelligenceView data={scanResult.results.results.dns_analysis.data} />
            ) : (
              <div className="dns-empty-state">
                <span className="eyebrow">DNS INTELLIGENCE</span>
                <h3>No DNS results yet</h3>
                <p>Run a domain scan to view DNS records, SPF, DMARC, MX and DNSSEC observations here.</p>
                <button type="button" onClick={() => setActive("New Scan")}>Start a scan</button>
              </div>
            )}
          </section>
        )}
        {active === "Scan History" && (
  <section className="panel" style={{ marginTop: "22px" }}>
    <div className="panel-title">
      <h3>Saved Scan History</h3>

      <button onClick={loadHistory} disabled={historyLoading}>
        {historyLoading ? "Loading..." : "Refresh"}
      </button>
    </div>

    {historyError && <p className="notice">{historyError}</p>}

    {historyLoading ? (
      <p>Loading saved scans...</p>
    ) : history.length === 0 ? (
      <p>No saved scans found.</p>
    ) : (
      <div className="module-grid">
        
       {history.map((item) => (
  <div key={item.scan_id} className="module-card">
    <strong>Scan #{item.scan_id}</strong>

    <span>{item.domain}</span>

    <small>Status: {item.status.toUpperCase()}</small>

    <small>
      {new Date(item.created_at).toLocaleString()}
    </small>

    <div className="history-actions">
      <button type="button" onClick={() => openHistoryScan(item.scan_id)}>
        View Results
      </button>
      <button type="button" onClick={() => downloadReport(item.scan_id, "clean")}>
        Clean PDF
      </button>
      <button type="button" onClick={() => downloadReport(item.scan_id, "json")}>
        JSON PDF
      </button>
    </div>
  </div>
))}
              </div>
                   )}

    {selectedHistory !== null && (
  <div className="selected-scan-panel">
    <div className="selected-scan-header">
      <div>
        <span className="eyebrow">SCAN INFORMATION</span>
        <h3>Selected Scan Details</h3>
      </div>

      <button
        type="button"
        className="close-results-btn"
        onClick={() => setSelectedHistory(null)}
      >
        ✕ Close Results
      </button>
    </div>

    <div className="selected-scan-structured">
      <ScanResultsView value={selectedHistory} />
    </div>
  </div>
)}
  </section>
)}

          <div className="welcome">
            <div>
              <div className="eyebrow">WEBSITE INTELLIGENCE PLATFORM</div>
              <h2>
                See the bigger picture<span>.</span>
              </h2>
              <p>
                Discover, analyze and organize publicly available website
                intelligence.
              </p>
            </div>
            <div className="welcome-mark">C</div>
          </div>

          <section className="scan-panel">
            <div className="section-heading">
              <div>
                <span className="eyebrow">START INVESTIGATION</span>
                <h3>New Intelligence Scan</h3>
              </div>
              <span className="passive-tag">◉ PASSIVE COLLECTION</span>
            </div>

            <form className="scan-form" onSubmit={handleScan}>
              <span className="search-icon">⌕</span>

              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="Enter a domain (e.g. example.com)"
                aria-label="Domain name"
                disabled={scanning}
              />

              <button type="submit" disabled={scanning || !connected}>
                {scanning ? "Scanning..." : "Start Scan"}
                <span> →</span>
              </button>
            </form>

            {notice && <p className="notice">{notice}</p>}

            <p className="helper">
              Investigate publicly available domain intelligence.
              Scans use passive collection and non-intrusive HTTP/HTTPS checks.
            </p>
          </section>

          <div className="section-heading overview-heading">
            <div>
              <span className="eyebrow">YOUR WORKSPACE</span>
              <h3>Intelligence Overview</h3>
            </div>
            <span className="muted">
              {scanResult ? "Latest scan data" : "Waiting for first scan"}
            </span>
          </div>

          <div className="stats-grid">
            <Stat
              icon="⌕"
              label="Total Scans"
              value={scanResult ? "1" : "—"}
              detail={scanResult ? "This session" : "No scans this session"}
            />
            <Stat
              icon="◈"
              label="Domains Analyzed"
              value={scanResult ? "1" : "—"}
              detail={scanResult?.domain || "Awaiting engine"}
            />
            <Stat
              icon="⬡"
              label="Modules Successful"
              value={scanResult ? String(successfulModules) : "—"}
              detail={
                scanResult
                  ? `Of ${scanResult.results.total_modules} executed`
                  : "No results yet"
              }
            />
            <Stat
              icon="▤"
              label="Report Formats"
              value={scanResult ? "2" : "—"}
              detail={scanResult ? "Clean PDF and JSON PDF" : "Run a scan to enable reports"}
            />
          </div>

          {scanResult && (
            <section className="panel latest-results-panel" style={{ marginTop: "22px" }}>
              <div className="panel-title">
                <h3>Latest Scan Results</h3>
                <span>SCAN #{scanResult.scan_id}</span>
              </div>

              <div className="report-actions">
                <button type="button" onClick={() => downloadReport(scanResult.scan_id, "clean")}>
                  ↓ Download Clean PDF
                </button>
                <button type="button" className="secondary" onClick={() => downloadReport(scanResult.scan_id, "json")}>
                  ↓ Download JSON PDF
                </button>
              </div>

              <div className="scan-summary-line">
                <span className="scan-summary-domain">
                  <strong>Domain:</strong>
                  <span>{scanResult.domain}</span>
                </span>
                <span className={`scan-status status-${scanResult.status.toLowerCase()}`}>
                  {scanResult.status.toUpperCase()}
                </span>
              </div>

              <div className="module-results-grid">
                {moduleResults.map(([key, result]) => {
                  const label = moduleLabels[key] || key;
                  const statusLabel =
                    result.status === "not_configured"
                      ? "NOT CONFIGURED"
                      : result.status.toUpperCase();
                  const statusClass = result.status
                    .toLowerCase()
                    .replace(/[^a-z0-9_-]/g, "-");

                  return (
                    <details className="module-result-card" key={key}>
                      <summary>
                        <span className="module-result-title">{label}</span>
                        <span className={`module-status status-${statusClass}`}>
                          {statusLabel}
                        </span>
                        <span className="module-expand-hint">View details ⌄</span>
                      </summary>

                      <div className="module-result-content">
                        {result.error && (
                          <div className="module-error">{result.error}</div>
                        )}
                        {result.data !== undefined ? (
                          key === "dns_analysis" ? <DNSIntelligenceView data={result.data} /> : <StructuredData value={result.data} />
                        ) : (
                          <p className="data-empty">No structured data was returned by this module.</p>
                        )}
                      </div>
                    </details>
                  );
                })}
              </div>
            </section>
          )}

          <div className="lower-grid">
            <section className="panel modules-panel">
              <div className="panel-title">
                <h3>Intelligence Modules</h3>
                <span>10 MODULES</span>
              </div>

              <div className="module-grid">
                {modules.map(([icon, name]) => (
                  <button
                    key={name}
                    className="module-card"
                    onClick={() => setActive(name)}
                  >
                    <span className="module-icon">{icon}</span>
                    <span>{name}</span>
                    <small>
                      {name === "Threat Intelligence"
                        ? "Not implemented"
                        : "Backend module available"}
                    </small>
                  </button>
                ))}
              </div>
            </section>

            <section className="panel recent-panel">
              <div className="panel-title">
                <h3>Recent Activity</h3>
                <span>HISTORY</span>
              </div>

              {scanResult ? (
                <div className="empty-state">
                  <div className="empty-icon">◷</div>
                  <strong>Latest scan completed</strong>
                  <p>
                    {scanResult.domain} · Scan #{scanResult.scan_id}
                  </p>
                  <p>Status: {scanResult.status}</p>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">◷</div>
                  <strong>No activity in this session</strong>
                  <p>Your latest scan activity will appear here.</p>
                </div>
              )}

              <div className="engine-card">
                <span className="status-dot" />
                <div>
                  <strong>Local Engine</strong>
                  <small>
                    {connected
                      ? "FastAPI connection active"
                      : "Waiting for Python API connection"}
                  </small>
                </div>
                <span className="offline">
                  {connected ? "ONLINE" : "OFFLINE"}
                </span>
              </div>
            </section>
          </div>

          <footer>
            CYBROT OSINT <span>·</span> Built for responsible security research
          </footer>
        </div>
      </section>
    </main>
  );
}

function humanizeKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}



function DNSIntelligenceView({ data }: { data: unknown }) {
  const root = isPlainObject(data) ? data : {};
  const records = isPlainObject(root.records) ? root.records : {};
  const email = isPlainObject(root.email_security) ? root.email_security : {};
  const spf = isPlainObject(email.SPF) ? email.SPF : {};
  const dmarc = isPlainObject(email.DMARC) ? email.DMARC : {};
  const dnssec = isPlainObject(root.dnssec) ? root.dnssec : {};
  const mx = isPlainObject(root.mail_server_intelligence)
    ? root.mail_server_intelligence
    : {};
  const ns = isPlainObject(root.nameserver_intelligence)
    ? root.nameserver_intelligence
    : {};

  const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"];
  const getText = (value: unknown, fallback = "Not available") =>
    typeof value === "string" || typeof value === "number"
      ? String(value)
      : fallback;
  const getArray = (value: unknown): unknown[] =>
    Array.isArray(value) ? value : [];
  const policyColor = (value: unknown) => {
    const policy = getText(value, "").toLowerCase();
    if (policy === "reject" || policy === "configured" || policy === "records_observed") return "good";
    if (policy === "quarantine" || policy === "null_mx") return "warn";
    if (policy === "none" || policy === "not_found" || policy === "no_records_observed") return "muted";
    return "neutral";
  };

  return (
    <div className="dns-intelligence">
      <div className="dns-intel-heading">
        <div>
          <span className="eyebrow">DOMAIN RECORDS & SECURITY</span>
          <h3>DNS Intelligence</h3>
          <p>DNS records, mail configuration and DNSSEC observations.</p>
        </div>
        <span className="dns-domain-pill">{getText(root.domain)}</span>
      </div>

      <div className="dns-security-grid">
        <div className="dns-security-card">
          <span className="dns-card-label">SPF POLICY</span>
          <strong className={`dns-state ${policyColor(spf.status)}`}>
            {getText(spf.status, "Unknown").replaceAll("_", " ").toUpperCase()}
          </strong>
          <code>{getText(spf.policy, "No SPF policy found")}</code>
          {getArray(spf.warnings).map((warning, index) => (
            <small className="dns-warning" key={index}>{getText(warning)}</small>
          ))}
        </div>

        <div className="dns-security-card">
          <span className="dns-card-label">DMARC POLICY</span>
          <strong className={`dns-state ${policyColor(dmarc.policy || dmarc.status)}`}>
            {getText(dmarc.policy || dmarc.status, "Unknown").toUpperCase()}
          </strong>
          <code>{getArray(dmarc.records).length ? getText(getArray(dmarc.records)[0]) : "No DMARC record found"}</code>
          {getArray(dmarc.warnings).map((warning, index) => (
            <small className="dns-warning" key={index}>{getText(warning)}</small>
          ))}
        </div>

        <div className="dns-security-card">
          <span className="dns-card-label">DNSSEC OBSERVATION</span>
          <strong className={`dns-state ${policyColor(dnssec.status)}`}>
            {getText(dnssec.status, "Unknown").replaceAll("_", " ").toUpperCase()}
          </strong>
          <small>DNSKEY: {getText(dnssec.dnskey_lookup)}</small>
          <small>DS: {getText(dnssec.ds_lookup)}</small>
          <small className="dns-warning">Record presence alone does not prove a valid DNSSEC chain.</small>
        </div>

        <div className="dns-security-card">
          <span className="dns-card-label">MAIL CONFIGURATION</span>
          <strong className={`dns-state ${mx.accepts_email === true ? "good" : mx.status === "null_mx" ? "warn" : "neutral"}`}>
            {mx.accepts_email === true ? "MAIL ENABLED" : mx.status === "null_mx" ? "NULL MX" : getText(mx.status, "UNKNOWN").toUpperCase()}
          </strong>
          <small>{mx.accepts_email === true ? "Mail exchangers are configured." : mx.status === "null_mx" ? "This domain explicitly indicates it does not accept email." : "Mail acceptance could not be confirmed."}</small>
          <small>{getText(mx.total_mail_servers, "0")} mail server(s)</small>
        </div>
      </div>

      <div className="dns-records-heading">
        <div>
          <h4>DNS Record Inventory</h4>
          <span>{getText(root.source, "DNS")} · {getText(root.collected_at, "Timestamp unavailable")}</span>
        </div>
        <span>{recordTypes.length} record types</span>
      </div>

      <div className="dns-record-grid">
        {recordTypes.map((type) => {
          const items = getArray(records[type]);
          return (
            <section className="dns-record-card" key={type}>
              <div className="dns-record-card-head">
                <strong>{type}</strong>
                <span>{items.length} {items.length === 1 ? "record" : "records"}</span>
              </div>
              {items.length ? (
                <div className="dns-record-values">
                  <StructuredData value={items} />
                </div>
              ) : (
                <p className="data-empty">No records returned</p>
              )}
            </section>
          );
        })}
      </div>

      <div className="dns-secondary-grid">
        <section className="dns-record-card">
          <div className="dns-record-card-head">
            <strong>Nameserver Intelligence</strong>
            <span>{getText(ns.total_nameservers, "0")} found</span>
          </div>
          <StructuredData value={getArray(ns.nameservers)} />
        </section>
        <section className="dns-record-card">
          <div className="dns-record-card-head">
            <strong>DNS Query Status</strong>
            <span>{isPlainObject(root.record_status) ? Object.keys(root.record_status).length : 0} queries</span>
          </div>
          <StructuredData value={root.record_status ?? {}} />
        </section>
      </div>
    </div>
  );
}

function ScanResultsView({ value }: { value: unknown }) {
  if (!isPlainObject(value)) return <StructuredData value={value} />;

  const scan = value;
  const scanResults = isPlainObject(scan.results) ? scan.results : {};
  const moduleObject = isPlainObject(scanResults.results) ? scanResults.results : {};
  const entries = Object.entries(moduleObject);
  const domain = typeof scan.domain === "string"
    ? scan.domain
    : typeof scanResults.domain === "string" ? scanResults.domain : "Unknown domain";
  const status = typeof scan.status === "string"
    ? scan.status
    : typeof scanResults.status === "string" ? scanResults.status : "unknown";
  const total = typeof scanResults.total_modules === "number" ? scanResults.total_modules : entries.length;
  const successful = typeof scanResults.successful_modules === "number"
    ? scanResults.successful_modules
    : entries.filter(([, item]) => isPlainObject(item) && item.status === "success").length;

  return (
    <div className="scan-results-view">
      <div className="scan-overview-grid">
        <div className="scan-overview-card"><small>Domain:</small><strong>{domain}</strong></div>
        <div className="scan-overview-card"><small>Scan Status:</small><strong>{status.toUpperCase()}</strong></div>
        <div className="scan-overview-card"><small>Modules Successful:</small><strong>{successful} / {total}</strong></div>
        <div className="scan-overview-card"><small>Scan ID:</small><strong>{scan.scan_id !== undefined ? String(scan.scan_id) : "Not available"}</strong></div>
      </div>
      <div className="panel-title module-section-heading">
        <h3>Module Analysis</h3><span>{entries.length} MODULES</span>
      </div>
      {entries.length === 0 ? <p className="data-empty">No individual module results were found.</p> : (
        <div className="module-results-grid">
          {entries.map(([key, raw]) => {
            const result = isPlainObject(raw) ? raw : {};
            const moduleStatus = typeof result.status === "string" ? result.status : "unknown";
            const statusClass = moduleStatus.toLowerCase().replace(/[^a-z0-9_-]/g, "-");
            return (
              <details className="module-result-card" key={key}>
                <summary>
                  <span className="module-result-title">{moduleLabels[key] || humanizeKey(key)}</span>
                  <span className={`module-status status-${statusClass}`}>{moduleStatus.replaceAll("_", " ").toUpperCase()}</span>
                  <span className="module-expand-hint">View details ⌄</span>
                </summary>
                <div className="module-result-content">
                  {typeof result.error === "string" && <div className="module-error">{result.error}</div>}
                  {result.data !== undefined ? key === "dns_analysis" ? <DNSIntelligenceView data={result.data} /> : <StructuredData value={result.data} /> : <p className="data-empty">No structured data was returned by this module.</p>}
                </div>
              </details>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StructuredData({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || value === undefined) {
    return <span className="data-null">Not provided</span>;
  }

  if (typeof value === "boolean") {
    return (
      <span className={`data-boolean ${value ? "is-true" : "is-false"}`}>
        {value ? "Yes" : "No"}
      </span>
    );
  }

  if (typeof value === "string" || typeof value === "number") {
    return <span className="data-scalar">{String(value)}</span>;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="data-null">No records</span>;
    }

    const primitiveArray = value.every(
      (item) =>
        item === null ||
        ["string", "number", "boolean"].includes(typeof item)
    );

    if (primitiveArray) {
      return (
        <div className="data-chip-list">
          {value.map((item, index) => (
            <span className="data-chip" key={`${String(item)}-${index}`}>
              {item === null ? "null" : String(item)}
            </span>
          ))}
        </div>
      );
    }

    return (
      <div className="data-array-list">
        {value.map((item, index) => (
          <div className="data-array-item" key={index}>
            <StructuredData value={item} depth={depth + 1} />
          </div>
        ))}
      </div>
    );
  }

  if (isPlainObject(value)) {
    const entries = Object.entries(value);

    if (entries.length === 0) {
      return <span className="data-null">No details available</span>;
    }

    if (depth >= 4) {
      return (
        <pre className="data-fallback">
          {JSON.stringify(value, null, 2)}
        </pre>
      );
    }

    return (
      <div className={`structured-data depth-${Math.min(depth, 3)}`}>
        {entries.map(([key, item]) => (
          <div className="data-field" key={key}>
            <div className="data-field-label">{humanizeKey(key)}:</div>
            <div className="data-field-value">
              <StructuredData value={item} depth={depth + 1} />
            </div>
          </div>
        ))}
      </div>
    );
  }

  return <span className="data-scalar">{String(value)}</span>;
}

function Stat({
  icon,
  label,
  value,
  detail,
}: {
  icon: string;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span>{label}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}
