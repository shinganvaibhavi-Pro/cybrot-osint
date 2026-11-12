"use client";

import { useEffect, useState, type FormEvent } from "react";

const API_BASE = "http://127.0.0.1:8000";

const modules = [
  ["⌕", "Domain Intelligence"],
  ["◈", "DNS Analysis"],
  ["⌘", "Subdomain Discovery"],
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
          authorized: true,
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
async function downloadReport(scanId: number) {
  try {
    setHistoryError("");

    const response = await fetch(
      `${API_BASE}/api/v1/scans/${scanId}/report`
    );

    if (!response.ok) {
      throw new Error("Could not download PDF report");
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = `cybrot_scan_${scanId}.pdf`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => {
      window.URL.revokeObjectURL(url);
    }, 1000);
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

    <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
      <button
        type="button"
        onClick={() => openHistoryScan(item.scan_id)}
      >
        View Results
      </button>

      <button
        type="button"
        onClick={() => downloadReport(item.scan_id)}
      >
        Download PDF
      </button>
    </div>
  </div>
))}
              </div>
                   )}

    {selectedHistory !== null && (
      <div style={{ marginTop: "20px" }}>
        <h3>Selected Scan Details</h3>
        <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
          {JSON.stringify(selectedHistory, null, 2)}
        </pre>
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
              Only investigate domains you own or are authorized to assess.
              Scans use passive collection modules.
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
              label="Reports Generated"
              value="—"
              detail="Report export not connected"
            />
          </div>

          {scanResult && (
            <section className="panel" style={{ marginTop: "22px" }}>
              <div className="panel-title">
                <h3>Latest Scan Results</h3>
                <span>SCAN #{scanResult.scan_id}</span>
              </div>

              <p>
                **Domain:** {scanResult.domain} · **Status:**{" "}
                {scanResult.status.toUpperCase()}
              </p>

              <div className="module-grid">
                {moduleResults.map(([key, result]) => {
                  const label = moduleLabels[key] || key;

                  return (
                    <div className="module-card" key={key}>
                      <span>{label}</span>
                      <small>
                        {result.status === "success"
    ? "SUCCESS"
    : result.status === "not_configured"
    ? "NOT CONFIGURED"
    : result.status === "unavailable"
    ? "UNAVAILABLE"
    : result.status === "partial"
    ? "PARTIAL"
    : "FAILED"}
                          
                      </small>
                      {result.error && (
                        <small>{result.error}</small>
                      )}
                      {result.data !== undefined && (
                        <small>
                          {JSON.stringify(result.data).slice(0, 180)}
                          {JSON.stringify(result.data).length > 180
                            ? "..."
                            : ""}
                        </small>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          <div className="lower-grid">
            <section className="panel modules-panel">
              <div className="panel-title">
                <h3>Intelligence Modules</h3>
                <span>09 MODULES</span>
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
