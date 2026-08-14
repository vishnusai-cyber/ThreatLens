import { useEffect, useState } from "react";

import {
  correlateIP,
  getIntelligenceHistory,
} from "../api";

import "../index.css";

// ==========================================================
// ThreatLens - Threat Intelligence
// ==========================================================

function ThreatIntelligence() {
  // ========================================================
  // State
  // ========================================================

  const [ip, setIP] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // ========================================================
  // IPv4 Validation
  // ========================================================

  function isValidIPv4(value) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return ipv4Regex.test(value.trim());
  }

  // ========================================================
  // Load Intelligence History
  // ========================================================

  async function loadHistory() {
    try {
      setHistoryLoading(true);

      const data = await getIntelligenceHistory(10, 0);

      if (Array.isArray(data)) {
        setHistory(data);
      } else {
        setHistory(
          data?.data ||
            data?.items ||
            data?.results ||
            []
        );
      }
    } catch (err) {
      console.error(
        "Intelligence history error:",
        err
      );
    } finally {
      setHistoryLoading(false);
    }
  }

  // ========================================================
  // Initial Load
  // ========================================================

  useEffect(() => {
    loadHistory();
  }, []);

  // ========================================================
  // Threat Score Extraction
  // ========================================================

  function getThreatScore(data) {
    if (!data) {
      return 0;
    }

    const candidates = [
      data.threat_score,
      data.score,
      data.threatScore,
      data.threatlens_score,
      data.threatlensScore,
      data?.threatlens?.score,
      data?.correlation?.score,
      data?.data?.threat_score,
      data?.data?.score,
    ];

    for (const value of candidates) {
      const number = Number(value);

      if (
        Number.isFinite(number) &&
        number >= 0
      ) {
        return Math.round(number);
      }
    }

    return 0;
  }

  // ========================================================
  // Severity Extraction
  // ========================================================

  function getSeverity(data, score) {
    if (!data) {
      return "unknown";
    }

    const candidates = [
      data.severity,
      data.risk_level,
      data.riskLevel,
      data.threat_level,
      data.threatLevel,
      data?.threatlens?.severity,
      data?.correlation?.severity,
      data?.data?.severity,
    ];

    for (const value of candidates) {
      if (value) {
        return String(value).toLowerCase();
      }
    }

    if (score >= 80) {
      return "critical";
    }

    if (score >= 60) {
      return "high";
    }

    if (score >= 30) {
      return "medium";
    }

    return "low";
  }

  // ========================================================
  // Format Severity
  // ========================================================

  function formatSeverity(value) {
    if (!value) {
      return "Unknown";
    }

    const text = String(value);

    return (
      text.charAt(0).toUpperCase() +
      text.slice(1).toLowerCase()
    );
  }

  // ========================================================
  // Source Extraction
  // ========================================================

  function getSourceData(data, source) {
    if (!data) {
      return null;
    }

    const lower = source.toLowerCase();

    const possibleSources = [
      data?.sources,
      data?.correlation,
      data?.data,
    ];

    for (const container of possibleSources) {
      if (!container) {
        continue;
      }

      if (container[source]) {
        return container[source];
      }

      if (container[lower]) {
        return container[lower];
      }

      const key = Object.keys(container).find(
        (item) =>
          String(item).toLowerCase() === lower
      );

      if (key) {
        return container[key];
      }
    }

    return null;
  }

  // ========================================================
  // Source Status
  // ========================================================

  function getSourceStatus(data, source) {
    const sourceData = getSourceData(
      data,
      source
    );

    if (sourceData !== null) {
      return "Success";
    }

    return "Checked";
  }

  // ========================================================
  // Scan IP
  // ========================================================

  async function handleScan(event) {
    event.preventDefault();

    const targetIP = ip.trim();

    // ------------------------------------------------------
    // Validation
    // ------------------------------------------------------

    if (!targetIP) {
      setError("Please enter an IP address.");
      return;
    }

    if (!isValidIPv4(targetIP)) {
      setError(
        "Please enter a valid IPv4 address. Example: 8.8.8.8"
      );
      return;
    }

    // ------------------------------------------------------
    // Start scan
    // ------------------------------------------------------

    try {
      setLoading(true);
      setError("");
      setResult(null);

      console.log(
        "Starting ThreatLens scan:",
        targetIP
      );

      // ----------------------------------------------------
      // Correlation Engine
      // ----------------------------------------------------

      const correlationResult =
        await correlateIP(targetIP);

      console.log(
        "Correlation Engine result:",
        correlationResult
      );

      setResult({
        ...correlationResult,
        analyzed_ip: targetIP,
      });

      // ----------------------------------------------------
      // Refresh history
      // ----------------------------------------------------

      await loadHistory();
    } catch (err) {
      console.error(
        "Threat intelligence scan failed:",
        err
      );

      setError(
        err?.message ||
          "Threat intelligence scan failed."
      );
    } finally {
      setLoading(false);
    }
  }

  // ========================================================
  // Reset Scan
  // ========================================================

  function resetScan() {
    setResult(null);
    setError("");
  }

  // ========================================================
  // Extract Result Information
  // ========================================================

  const score = getThreatScore(result);

  const severity = getSeverity(
    result,
    score
  );

  const analyzedIP =
    result?.analyzed_ip ||
    result?.ip_address ||
    result?.ip ||
    ip;

  // ========================================================
  // Source Data
  // ========================================================

  const virusTotal = getSourceData(
    result,
    "VirusTotal"
  );

  const abuseIPDB = getSourceData(
    result,
    "AbuseIPDB"
  );

  const otx = getSourceData(
    result,
    "OTX"
  );

  // ========================================================
  // Render
  // ========================================================

  return (
    <section className="dashboard">

      {/* ==================================================
          PAGE HEADER
      ================================================== */}

      <div className="page-heading">

        <div>

          <span className="modal-label">
            THREAT INTELLIGENCE
          </span>

          <h3>
            Threat Intelligence
          </h3>

          <p>
            Analyze IP addresses using
            multiple threat intelligence
            sources and the ThreatLens
            correlation engine.
          </p>

        </div>

      </div>

      {/* ==================================================
          SCAN PANEL
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <h4>
              New Threat Scan
            </h4>

            <p>
              Enter an IPv4 address to
              perform multi-source threat
              correlation.
            </p>

          </div>

        </div>

        <form
          className="scan-form"
          onSubmit={handleScan}
        >

          <label htmlFor="threat-ip">
            IP Address
          </label>

          <div
            style={{
              display: "flex",
              gap: "12px",
              alignItems: "stretch",
            }}
          >

            <input
              id="threat-ip"
              type="text"
              value={ip}
              onChange={(event) => {
                setIP(event.target.value);
                setError("");
              }}
              placeholder="8.8.8.8"
              autoComplete="off"
              spellCheck="false"
              disabled={loading}
              style={{
                flex: 1,
              }}
            />

            <button
              type="submit"
              className="primary-button"
              disabled={loading}
            >
              {loading
                ? "Analyzing..."
                : "Analyze IP"}
            </button>

          </div>

          <span className="input-hint">
            Example: 8.8.8.8
          </span>

          {error && (
            <div className="scan-error">
              {error}
            </div>
          )}

        </form>

      </div>

      {/* ==================================================
          LOADING
      ================================================== */}

      {loading && (

        <div className="panel">

          <div className="scan-progress">

            <div className="spinner" />

            <strong>
              Running Correlation Engine...
            </strong>

            <span>
              Querying VirusTotal,
              AbuseIPDB and AlienVault
              OTX.
            </span>

          </div>

        </div>

      )}

      {/* ==================================================
          RESULT
      ================================================== */}

      {!loading && result && (

        <div className="panel">

          <div className="panel-header">

            <div>

              <h4>
                Threat Analysis Result
              </h4>

              <p>
                Correlation analysis completed
                successfully.
              </p>

            </div>

            <button
              className="secondary-button"
              onClick={resetScan}
            >
              Scan Another IP
            </button>

          </div>

          {/* ==================================================
              SCORE
          ================================================== */}

          <div className="score-card">

            <div>

              <span>
                THREATLENS SCORE
              </span>

              <strong>
                {score}
              </strong>

            </div>

            <span
              className={`score-severity ${severity}`}
            >
              {formatSeverity(severity)}
            </span>

          </div>

          {/* ==================================================
              IP
          ================================================== */}

          <div className="result-ip">

            <span>
              ANALYZED IP ADDRESS
            </span>

            <strong>
              {analyzedIP}
            </strong>

          </div>

          {/* ==================================================
              INTELLIGENCE SOURCES
          ================================================== */}

          <div className="source-grid">

            {/* VirusTotal */}

            <div className="source-card">

              <div className="source-icon">
                VT
              </div>

              <div>

                <strong>
                  VirusTotal
                </strong>

                <small>
                  IP reputation
                </small>

              </div>

              <span
                className={`source-status ${
                  getSourceStatus(
                    result,
                    "VirusTotal"
                  ) === "Success"
                    ? "success"
                    : "warning"
                }`}
              >
                {getSourceStatus(
                  result,
                  "VirusTotal"
                )}
              </span>

            </div>

            {/* AbuseIPDB */}

            <div className="source-card">

              <div className="source-icon">
                AIP
              </div>

              <div>

                <strong>
                  AbuseIPDB
                </strong>

                <small>
                  Abuse reputation
                </small>

              </div>

              <span
                className={`source-status ${
                  getSourceStatus(
                    result,
                    "AbuseIPDB"
                  ) === "Success"
                    ? "success"
                    : "warning"
                }`}
              >
                {getSourceStatus(
                  result,
                  "AbuseIPDB"
                )}
              </span>

            </div>

            {/* AlienVault OTX */}

            <div className="source-card">

              <div className="source-icon">
                OTX
              </div>

              <div>

                <strong>
                  AlienVault OTX
                </strong>

                <small>
                  Threat intelligence
                </small>

              </div>

              <span
                className={`source-status ${
                  getSourceStatus(
                    result,
                    "OTX"
                  ) === "Success"
                    ? "success"
                    : "warning"
                }`}
              >
                {getSourceStatus(
                  result,
                  "OTX"
                )}
              </span>

            </div>

          </div>

          {/* ==================================================
              SOURCE DETAILS
          ================================================== */}

          <div
            className="dashboard-grid"
            style={{
              marginTop: "20px",
            }}
          >

            {/* VirusTotal */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    VirusTotal
                  </h4>

                  <p>
                    Reputation analysis
                  </p>

                </div>

              </div>

              <div className="chart-message">

                {virusTotal ? (

                  <pre
                    style={{
                      whiteSpace:
                        "pre-wrap",
                      wordBreak:
                        "break-word",
                      fontSize:
                        "12px",
                    }}
                  >
                    {JSON.stringify(
                      virusTotal,
                      null,
                      2
                    )}
                  </pre>

                ) : (

                  "VirusTotal data included in correlation response."

                )}

              </div>

            </div>

            {/* AbuseIPDB */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    AbuseIPDB
                  </h4>

                  <p>
                    Abuse reputation
                  </p>

                </div>

              </div>

              <div className="chart-message">

                {abuseIPDB ? (

                  <pre
                    style={{
                      whiteSpace:
                        "pre-wrap",
                      wordBreak:
                        "break-word",
                      fontSize:
                        "12px",
                    }}
                  >
                    {JSON.stringify(
                      abuseIPDB,
                      null,
                      2
                    )}
                  </pre>

                ) : (

                  "AbuseIPDB data included in correlation response."

                )}

              </div>

            </div>

            {/* OTX */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    AlienVault OTX
                  </h4>

                  <p>
                    Threat intelligence
                  </p>

                </div>

              </div>

              <div className="chart-message">

                {otx ? (

                  <pre
                    style={{
                      whiteSpace:
                        "pre-wrap",
                      wordBreak:
                        "break-word",
                      fontSize:
                        "12px",
                    }}
                  >
                    {JSON.stringify(
                      otx,
                      null,
                      2
                    )}
                  </pre>

                ) : (

                  "OTX data included in correlation response."

                )}

              </div>

            </div>

          </div>

        </div>

      )}

      {/* ==================================================
          INTELLIGENCE HISTORY
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <h4>
              Intelligence History
            </h4>

            <p>
              Recent threat intelligence
              lookups.
            </p>

          </div>

          <button
            className="secondary-button"
            onClick={loadHistory}
            disabled={historyLoading}
          >
            {historyLoading
              ? "Loading..."
              : "↻ Refresh"}
          </button>

        </div>

        {historyLoading ? (

          <div className="chart-message">
            Loading intelligence history...
          </div>

        ) : history.length === 0 ? (

          <div className="chart-message">
            No intelligence lookups found.
          </div>

        ) : (

          <div className="ip-list">

            {history.map(
              (item, index) => {

                const historyIP =
                  item?.ip_address ||
                  item?.ip ||
                  "Unknown IP";

                const source =
                  item?.source ||
                  item?.provider ||
                  "Unknown";

                const historyScore =
                  Number(
                    item?.threat_score ??
                      item?.score ??
                      0
                  );

                let risk = "low";

                if (
                  historyScore >= 80
                ) {
                  risk = "critical";
                } else if (
                  historyScore >= 60
                ) {
                  risk = "high";
                } else if (
                  historyScore >= 30
                ) {
                  risk = "medium";
                }

                return (
                  <div
                    className="ip-row"
                    key={
                      item?.id ||
                      `${historyIP}-${source}-${index}`
                    }
                  >

                    <div>

                      <strong>
                        {historyIP}
                      </strong>

                      <small>
                        Source: {source}
                      </small>

                    </div>

                    <div
                      style={{
                        display: "flex",
                        alignItems:
                          "center",
                        gap: "12px",
                      }}
                    >

                      <small>
                        Score:{" "}
                        {historyScore}
                      </small>

                      <span
                        className={`risk ${risk}`}
                      >
                        {formatSeverity(
                          risk
                        )}
                      </span>

                    </div>

                  </div>
                );
              }
            )}

          </div>

        )}

      </div>

    </section>
  );
}

export default ThreatIntelligence;