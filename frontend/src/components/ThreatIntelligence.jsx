import { useEffect, useMemo, useState } from "react";

import {
  correlateIP,
  getIntelligenceHistory,
} from "../api";

import "../index.css";

// ==========================================================
// ThreatLens — Threat Intelligence
// Premium SOC Intelligence Workspace
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
  // Threat Score
  // ========================================================

  function getThreatScore(data) {
    if (!data) {
      return 0;
    }

    const score = Number(
      data.threatlens_score
    );

    if (
      Number.isFinite(score) &&
      score >= 0
    ) {
      return Math.round(score);
    }

    return 0;
  }

  // ========================================================
  // Severity
  // ========================================================

  function getSeverity(data, score) {
    if (data?.severity) {
      return String(
        data.severity
      ).toLowerCase();
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
  // Scan IP
  // ========================================================

  async function handleScan(event) {
    event.preventDefault();

    const targetIP = ip.trim();

    // ------------------------------------------------------
    // Validation
    // ------------------------------------------------------

    if (!targetIP) {
      setError(
        "Please enter an IP address."
      );
      return;
    }

    if (!isValidIPv4(targetIP)) {
      setError(
        "Please enter a valid IPv4 address. Example: 8.8.8.8"
      );
      return;
    }

    // ------------------------------------------------------
    // Start Scan
    // ------------------------------------------------------

    try {
      setLoading(true);
      setError("");
      setResult(null);

      console.log(
        "[ThreatLens] Starting correlation:",
        targetIP
      );

      const correlationResult =
        await correlateIP(targetIP);

      console.log(
        "[ThreatLens] Correlation result:",
        correlationResult
      );

      setResult(correlationResult);

      // Refresh history after successful scan
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
    setIP("");
  }

  // ========================================================
  // Result Information
  // ========================================================

  const score = getThreatScore(result);

  const severity = getSeverity(
    result,
    score
  );

  const analyzedIP =
    result?.ip || ip;

  // ========================================================
  // Exact Backend Source Data
  // ========================================================

  const virusTotal =
    result?.sources?.virustotal || null;

  const abuseIPDB =
    result?.sources?.abuseipdb || null;

  const otx =
    result?.sources?.otx || null;

  // ========================================================
  // Source Configuration
  // ========================================================

  const sourceCards = useMemo(
    () => [
      {
        key: "virustotal",
        short: "VT",
        name: "VirusTotal",
        description: "IP reputation",
        data: virusTotal,
      },
      {
        key: "abuseipdb",
        short: "AIP",
        name: "AbuseIPDB",
        description: "Abuse reputation",
        data: abuseIPDB,
      },
      {
        key: "otx",
        short: "OTX",
        name: "AlienVault OTX",
        description: "Threat intelligence",
        data: otx,
      },
    ],
    [virusTotal, abuseIPDB, otx]
  );

  // ========================================================
  // History Risk
  // ========================================================

  function getHistoryRisk(score) {
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
  // Render
  // ========================================================

  return (
    <section className="dashboard threat-intelligence-page">

      {/* ==================================================
          PAGE HEADER
      ================================================== */}

      <div className="page-heading threat-intel-heading">

        <div>
          <span className="modal-label">
            THREAT INTELLIGENCE
          </span>

          <h3>
            Threat Intelligence
          </h3>

          <p>
            Analyze IP addresses across
            multiple intelligence providers
            using the ThreatLens correlation
            engine.
          </p>
        </div>

        {result && (
          <div className="intel-heading-status">
            <span className="status-dot" />
            Analysis Complete
          </div>
        )}

      </div>

      {/* ==================================================
          SCAN PANEL
      ================================================== */}

      <div className="panel threat-scan-panel">

        <div className="panel-header">

          <div>
            <div className="panel-kicker">
              CORRELATION ENGINE
            </div>

            <h4>
              New Threat Scan
            </h4>

            <p>
              Enter an IPv4 address to perform
              multi-source threat correlation.
            </p>
          </div>

          <div className="scan-engine-status">
            <span className="status-dot" />
            Engine Ready
          </div>

        </div>

        <form
          className="scan-form"
          onSubmit={handleScan}
        >

          <label htmlFor="threat-ip">
            IP Address
          </label>

          <div className="scan-input-row">

            <div className="scan-input-wrapper">

              <span className="scan-input-prefix">
                IP
              </span>

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
              />

            </div>

            <button
              type="submit"
              className="primary-button scan-button"
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="button-spinner" />
                  Analyzing
                </>
              ) : (
                <>
                  Analyze IP
                  <span className="button-arrow">
                    →
                  </span>
                </>
              )}
            </button>

          </div>

          <div className="scan-form-footer">

            <span className="input-hint">
              Example: 8.8.8.8
            </span>

            <span className="scan-provider-hint">
              VT · AbuseIPDB · OTX
            </span>

          </div>

          {error && (
            <div className="scan-error">
              <span>!</span>
              {error}
            </div>
          )}

        </form>

      </div>

      {/* ==================================================
          LOADING
      ================================================== */}

      {loading && (
        <div className="panel scan-loading-panel">

          <div className="scan-progress">

            <div className="scan-loader-ring">
              <div className="spinner" />
            </div>

            <div className="scan-progress-content">

              <strong>
                Running Correlation Engine
              </strong>

              <span>
                Querying VirusTotal,
                AbuseIPDB and AlienVault OTX.
              </span>

            </div>

            <div className="scan-progress-indicator">
              LIVE
            </div>

          </div>

          <div className="scan-loading-line">
            <span />
          </div>

        </div>
      )}

      {/* ==================================================
          RESULT
      ================================================== */}

      {!loading && result && (
        <div className="threat-result-container">

          {/* ==================================================
              RESULT HEADER
          ================================================== */}

          <div className="panel result-panel">

            <div className="panel-header">

              <div>
                <div className="panel-kicker">
                  ANALYSIS COMPLETE
                </div>

                <h4>
                  Threat Analysis Result
                </h4>

                <p>
                  Correlation analysis completed
                  successfully across all available
                  intelligence sources.
                </p>
              </div>

              <button
                className="secondary-button"
                onClick={resetScan}
              >
                + Scan Another IP
              </button>

            </div>

            {/* ==================================================
                SCORE
            ================================================== */}

            <div
              className={`score-card score-card-${severity}`}
            >

              <div className="score-main">

                <span className="score-label">
                  THREATLENS SCORE
                </span>

                <strong>
                  {score}
                  <small>/100</small>
                </strong>

                <span className="score-description">
                  Correlated threat risk assessment
                </span>

              </div>

              <div className="score-severity-wrapper">

                <span className="score-severity-label">
                  RISK LEVEL
                </span>

                <span
                  className={`score-severity ${severity}`}
                >
                  <span className="severity-dot" />
                  {formatSeverity(severity)}
                </span>

              </div>

            </div>

            {/* ==================================================
                ANALYZED IP
            ================================================== */}

            <div className="result-ip">

              <div className="result-ip-label">
                ANALYZED IP ADDRESS
              </div>

              <div className="result-ip-value">

                <span className="ip-address-icon">
                  ⌁
                </span>

                <strong>
                  {analyzedIP}
                </strong>

              </div>

            </div>

            {/* ==================================================
                RECOMMENDATION
            ================================================== */}

            {result?.recommendation && (
              <div className="result-recommendation">

                <div className="result-recommendation-label">
                  RECOMMENDATION
                </div>

                <div className="result-recommendation-text">
                  {result.recommendation}
                </div>

              </div>
            )}

            {/* ==================================================
                ALERT STATUS
            ================================================== */}

            {result?.alert_created && (
              <div className="result-alert-status">

                <span className="status-dot" />

                <div>
                  <strong>
                    Security Alert Created
                  </strong>

                  {result.alert_id && (
                    <span>
                      Alert ID #{result.alert_id}
                    </span>
                  )}
                </div>

              </div>
            )}

            {/* ==================================================
                INTELLIGENCE SOURCES
            ================================================== */}

            <div className="source-section">

              <div className="source-section-header">

                <div>
                  <strong>
                    Intelligence Sources
                  </strong>

                  <span>
                    Multi-source correlation status
                  </span>
                </div>

                <span className="source-count">
                  3 PROVIDERS
                </span>

              </div>

              <div className="source-grid">

                {sourceCards.map((source) => {

                  const success =
                    source.data !== null;

                  return (
                    <div
                      className="source-card"
                      key={source.key}
                    >

                      <div className="source-icon">
                        {source.short}
                      </div>

                      <div className="source-card-info">

                        <strong>
                          {source.name}
                        </strong>

                        <small>
                          {source.description}
                        </small>

                      </div>

                      <span
                        className={`source-status ${
                          success
                            ? "success"
                            : "warning"
                        }`}
                      >
                        <span className="source-status-dot" />

                        {success
                          ? "Success"
                          : "Unavailable"}

                      </span>

                    </div>
                  );

                })}

              </div>

            </div>

          </div>

          {/* ==================================================
              SOURCE DETAILS
          ================================================== */}

          <div className="source-details-grid">

            {sourceCards.map((source) => (

              <div
                className="panel source-detail-panel"
                key={source.key}
              >

                <div className="panel-header">

                  <div>
                    <div className="source-detail-title">

                      <span className="source-detail-icon">
                        {source.short}
                      </span>

                      <div>

                        <h4>
                          {source.name}
                        </h4>

                        <p>
                          {source.description}
                        </p>

                      </div>

                    </div>
                  </div>

                  <span
                    className={`source-status ${
                      source.data !== null
                        ? "success"
                        : "warning"
                    }`}
                  >
                    <span className="source-status-dot" />

                    {source.data !== null
                      ? "Available"
                      : "Unavailable"}

                  </span>

                </div>

                <div className="source-detail-body">

                  {source.data ? (

                    <pre>
                      {JSON.stringify(
                        source.data,
                        null,
                        2
                      )}
                    </pre>

                  ) : (

                    <div className="chart-message">
                      {source.name} did not return
                      data for this lookup.
                    </div>

                  )}

                </div>

              </div>

            ))}

          </div>

        </div>
      )}

      {/* ==================================================
          INTELLIGENCE HISTORY
      ================================================== */}

      <div className="panel intelligence-history-panel">

        <div className="panel-header">

          <div>
            <div className="panel-kicker">
              ACTIVITY
            </div>

            <h4>
              Intelligence History
            </h4>

            <p>
              Recent threat intelligence
              lookups performed by ThreatLens.
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

          <div className="history-loading">

            <div className="spinner" />

            <span>
              Loading intelligence history...
            </span>

          </div>

        ) : history.length === 0 ? (

          <div className="history-empty">

            <div className="history-empty-icon">
              ◌
            </div>

            <strong>
              No intelligence lookups
            </strong>

            <span>
              Run a threat scan to populate
              intelligence history.
            </span>

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
                      item?.threatlens_score ??
                      item?.score ??
                      0
                  );

                const risk =
                  getHistoryRisk(
                    historyScore
                  );

                return (

                  <div
                    className="ip-row intelligence-history-row"
                    key={
                      item?.id ||
                      `${historyIP}-${source}-${index}`
                    }
                  >

                    <div className="history-ip-info">

                      <div className="history-ip-primary">

                        <span className="history-ip-indicator" />

                        <strong>
                          {historyIP}
                        </strong>

                      </div>

                      <small>
                        Source: {source}
                      </small>

                    </div>

                    <div className="history-result">

                      <div className="history-score">

                        <small>
                          Score
                        </small>

                        <strong>
                          {historyScore}
                        </strong>

                      </div>

                      <span
                        className={`risk ${risk}`}
                      >
                        {formatSeverity(risk)}
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