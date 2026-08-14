import { useState } from "react";

import {
  correlateIP,
  getVirusTotalIP,
  getAbuseIPDB,
  getOTX,
} from "./api";

import "./index.css";

// ==========================================================
// ThreatLens - Threat Intelligence Module
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

  // ========================================================
  // IPv4 Validation
  // ========================================================

  function isValidIPv4(value) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return ipv4Regex.test(value.trim());
  }

  // ========================================================
  // Extract ThreatLens Score
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

      if (Number.isFinite(number)) {
        return Math.round(number);
      }
    }

    return 0;
  }

  // ========================================================
  // Extract Severity
  // ========================================================

  function getSeverity(data, score) {
    if (data) {
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

    return (
      String(value).charAt(0).toUpperCase() +
      String(value).slice(1).toLowerCase()
    );
  }

  // ========================================================
  // Extract Source
  // ========================================================

  function getSource(data, sourceName) {
    if (!data) {
      return null;
    }

    const sourceLower = sourceName.toLowerCase();

    const sources = data?.sources;

    if (sources && !Array.isArray(sources)) {
      return (
        sources[sourceName] ||
        sources[sourceLower] ||
        sources[
          Object.keys(sources).find(
            (key) => key.toLowerCase() === sourceLower
          )
        ] ||
        null
      );
    }

    if (Array.isArray(sources)) {
      return (
        sources.find((item) => {
          const name =
            item?.source ||
            item?.name ||
            item?.provider ||
            "";

          return String(name).toLowerCase() === sourceLower;
        }) || null
      );
    }

    const correlation = data?.correlation;

    if (correlation && typeof correlation === "object") {
      return (
        correlation[sourceName] ||
        correlation[sourceLower] ||
        null
      );
    }

    return null;
  }

  // ========================================================
  // Run Correlation Scan
  // ========================================================

  async function handleScan(event) {
    event.preventDefault();

    const cleanIP = ip.trim();

    setError("");

    // ------------------------------------------------------
    // Validation
    // ------------------------------------------------------

    if (!cleanIP) {
      setError("Please enter an IP address.");
      return;
    }

    if (!isValidIPv4(cleanIP)) {
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
      setResult(null);

      // ----------------------------------------------------
      // Correlation Engine
      // ----------------------------------------------------

      const correlationResult = await correlateIP(cleanIP);

      console.log(
        "ThreatLens correlation result:",
        correlationResult
      );

      // ----------------------------------------------------
      // Store result
      // ----------------------------------------------------

      const completeResult = {
        ...correlationResult,
        analyzed_ip: cleanIP,
      };

      setResult(completeResult);

      // ----------------------------------------------------
      // Local session history
      // ----------------------------------------------------

      setHistory((previous) => {
        const score = getThreatScore(completeResult);

        const severity = getSeverity(
          completeResult,
          score
        );

        const newEntry = {
          ip: cleanIP,
          score,
          severity,
          time: new Date().toLocaleTimeString(),
        };

        return [
          newEntry,
          ...previous.filter(
            (item) => item.ip !== cleanIP
          ),
        ].slice(0, 10);
      });
    } catch (scanError) {
      console.error(
        "Threat intelligence scan failed:",
        scanError
      );

      setError(
        scanError?.message ||
          "Threat intelligence correlation failed."
      );
    } finally {
      setLoading(false);
    }
  }

  // ========================================================
  // Individual Source Lookup
  // ========================================================

  async function handleSourceLookup(source) {
    const cleanIP = ip.trim();

    if (!cleanIP || !isValidIPv4(cleanIP)) {
      setError(
        "Enter a valid IPv4 address before querying a source."
      );

      return;
    }

    try {
      setError("");

      let sourceResult;

      if (source === "VirusTotal") {
        sourceResult = await getVirusTotalIP(cleanIP);
      }

      if (source === "AbuseIPDB") {
        sourceResult = await getAbuseIPDB(cleanIP);
      }

      if (source === "OTX") {
        sourceResult = await getOTX(cleanIP);
      }

      console.log(
        `${source} result:`,
        sourceResult
      );

      setResult((previous) => ({
        ...(previous || {}),
        analyzed_ip: cleanIP,
        [source.toLowerCase().replace(" ", "_")]:
          sourceResult,
      }));
    } catch (sourceError) {
      console.error(
        `${source} lookup failed:`,
        sourceError
      );

      setError(
        sourceError?.message ||
          `${source} lookup failed.`
      );
    }
  }

  // ========================================================
  // Clear Result
  // ========================================================

  function clearResult() {
    setResult(null);
    setError("");
  }

  // ========================================================
  // Result Values
  // ========================================================

  const score = getThreatScore(result);

  const severity = getSeverity(
    result,
    score
  );

  const analyzedIP =
    result?.analyzed_ip ||
    result?.ip_address ||
    ip;

  // ========================================================
  // Source Data
  // ========================================================

  const virusTotal =
    getSource(result, "VirusTotal") ||
    result?.virustotal ||
    result?.virus_total ||
    result?.virustotal_result;

  const abuseIPDB =
    getSource(result, "AbuseIPDB") ||
    result?.abuseipdb ||
    result?.abuse_ipdb ||
    result?.abuseipdb_result;

  const otx =
    getSource(result, "OTX") ||
    result?.otx ||
    result?.alienvault ||
    result?.alienvault_otx;

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
            Investigate IP addresses using
            multi-source threat intelligence
            correlation.
          </p>
        </div>

      </div>

      {/* ==================================================
          SEARCH PANEL
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>
            <h4>
              IP Intelligence Search
            </h4>

            <p>
              Enter an IPv4 address to run the
              ThreatLens Correlation Engine.
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
              width: "100%",
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
              Querying VirusTotal, AbuseIPDB
              and AlienVault OTX.
            </span>

          </div>

        </div>

      )}

      {/* ==================================================
          RESULTS
      ================================================== */}

      {!loading && result && (

        <>

          {/* ================================================
              SCORE
          ================================================= */}

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

          {/* ================================================
              IP INFORMATION
          ================================================= */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>
                  Analysis Result
                </h4>

                <p>
                  Correlation result for the
                  analyzed IP address.
                </p>
              </div>

              <button
                className="secondary-button"
                onClick={clearResult}
              >
                Clear Result
              </button>

            </div>

            <div className="result-ip">

              <span>
                ANALYZED IP ADDRESS
              </span>

              <strong>
                {analyzedIP}
              </strong>

            </div>

          </div>

          {/* ================================================
              INTELLIGENCE SOURCES
          ================================================= */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>
                  Intelligence Sources
                </h4>

                <p>
                  Results collected from
                  integrated threat intelligence
                  providers.
                </p>
              </div>

            </div>

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

                <span className="source-status success">
                  Available
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

                <span className="source-status success">
                  Available
                </span>

              </div>

              {/* OTX */}

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

                <span className="source-status success">
                  Available
                </span>

              </div>

            </div>

          </div>

          {/* ================================================
              SOURCE ACTIONS
          ================================================= */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>
                  Individual Intelligence Lookups
                </h4>

                <p>
                  Query each provider independently.
                </p>
              </div>

            </div>

            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "12px",
              }}
            >

              <button
                className="secondary-button"
                onClick={() =>
                  handleSourceLookup(
                    "VirusTotal"
                  )
                }
              >
                Query VirusTotal
              </button>

              <button
                className="secondary-button"
                onClick={() =>
                  handleSourceLookup(
                    "AbuseIPDB"
                  )
                }
              >
                Query AbuseIPDB
              </button>

              <button
                className="secondary-button"
                onClick={() =>
                  handleSourceLookup("OTX")
                }
              >
                Query AlienVault OTX
              </button>

            </div>

          </div>

          {/* ================================================
              RAW SOURCE DATA
          ================================================= */}

          {(virusTotal ||
            abuseIPDB ||
            otx) && (

            <div className="panel">

              <div className="panel-header">

                <div>
                  <h4>
                    Source Intelligence
                  </h4>

                  <p>
                    Provider-specific intelligence
                    returned by the backend.
                  </p>
                </div>

              </div>

              <div
                style={{
                  display: "grid",
                  gap: "16px",
                }}
              >

                {virusTotal && (

                  <details>
                    <summary>
                      VirusTotal Intelligence
                    </summary>

                    <pre
                      style={{
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                        marginTop: "12px",
                      }}
                    >
                      {JSON.stringify(
                        virusTotal,
                        null,
                        2
                      )}
                    </pre>

                  </details>

                )}

                {abuseIPDB && (

                  <details>
                    <summary>
                      AbuseIPDB Intelligence
                    </summary>

                    <pre
                      style={{
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                        marginTop: "12px",
                      }}
                    >
                      {JSON.stringify(
                        abuseIPDB,
                        null,
                        2
                      )}
                    </pre>

                  </details>

                )}

                {otx && (

                  <details>
                    <summary>
                      AlienVault OTX Intelligence
                    </summary>

                    <pre
                      style={{
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                        marginTop: "12px",
                      }}
                    >
                      {JSON.stringify(
                        otx,
                        null,
                        2
                      )}
                    </pre>

                  </details>

                )}

              </div>

            </div>

          )}

        </>

      )}

      {/* ==================================================
          SESSION SCAN HISTORY
      ================================================== */}

      {history.length > 0 && (

        <div className="panel">

          <div className="panel-header">

            <div>
              <h4>
                Recent Intelligence Scans
              </h4>

              <p>
                IP addresses analyzed during
                this session.
              </p>
            </div>

          </div>

          <div className="ip-list">

            {history.map(
              (item, index) => (

                <div
                  className="ip-row"
                  key={`${item.ip}-${index}`}
                >

                  <div>

                    <strong>
                      {item.ip}
                    </strong>

                    <small>
                      Score: {item.score}
                      {" • "}
                      {item.time}
                    </small>

                  </div>

                  <span
                    className={`risk ${item.severity}`}
                  >
                    {formatSeverity(
                      item.severity
                    )}
                  </span>

                </div>

              )
            )}

          </div>

        </div>

      )}

    </section>
  );
}

export default ThreatIntelligence;