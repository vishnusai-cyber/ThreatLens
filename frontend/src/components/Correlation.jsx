import { useState } from "react";
import { correlateIP } from "../api";

function Correlation() {
  const [ip, setIP] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  function isValidIPv4(value) {
    const regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return regex.test(value.trim());
  }

  function getScore(data) {
    const candidates = [
      data?.threat_score,
      data?.score,
      data?.threatScore,
      data?.threatlens_score,
      data?.threatlensScore,
      data?.correlation?.score,
      data?.threatlens?.score,
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

  function getSeverity(data, score) {
    const candidates = [
      data?.severity,
      data?.risk_level,
      data?.riskLevel,
      data?.threat_level,
      data?.threatLevel,
      data?.correlation?.severity,
      data?.threatlens?.severity,
      data?.data?.severity,
    ];

    for (const value of candidates) {
      if (value) {
        return String(value).toLowerCase();
      }
    }

    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 30) return "medium";

    return "low";
  }

  function getSourceStatus(data, source) {
    const sources = data?.sources;

    if (!sources) {
      return false;
    }

    if (Array.isArray(sources)) {
      return sources.some((item) => {
        const name =
          item?.source ||
          item?.name ||
          item?.provider ||
          "";

        return (
          String(name).toLowerCase() ===
          source.toLowerCase()
        );
      });
    }

    const key = Object.keys(sources).find(
      (item) =>
        item.toLowerCase() ===
        source.toLowerCase()
    );

    return Boolean(key && sources[key]);
  }

  function formatSeverity(value) {
    if (!value) return "Unknown";

    return (
      String(value).charAt(0).toUpperCase() +
      String(value).slice(1).toLowerCase()
    );
  }

  async function handleSubmit(event) {
    event.preventDefault();

    const value = ip.trim();

    if (!value) {
      setError("Please enter an IP address.");
      return;
    }

    if (!isValidIPv4(value)) {
      setError(
        "Please enter a valid IPv4 address. Example: 8.8.8.8"
      );
      return;
    }

    try {
      setLoading(true);
      setError("");
      setResult(null);

      console.log(
        "ThreatLens Correlation: scanning",
        value
      );

      const response = await correlateIP(value);

      console.log(
        "ThreatLens Correlation result:",
        response
      );

      setResult({
        ...response,
        analyzed_ip: value,
      });
    } catch (err) {
      console.error(
        "Correlation error:",
        err
      );

      setError(
        err?.message ||
          "Correlation failed. Please try again."
      );
    } finally {
      setLoading(false);
    }
  }

  const score = getScore(result);
  const severity = getSeverity(result, score);

  return (
    <section className="dashboard">

      {/* =====================================================
          PAGE HEADER
      ===================================================== */}

      <div className="page-heading">

        <div>
          <h3>Correlation Engine</h3>

          <p>
            Correlate an IP address across
            multiple threat intelligence sources.
          </p>
        </div>

      </div>

      {/* =====================================================
          SEARCH PANEL
      ===================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>
            <h4>IP Correlation</h4>

            <p>
              Query VirusTotal, AbuseIPDB and
              AlienVault OTX.
            </p>
          </div>

        </div>

        <form
          className="scan-form"
          onSubmit={handleSubmit}
        >

          <label htmlFor="correlation-ip">
            IP Address
          </label>

          <input
            id="correlation-ip"
            type="text"
            value={ip}
            onChange={(event) => {
              setIP(event.target.value);
              setError("");
            }}
            placeholder="8.8.8.8"
            autoComplete="off"
            spellCheck="false"
          />

          <span className="input-hint">
            Enter a public IPv4 address to
            perform threat correlation.
          </span>

          {error && (
            <div className="scan-error">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="primary-button"
            disabled={loading}
          >
            {loading
              ? "Correlating..."
              : "Run Correlation"}
          </button>

        </form>

      </div>

      {/* =====================================================
          LOADING
      ===================================================== */}

      {loading && (

        <div className="panel">

          <div className="scan-progress">

            <div className="spinner" />

            <strong>
              Correlation Engine Running
            </strong>

            <span>
              Querying multiple threat
              intelligence providers...
            </span>

          </div>

        </div>

      )}

      {/* =====================================================
          RESULTS
      ===================================================== */}

      {!loading && result && (

        <>

          {/* SCORE */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>Correlation Result</h4>

                <p>
                  Aggregated ThreatLens
                  assessment.
                </p>
              </div>

            </div>

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

            <div className="result-ip">

              <span>
                ANALYZED IP ADDRESS
              </span>

              <strong>
                {result.analyzed_ip}
              </strong>

            </div>

          </div>

          {/* =================================================
              SOURCES
          ================================================= */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>
                  Intelligence Sources
                </h4>

                <p>
                  Provider availability for
                  this correlation.
                </p>
              </div>

            </div>

            <div className="source-grid">

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
                    )
                      ? "success"
                      : "warning"
                  }`}
                >
                  {getSourceStatus(
                    result,
                    "VirusTotal"
                  )
                    ? "Success"
                    : "Unavailable"}
                </span>

              </div>

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
                    )
                      ? "success"
                      : "warning"
                  }`}
                >
                  {getSourceStatus(
                    result,
                    "AbuseIPDB"
                  )
                    ? "Success"
                    : "Unavailable"}
                </span>

              </div>

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
                    )
                      ? "success"
                      : "warning"
                  }`}
                >
                  {getSourceStatus(
                    result,
                    "OTX"
                  )
                    ? "Success"
                    : "Unavailable"}
                </span>

              </div>

            </div>

          </div>

          {/* =================================================
              RAW CORRELATION DATA
          ================================================= */}

          <div className="panel">

            <div className="panel-header">

              <div>
                <h4>
                  Correlation Details
                </h4>

                <p>
                  Backend response from the
                  ThreatLens correlation engine.
                </p>
              </div>

            </div>

            <pre
              style={{
                overflowX: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                fontSize: "12px",
                lineHeight: "1.6",
                padding: "16px",
                borderRadius: "10px",
                background:
                  "rgba(0, 0, 0, 0.25)",
              }}
            >
              {JSON.stringify(
                result,
                null,
                2
              )}
            </pre>

          </div>

        </>

      )}

    </section>
  );
}

export default Correlation;