import { useEffect, useState } from "react";

import "../index.css";

import { getThreatScores } from "../api";

// ==========================================================
// ThreatLens - Threat Scores
// ==========================================================

function ThreatScores() {
  const [scores, setScores] = useState([]);

  const [total, setTotal] = useState(0);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  const [offset, setOffset] = useState(0);

  const limit = 10;

  // ========================================================
  // Load Threat Scores
  // ========================================================

  async function loadThreatScores(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const data = await getThreatScores(
        limit,
        offset
      );

      console.log(
        "[ThreatLens] Threat Scores response:",
        data
      );

      // ====================================================
      // Normalize API response
      // ====================================================

      let normalized = [];

      if (Array.isArray(data)) {
        normalized = data;
      } else if (
        data &&
        typeof data === "object"
      ) {
        normalized =
          data.items ||
          data.data ||
          data.results ||
          data.threat_scores ||
          data.threatScores ||
          [];
      }

      if (!Array.isArray(normalized)) {
        normalized = [];
      }

      setScores(normalized);

      // Backend returns:
      // {
      //   items: [...],
      //   total: 4,
      //   limit: 10,
      //   offset: 0
      // }

      const backendTotal = Number(
        data?.total
      );

      if (
        Number.isFinite(backendTotal)
      ) {
        setTotal(backendTotal);
      } else {
        setTotal(normalized.length);
      }

    } catch (err) {
      console.error(
        "ThreatLens Threat Scores error:",
        err
      );

      setScores([]);
      setTotal(0);

      setError(
        err?.message ||
          "Unable to load threat scores."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial Load / Pagination
  // ========================================================

  useEffect(() => {
    loadThreatScores();
  }, [offset]);

  // ========================================================
  // Score Extraction
  // ========================================================

  function getScore(item) {
    if (!item) {
      return 0;
    }

    const candidates = [
      item.threatlens_score,
      item.threatlensScore,
      item.threat_score,
      item.threatScore,
      item.score,
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
  // IP Extraction
  // ========================================================

  function getIP(item) {
    return (
      item?.ip_address ||
      item?.ip ||
      item?.address ||
      item?.source_ip ||
      "Unknown IP"
    );
  }

  // ========================================================
  // Severity Extraction
  // ========================================================

  function getSeverity(item) {
    const explicitSeverity =
      item?.severity ||
      item?.risk_level ||
      item?.riskLevel ||
      item?.threat_level ||
      item?.threatLevel;

    if (explicitSeverity) {
      return String(
        explicitSeverity
      ).toLowerCase();
    }

    const score = getScore(item);

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
  // Severity Formatting
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
  // Incident ID
  // ========================================================

  function getIncidentID(item) {
    return (
      item?.incident_id ??
      item?.incidentId ??
      "—"
    );
  }

  // ========================================================
  // Alert ID
  // ========================================================

  function getAlertID(item) {
    return (
      item?.alert_id ??
      item?.alertId ??
      "—"
    );
  }

  // ========================================================
  // Record ID
  // ========================================================

  function getRecordID(item) {
    return (
      item?.id ??
      item?.threat_score_id ??
      item?.threatScoreId ??
      "—"
    );
  }

  // ========================================================
  // Recommendation
  // ========================================================

  function getRecommendation(item) {
    return (
      item?.recommendation ||
      item?.action ||
      "—"
    );
  }

  // ========================================================
  // Timestamp
  // ========================================================

  function getTimestamp(item) {
    const timestamp =
      item?.created_at ||
      item?.createdAt ||
      item?.updated_at ||
      item?.timestamp;

    if (!timestamp) {
      return "—";
    }

    const date = new Date(timestamp);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return String(timestamp);
    }

    return date.toLocaleString();
  }

  // ========================================================
  // Score Class
  // ========================================================

  function getScoreClass(score) {
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
  // Pagination
  // ========================================================

  function previousPage() {
    setOffset((current) =>
      Math.max(
        0,
        current - limit
      )
    );
  }

  function nextPage() {
    if (
      offset + scores.length >=
      total
    ) {
      return;
    }

    setOffset((current) =>
      current + limit
    );
  }

  const currentPage =
    Math.floor(
      offset / limit
    ) + 1;

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        total / limit
      )
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
            THREAT ANALYSIS
          </span>

          <h3>
            Threat Scores
          </h3>

          <p>
            Review ThreatLens risk scores
            generated by the correlation engine.
          </p>

        </div>

        <div className="heading-actions">

          <button
            className="secondary-button"
            onClick={() =>
              loadThreatScores(true)
            }
            disabled={refreshing}
          >
            {refreshing
              ? "↻ Refreshing..."
              : "↻ Refresh"}
          </button>

        </div>

      </div>

      {/* ==================================================
          ERROR
      ================================================== */}

      {error && (

        <div className="dashboard-error">
          {error}
        </div>

      )}

      {/* ==================================================
          SUMMARY
      ================================================== */}

      {!loading &&
        !error &&
        scores.length > 0 && (

          <div className="stats-grid">

            {/* RECORDS */}

            <div className="stat-card">

              <div className="stat-header">

                <span>
                  Records
                </span>

                <span className="stat-icon">
                  ◎
                </span>

              </div>

              <strong>
                {total}
              </strong>

              <div className="stat-change">
                Total threat score records
              </div>

            </div>

            {/* CRITICAL */}

            <div className="stat-card critical-card">

              <div className="stat-header">

                <span>
                  Critical
                </span>

                <span className="stat-icon">
                  ⚠
                </span>

              </div>

              <strong>
                {
                  scores.filter(
                    (item) =>
                      getSeverity(item) ===
                      "critical"
                  ).length
                }
              </strong>

              <div className="stat-change negative">
                Immediate attention
              </div>

            </div>

            {/* HIGH */}

            <div className="stat-card">

              <div className="stat-header">

                <span>
                  High
                </span>

                <span className="stat-icon">
                  !
                </span>

              </div>

              <strong>
                {
                  scores.filter(
                    (item) =>
                      getSeverity(item) ===
                      "high"
                  ).length
                }
              </strong>

              <div className="stat-change">
                High risk records
              </div>

            </div>

            {/* AVERAGE */}

            <div className="stat-card">

              <div className="stat-header">

                <span>
                  Average Score
                </span>

                <span className="stat-icon">
                  ◈
                </span>

              </div>

              <strong>

                {Math.round(
                  scores.reduce(
                    (
                      totalScore,
                      item
                    ) =>
                      totalScore +
                      getScore(item),
                    0
                  ) /
                    Math.max(
                      scores.length,
                      1
                    )
                )}

              </strong>

              <div className="stat-change">
                Current page average
              </div>

            </div>

          </div>

        )}

      {/* ==================================================
          TABLE PANEL
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <h4>
              Threat Score Records
            </h4>

            <p>
              Correlation engine scoring results.
            </p>

          </div>

          {!loading && (

            <span className="input-hint">
              Showing{" "}
              {scores.length}{" "}
              of{" "}
              {total}{" "}
              records
            </span>

          )}

        </div>

        {/* ==================================================
            LOADING
        ================================================== */}

        {loading ? (

          <div className="chart-message">

            <div className="scan-progress">

              <div className="spinner" />

              <strong>
                Loading Threat Scores...
              </strong>

              <span>
                Retrieving correlation engine
                scoring records.
              </span>

            </div>

          </div>

        ) : error ? (

          /* ==================================================
              ERROR STATE
          ================================================== */

          <div className="chart-message">

            <strong>
              Failed to fetch threat scores.
            </strong>

            <br />

            <span>
              {error}
            </span>

            <br />

            <br />

            <button
              className="primary-button"
              onClick={() =>
                loadThreatScores(true)
              }
              disabled={refreshing}
            >
              {refreshing
                ? "Retrying..."
                : "Retry"}
            </button>

          </div>

        ) : scores.length === 0 ? (

          /* ==================================================
              EMPTY STATE
          ================================================== */

          <div className="chart-message">

            <strong>
              No threat scores found.
            </strong>

            <br />

            Run a threat intelligence scan
            to generate ThreatLens scores.

          </div>

        ) : (

          /* ==================================================
              TABLE
          ================================================== */

          <div
            style={{
              overflowX:
                "auto",
              width:
                "100%",
            }}
          >

            <table
              style={{
                width:
                  "100%",
                minWidth:
                  "900px",
                borderCollapse:
                  "collapse",
              }}
            >

              <thead>

                <tr>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    ID
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    IP ADDRESS
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    THREAT SCORE
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    SEVERITY
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    INCIDENT
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    ALERT
                  </th>

                  <th
                    style={{
                      textAlign:
                        "left",
                      padding:
                        "14px",
                      fontSize:
                        "12px",
                      opacity:
                        0.65,
                    }}
                  >
                    CREATED
                  </th>

                </tr>

              </thead>

              <tbody>

                {scores.map(
                  (
                    item,
                    index
                  ) => {

                    const score =
                      getScore(item);

                    const severity =
                      getSeverity(item);

                    return (

                      <tr
                        key={
                          item?.id ||
                          `${getIP(
                            item
                          )}-${index}`
                        }
                        style={{
                          borderTop:
                            "1px solid rgba(255,255,255,0.06)",
                        }}
                      >

                        <td
                          style={{
                            padding:
                              "16px 14px",
                            opacity:
                              0.7,
                          }}
                        >
                          #
                          {getRecordID(
                            item
                          )}
                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                          }}
                        >
                          <strong>
                            {getIP(
                              item
                            )}
                          </strong>
                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                          }}
                        >

                          <div
                            style={{
                              display:
                                "flex",
                              alignItems:
                                "center",
                              gap:
                                "10px",
                            }}
                          >

                            <strong
                              className={`score-number ${getScoreClass(
                                score
                              )}`}
                            >
                              {score}
                            </strong>

                            <span
                              style={{
                                opacity:
                                  0.45,
                              }}
                            >
                              / 100
                            </span>

                          </div>

                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                          }}
                        >

                          <span
                            className={`risk ${severity}`}
                          >
                            {formatSeverity(
                              severity
                            )}
                          </span>

                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                            opacity:
                              0.75,
                          }}
                        >
                          {getIncidentID(
                            item
                          )}
                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                            opacity:
                              0.75,
                          }}
                        >
                          {getAlertID(
                            item
                          )}
                        </td>

                        <td
                          style={{
                            padding:
                              "16px 14px",
                            opacity:
                              0.7,
                          }}
                        >
                          {getTimestamp(
                            item
                          )}
                        </td>

                      </tr>

                    );
                  }
                )}

              </tbody>

            </table>

          </div>

        )}

        {/* ==================================================
            PAGINATION
        ================================================== */}

        {!loading &&
          !error &&
          scores.length > 0 && (

            <div
              style={{
                display:
                  "flex",
                justifyContent:
                  "space-between",
                alignItems:
                  "center",
                marginTop:
                  "20px",
                paddingTop:
                  "16px",
                borderTop:
                  "1px solid rgba(255,255,255,0.06)",
              }}
            >

              <button
                className="secondary-button"
                onClick={
                  previousPage
                }
                disabled={
                  offset === 0 ||
                  refreshing
                }
              >
                ← Previous
              </button>

              <span
                style={{
                  fontSize:
                    "13px",
                  opacity:
                    0.65,
                }}
              >
                Page{" "}
                {currentPage}
                {" "}
                of{" "}
                {totalPages}
              </span>

              <button
                className="secondary-button"
                onClick={
                  nextPage
                }
                disabled={
                  offset +
                    scores.length >=
                    total ||
                  refreshing
                }
              >
                Next →
              </button>

            </div>

          )}

      </div>

    </section>
  );
}

export default ThreatScores;