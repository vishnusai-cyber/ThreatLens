import { useEffect, useState } from "react";

import { getIntelligenceHistory } from "../api";

import "../index.css";

// ==========================================================
// ThreatLens - Intelligence History
// ==========================================================

function IntelligenceHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  // ========================================================
  // Normalize API Response
  // ========================================================

  function normalizeHistory(response) {
    if (Array.isArray(response)) {
      return response;
    }

    if (!response || typeof response !== "object") {
      return [];
    }

    if (Array.isArray(response.data)) {
      return response.data;
    }

    if (Array.isArray(response.items)) {
      return response.items;
    }

    if (Array.isArray(response.results)) {
      return response.results;
    }

    return [];
  }

  // ========================================================
  // Severity
  // ========================================================

  function getSeverity(score) {
    const value = Number(score);

    if (!Number.isFinite(value)) {
      return "low";
    }

    if (value >= 80) {
      return "critical";
    }

    if (value >= 60) {
      return "high";
    }

    if (value >= 30) {
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
  // Format Date
  // ========================================================

  function formatDate(value) {
    if (!value) {
      return "Unknown";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return String(value);
    }

    return date.toLocaleString();
  }

  // ========================================================
  // Load History
  // ========================================================

  async function loadHistory(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      console.log(
        "ThreatLens: Loading intelligence history..."
      );

      const response =
        await getIntelligenceHistory(50, 0);

      const normalized =
        normalizeHistory(response);

      setHistory(normalized);

      console.log(
        "ThreatLens intelligence history:",
        normalized
      );
    } catch (err) {
      console.error(
        "ThreatLens intelligence history error:",
        err
      );

      setError(
        err?.message ||
          "Unable to load intelligence history."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial Load
  // ========================================================

  useEffect(() => {
    loadHistory(false);
  }, []);

  // ========================================================
  // Statistics
  // ========================================================

  const totalLookups = history.length;

  const uniqueIPs = new Set(
    history
      .map(
        (item) =>
          item?.ip_address ||
          item?.ip ||
          item?.address
      )
      .filter(Boolean)
  ).size;

  const criticalCount = history.filter(
    (item) => {
      const score = Number(
        item?.threat_score ??
          item?.score ??
          item?.threatlens_score ??
          0
      );

      return score >= 80;
    }
  ).length;

  const highCount = history.filter(
    (item) => {
      const score = Number(
        item?.threat_score ??
          item?.score ??
          item?.threatlens_score ??
          0
      );

      return score >= 60 && score < 80;
    }
  ).length;

  // ========================================================
  // Render
  // ========================================================

  return (
    <section className="dashboard">

      {/* ==================================================
          HEADER
      ================================================== */}

      <div className="page-heading">

        <div>

          <span className="modal-label">
            THREAT INTELLIGENCE
          </span>

          <h3>
            Intelligence History
          </h3>

          <p>
            Review historical threat intelligence
            lookups and correlation results.
          </p>

        </div>

        <div className="heading-actions">

          <button
            className="secondary-button"
            onClick={() =>
              loadHistory(true)
            }
            disabled={refreshing}
          >
            {refreshing
              ? "↻ Refreshing..."
              : "↻ Refresh History"}
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
          STATISTICS
      ================================================== */}

      {!loading && (

        <div className="stats-grid">

          <div className="stat-card">

            <div className="stat-header">

              <span>
                Total Lookups
              </span>

              <span className="stat-icon">
                ⌁
              </span>

            </div>

            <strong>
              {totalLookups}
            </strong>

            <div className="stat-change">
              Historical intelligence queries
            </div>

          </div>

          <div className="stat-card">

            <div className="stat-header">

              <span>
                Unique IPs
              </span>

              <span className="stat-icon">
                ◎
              </span>

            </div>

            <strong>
              {uniqueIPs}
            </strong>

            <div className="stat-change">
              Unique addresses analyzed
            </div>

          </div>

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
              {criticalCount}
            </strong>

            <div className="stat-change negative">
              Score 80 or above
            </div>

          </div>

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
              {highCount}
            </strong>

            <div className="stat-change">
              Score 60–79
            </div>

          </div>

        </div>

      )}

      {/* ==================================================
          HISTORY TABLE
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <h4>
              Intelligence Lookup History
            </h4>

            <p>
              Recent intelligence lookups stored
              by ThreatLens.
            </p>

          </div>

          <span className="history-count">
            {history.length} records
          </span>

        </div>

        {loading ? (

          <div className="chart-message">
            Loading intelligence history...
          </div>

        ) : history.length === 0 ? (

          <div className="chart-message">
            No intelligence lookups found.
          </div>

        ) : (

          <div className="history-table-wrapper">

            <table className="history-table">

              <thead>

                <tr>

                  <th>
                    ID
                  </th>

                  <th>
                    IP ADDRESS
                  </th>

                  <th>
                    SOURCE
                  </th>

                  <th>
                    THREAT SCORE
                  </th>

                  <th>
                    SEVERITY
                  </th>

                  <th>
                    INCIDENT
                  </th>

                  <th>
                    LOOKUP TIME
                  </th>

                </tr>

              </thead>

              <tbody>

                {history.map(
                  (item, index) => {

                    const id =
                      item?.id ??
                      index + 1;

                    const ip =
                      item?.ip_address ||
                      item?.ip ||
                      item?.address ||
                      "Unknown";

                    const source =
                      item?.source ||
                      item?.provider ||
                      "Unknown";

                    const score = Number(
                      item?.threat_score ??
                        item?.score ??
                        item?.threatlens_score ??
                        0
                    );

                    const severity =
                      String(
                        item?.severity ||
                          getSeverity(score)
                      ).toLowerCase();

                    const incident =
                      item?.incident_id ??
                      item?.incident?.id ??
                      "—";

                    const timestamp =
                      item?.created_at ||
                      item?.timestamp ||
                      item?.updated_at;

                    return (

                      <tr
                        key={`${id}-${ip}-${index}`}
                      >

                        <td>
                          #{id}
                        </td>

                        <td>

                          <strong className="history-ip">
                            {ip}
                          </strong>

                        </td>

                        <td>

                          <span className="source-badge">
                            {source}
                          </span>

                        </td>

                        <td>

                          <strong>
                            {score}
                          </strong>

                        </td>

                        <td>

                          <span
                            className={`risk ${severity}`}
                          >
                            {formatSeverity(
                              severity
                            )}
                          </span>

                        </td>

                        <td>

                          {incident === "—"
                            ? "—"
                            : `#${incident}`}

                        </td>

                        <td>

                          <small>
                            {formatDate(
                              timestamp
                            )}
                          </small>

                        </td>

                      </tr>

                    );
                  }
                )}

              </tbody>

            </table>

          </div>

        )}

      </div>

    </section>
  );
}

export default IntelligenceHistory;