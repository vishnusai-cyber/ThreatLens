import { useEffect, useMemo, useState } from "react";

import {
  getAlerts,
  updateAlert,
} from "../api";

import "../index.css";

// ==========================================================
// ThreatLens - Alerts
// ==========================================================

function Alerts({ refreshKey = 0 }) {
  // ========================================================
  // State
  // ========================================================

  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] = useState(true);

  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  // all | open | resolved
  const [filter, setFilter] = useState("all");

  // ========================================================
  // Load Alerts
  // ========================================================

  async function loadAlerts(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      console.log(
        "ThreatLens Alerts: Loading alerts..."
      );

      const data = await getAlerts();

      console.log(
        "ThreatLens Alerts: API response:",
        data
      );

      // ====================================================
      // Normalize API response
      // ====================================================

      let normalizedAlerts = [];

      if (Array.isArray(data)) {
        normalizedAlerts = data;
      } else {
        normalizedAlerts =
          data?.data ||
          data?.items ||
          data?.results ||
          [];
      }

      // ====================================================
      // Ensure array
      // ====================================================

      if (!Array.isArray(normalizedAlerts)) {
        normalizedAlerts = [];
      }

      setAlerts(normalizedAlerts);

      console.log(
        "ThreatLens Alerts: Normalized alerts:",
        normalizedAlerts
      );
    } catch (err) {
      console.error(
        "ThreatLens Alerts loading error:",
        err
      );

      setError(
        err?.message ||
          "Unable to load alerts."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial Load + Scan Refresh
  // ========================================================

  useEffect(() => {
    if (refreshKey === 0) {
      console.log(
        "ThreatLens Alerts: Initial load."
      );

      loadAlerts(false);

      return;
    }

    console.log(
      "ThreatLens Alerts: refreshKey changed:",
      refreshKey
    );

    console.log(
      "ThreatLens Alerts: Refreshing after scan..."
    );

    loadAlerts(true);
  }, [refreshKey]);

  // ========================================================
  // Update Alert Status
  // ========================================================

  async function handleStatusChange(
    alert,
    status
  ) {
    try {
      setError("");

      console.log(
        "ThreatLens Alerts: Updating alert:",
        alert?.id,
        "→",
        status
      );

      if (!alert?.id) {
        throw new Error(
          "Alert ID is missing."
        );
      }

      await updateAlert(
        alert.id,
        {
          status,
        }
      );

      console.log(
        "ThreatLens Alerts: Alert updated successfully."
      );

      // ====================================================
      // Reload alerts after update
      // ====================================================

      await loadAlerts(true);
    } catch (err) {
      console.error(
        "Alert update error:",
        err
      );

      setError(
        err?.message ||
          "Unable to update alert."
      );
    }
  }

  // ========================================================
  // Severity
  // ========================================================

  function getSeverity(alert) {
    return String(
      alert?.severity ||
        alert?.level ||
        "low"
    ).toLowerCase();
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
  // Format Status
  // ========================================================

  function formatStatus(value) {
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
  // Status Class
  // ========================================================

  function getStatusClass(status) {
    const normalized =
      String(status || "").toLowerCase();

    if (normalized === "open") {
      return "high";
    }

    if (
      normalized === "resolved" ||
      normalized === "closed"
    ) {
      return "low";
    }

    return "medium";
  }

  // ========================================================
  // Normalize Status
  // ========================================================

  function getStatus(alert) {
    return String(
      alert?.status || "open"
    ).toLowerCase();
  }

  // ========================================================
  // Filter Alerts
  // ========================================================

  const filteredAlerts = useMemo(() => {
    if (filter === "open") {
      return alerts.filter(
        (alert) =>
          getStatus(alert) === "open"
      );
    }

    if (filter === "resolved") {
      return alerts.filter((alert) => {
        const status = getStatus(alert);

        return (
          status === "resolved" ||
          status === "closed"
        );
      });
    }

    return alerts;
  }, [alerts, filter]);

  // ========================================================
  // Alert Statistics
  // ========================================================

  const alertStats = useMemo(() => {
    let open = 0;
    let resolved = 0;
    let critical = 0;
    let high = 0;

    alerts.forEach((alert) => {
      const status = getStatus(alert);
      const severity = getSeverity(alert);

      if (status === "open") {
        open++;
      }

      if (
        status === "resolved" ||
        status === "closed"
      ) {
        resolved++;
      }

      if (severity === "critical") {
        critical++;
      }

      if (severity === "high") {
        high++;
      }
    });

    return {
      total: alerts.length,
      open,
      resolved,
      critical,
      high,
    };
  }, [alerts]);

  // ========================================================
  // Render Alert
  // ========================================================

  function renderAlert(alert, index) {
    // ======================================================
    // Severity
    // ======================================================

    const severity =
      getSeverity(alert);

    // ======================================================
    // Title
    // ======================================================

    const title =
      alert?.title ||
      "Threat Alert";

    // ======================================================
    // Description
    // ======================================================

    const description =
      alert?.description ||
      alert?.message ||
      "Security threat detected.";

    // ======================================================
    // IP
    // ======================================================

    const ip =
      alert?.ip_address ||
      alert?.ip ||
      "Unknown IP";

    // ======================================================
    // Score
    // ======================================================

    const score =
      Number(
        alert?.threatlens_score ??
          alert?.threat_score ??
          alert?.score ??
          0
      );

    // ======================================================
    // Status
    // ======================================================

    const status =
      getStatus(alert);

    const statusClass =
      getStatusClass(status);

    // ======================================================
    // Created Date
    // ======================================================

    const createdAt =
      alert?.created_at ||
      alert?.createdAt ||
      alert?.timestamp ||
      "";

    let formattedDate = "";

    if (createdAt) {
      try {
        formattedDate =
          new Date(
            createdAt
          ).toLocaleString();
      } catch {
        formattedDate =
          String(createdAt);
      }
    }

    // ======================================================
    // Resolved Date
    // ======================================================

    const resolvedAt =
      alert?.resolved_at ||
      alert?.resolvedAt ||
      "";

    let formattedResolvedDate = "";

    if (resolvedAt) {
      try {
        formattedResolvedDate =
          new Date(
            resolvedAt
          ).toLocaleString();
      } catch {
        formattedResolvedDate =
          String(resolvedAt);
      }
    }

    // ======================================================
    // Render
    // ======================================================

    return (
      <div
        className="alert-row"
        key={
          alert?.id ||
          `${ip}-${index}`
        }
      >
        {/* ==================================================
            ICON
        ================================================== */}

        <div
          className={`alert-icon ${severity}`}
        >
          ⚠
        </div>

        {/* ==================================================
            INFORMATION
        ================================================== */}

        <div
          style={{
            flex: 1,
            minWidth: 0,
          }}
        >
          <strong>
            {title}
          </strong>

          <small>
            {description}
          </small>

          <small>
            IP: {ip}
          </small>

          {formattedDate && (
            <small>
              Created: {formattedDate}
            </small>
          )}

          {formattedResolvedDate && (
            <small>
              Resolved:{" "}
              {formattedResolvedDate}
            </small>
          )}
        </div>

        {/* ==================================================
            SCORE
        ================================================== */}

        <div
          style={{
            textAlign: "center",
            minWidth: "80px",
          }}
        >
          <small>
            Score
          </small>

          <strong>
            {score}
          </strong>
        </div>

        {/* ==================================================
            SEVERITY
        ================================================== */}

        <span
          className={`risk ${severity}`}
        >
          {formatSeverity(
            severity
          )}
        </span>

        {/* ==================================================
            STATUS
        ================================================== */}

        <span
          className={`risk ${statusClass}`}
        >
          {formatStatus(
            status
          )}
        </span>

        {/* ==================================================
            ACTION
        ================================================== */}

        {status === "open" && (
          <button
            className="secondary-button"
            onClick={() =>
              handleStatusChange(
                alert,
                "Resolved"
              )
            }
            disabled={refreshing}
          >
            {refreshing
              ? "Updating..."
              : "Resolve"}
          </button>
        )}
      </div>
    );
  }

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
            SECURITY OPERATIONS
          </span>

          <h3>
            Alerts
          </h3>

          <p>
            Monitor and manage active
            ThreatLens security alerts.
          </p>

        </div>

        <div className="heading-actions">

          <button
            className="secondary-button"
            onClick={() =>
              loadAlerts(true)
            }
            disabled={
              loading ||
              refreshing
            }
          >
            {refreshing
              ? "↻ Refreshing..."
              : "↻ Refresh Alerts"}
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
          STAT CARDS
      ================================================== */}

      {!loading && (
        <div className="stats-grid">

          {/* TOTAL */}

          <div className="stat-card">

            <div className="stat-header">
              <span>
                Total Alerts
              </span>

              <span className="stat-icon">
                ⚠
              </span>
            </div>

            <strong>
              {alertStats.total}
            </strong>

            <div className="stat-change">
              All security alerts
            </div>

          </div>

          {/* OPEN */}

          <div className="stat-card critical-card">

            <div className="stat-header">
              <span>
                Active Alerts
              </span>

              <span className="stat-icon">
                !
              </span>
            </div>

            <strong>
              {alertStats.open}
            </strong>

            <div className="stat-change negative">
              Requires attention
            </div>

          </div>

          {/* CRITICAL */}

          <div className="stat-card">

            <div className="stat-header">
              <span>
                Critical
              </span>

              <span className="stat-icon">
                ⚠
              </span>
            </div>

            <strong>
              {alertStats.critical}
            </strong>

            <div className="stat-change">
              Critical detections
            </div>

          </div>

          {/* RESOLVED */}

          <div className="stat-card">

            <div className="stat-header">
              <span>
                Resolved
              </span>

              <span className="stat-icon">
                ✓
              </span>
            </div>

            <strong>
              {alertStats.resolved}
            </strong>

            <div className="stat-change">
              Historical alerts
            </div>

          </div>

        </div>
      )}

      {/* ==================================================
          ALERT PANEL
      ================================================== */}

      <div className="panel">

        <div className="panel-header">

          <div>

            <h4>
              Security Alerts
            </h4>

            <p>
              Automatically generated
              alerts for High and Critical
              threats.
            </p>

          </div>

          <strong>
            {filteredAlerts.length} Alerts
          </strong>

        </div>

        {/* ==================================================
            FILTERS
        ================================================== */}

        {!loading && (
          <div
            style={{
              display: "flex",
              gap: "10px",
              marginBottom: "20px",
              flexWrap: "wrap",
            }}
          >

            <button
              className={
                filter === "all"
                  ? "primary-button"
                  : "secondary-button"
              }
              onClick={() =>
                setFilter("all")
              }
            >
              All ({alertStats.total})
            </button>

            <button
              className={
                filter === "open"
                  ? "primary-button"
                  : "secondary-button"
              }
              onClick={() =>
                setFilter("open")
              }
            >
              Active ({alertStats.open})
            </button>

            <button
              className={
                filter === "resolved"
                  ? "primary-button"
                  : "secondary-button"
              }
              onClick={() =>
                setFilter("resolved")
              }
            >
              Resolved ({alertStats.resolved})
            </button>

          </div>
        )}

        {/* ==================================================
            LOADING
        ================================================== */}

        {loading ? (

          <div className="chart-message">
            Loading security alerts...
          </div>

        ) : filteredAlerts.length === 0 ? (

          <div className="chart-message">

            {filter === "open"
              ? "No active security alerts."
              : filter === "resolved"
              ? "No resolved alerts found."
              : "No security alerts found."}

          </div>

        ) : (

          <div className="alert-list">

            {filteredAlerts.map(
              renderAlert
            )}

          </div>

        )}

      </div>

    </section>
  );
}

export default Alerts;