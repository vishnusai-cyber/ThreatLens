import { useEffect, useState } from "react";
import "./index.css";

import {
  getDashboardOverview,
  getSeverityDistribution,
  getTopThreatIPs,
  getRecentAlerts,
  getThreatTrends,
} from "./api";

function App() {
  // ==========================================================
  // State
  // ==========================================================

  const [overview, setOverview] = useState(null);
  const [severity, setSeverity] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [threatTrends, setThreatTrends] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // ==========================================================
  // Load Dashboard Data
  // ==========================================================

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      setError("");

      const [
        overviewData,
        severityData,
        topIPsData,
        recentAlertsData,
        trendsData,
      ] = await Promise.all([
        getDashboardOverview(),
        getSeverityDistribution(),
        getTopThreatIPs(),
        getRecentAlerts(),
        getThreatTrends(),
      ]);

      // ------------------------------------------------------
      // Overview
      // ------------------------------------------------------

      setOverview(overviewData);

      // ------------------------------------------------------
      // Severity Distribution
      // ------------------------------------------------------

      setSeverity(
        Array.isArray(severityData)
          ? severityData
          : severityData?.items ||
              severityData?.data ||
              []
      );

      // ------------------------------------------------------
      // Top Threat IPs
      // ------------------------------------------------------

      setTopIPs(
        Array.isArray(topIPsData)
          ? topIPsData
          : topIPsData?.items ||
              topIPsData?.data ||
              []
      );

      // ------------------------------------------------------
      // Recent Activity / Alerts
      // ------------------------------------------------------

      setRecentAlerts(
        Array.isArray(recentAlertsData)
          ? recentAlertsData
          : recentAlertsData?.items ||
              recentAlertsData?.data ||
              []
      );

      // ------------------------------------------------------
      // Threat Trends
      // ------------------------------------------------------

      setThreatTrends(
        Array.isArray(trendsData)
          ? trendsData
          : trendsData?.items ||
              trendsData?.data ||
              []
      );
    } catch (err) {
      console.error(
        "Dashboard loading error:",
        err
      );

      setError(
        err.message ||
          "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
    }
  }

  // ==========================================================
  // Overview Values
  // ==========================================================

  const totalScans =
    overview?.total_scans ?? 0;

  const uniqueIPs =
    overview?.unique_ips ?? 0;

  const criticalThreats =
    overview?.critical ?? 0;

  const highThreats =
    overview?.high ?? 0;

  const mediumThreats =
    overview?.medium ?? 0;

  const lowThreats =
    overview?.low ?? 0;

  // ==========================================================
  // Threat Trend Maximum
  // ==========================================================

  const maxTrendCount = Math.max(
    ...threatTrends.map((trend) =>
      Number(trend.count ?? 0)
    ),
    1
  );

  // ==========================================================
  // Helpers
  // ==========================================================

  function formatSeverity(level) {
    if (!level) {
      return "Unknown";
    }

    const value = String(level);

    return (
      value.charAt(0).toUpperCase() +
      value.slice(1).toLowerCase()
    );
  }

  function formatDate(dateValue) {
    if (!dateValue) {
      return "";
    }

    const date = new Date(dateValue);

    if (Number.isNaN(date.getTime())) {
      return String(dateValue);
    }

    return date.toLocaleDateString(
      undefined,
      {
        month: "short",
        day: "numeric",
      }
    );
  }

  function formatDateTime(dateValue) {
    if (!dateValue) {
      return "Recently";
    }

    const date = new Date(dateValue);

    if (Number.isNaN(date.getTime())) {
      return String(dateValue);
    }

    return date.toLocaleString();
  }

  // ==========================================================
  // Render
  // ==========================================================

  return (
    <div className="app">

      {/* =====================================================
          SIDEBAR
      ===================================================== */}

      <aside className="sidebar">

        {/* Logo */}

        <div className="logo">

          <div className="logo-icon">
            T
          </div>

          <div>
            <h1>ThreatLens</h1>
            <span>SOC Platform</span>
          </div>

        </div>

        {/* Navigation */}

        <nav className="navigation">

          {/* MAIN */}

          <div className="nav-section">

            <span className="nav-title">
              MAIN
            </span>

            <a
              className="nav-item active"
              href="#"
            >
              <span>▣</span>
              Dashboard
            </a>

            <a
              className="nav-item"
              href="#"
            >
              <span>⌕</span>
              Threat Intelligence
            </a>

            <a
              className="nav-item"
              href="#"
            >
              <span>⚠</span>
              Alerts
            </a>

            <a
              className="nav-item"
              href="#"
            >
              <span>◈</span>
              Incidents
            </a>

          </div>

          {/* ANALYSIS */}

          <div className="nav-section">

            <span className="nav-title">
              ANALYSIS
            </span>

            <a
              className="nav-item"
              href="#"
            >
              <span>◎</span>
              Correlation
            </a>

            <a
              className="nav-item"
              href="#"
            >
              <span>◉</span>
              Threat Scores
            </a>

            <a
              className="nav-item"
              href="#"
            >
              <span>◌</span>
              Intelligence History
            </a>

          </div>

          {/* SYSTEM */}

          <div className="nav-section">

            <span className="nav-title">
              SYSTEM
            </span>

            <a
              className="nav-item"
              href="#"
            >
              <span>⚙</span>
              Settings
            </a>

          </div>

        </nav>

        {/* System Status */}

        <div className="sidebar-footer">

          <div className="system-status">

            <span className="status-dot"></span>

            <div>

              <strong>
                System Online
              </strong>

              <small>
                ThreatLens API
              </small>

            </div>

          </div>

        </div>

      </aside>

      {/* =====================================================
          MAIN CONTENT
      ===================================================== */}

      <main className="main-content">

        {/* ===================================================
            TOP BAR
        =================================================== */}

        <header className="topbar">

          <div>

            <h2>
              Security Operations Center
            </h2>

            <p>
              Real-time threat intelligence overview
            </p>

          </div>

          <div className="topbar-actions">

            <button
              className="icon-button"
              type="button"
            >
              ⌕
            </button>

            <button
              className="icon-button"
              type="button"
            >
              🔔
            </button>

            <div className="profile">

              <div className="avatar">
                A
              </div>

              <div>

                <strong>
                  Administrator
                </strong>

                <small>
                  Admin
                </small>

              </div>

            </div>

          </div>

        </header>

        {/* ===================================================
            DASHBOARD
        =================================================== */}

        <section className="dashboard">

          {/* Page Heading */}

          <div className="page-heading">

            <div>

              <h3>
                Dashboard
              </h3>

              <p>
                Monitor your threat landscape
                and security posture.
              </p>

            </div>

            <button
              className="primary-button"
              type="button"
              onClick={loadDashboard}
            >
              ↻ Refresh Dashboard
            </button>

          </div>

          {/* =================================================
              ERROR
          ================================================= */}

          {error && (
            <div
              style={{
                background: "#351c22",
                border: "1px solid #6b2a34",
                color: "#f27782",
                padding: "12px 15px",
                borderRadius: "8px",
                marginBottom: "18px",
                fontSize: "12px",
              }}
            >
              Dashboard API Error:{" "}
              {error}
            </div>
          )}

          {/* =================================================
              STATISTICS
          ================================================= */}

          <div className="stats-grid">

            {/* Total Scans */}

            <div className="stat-card">

              <div className="stat-header">

                <span>
                  Total Scans
                </span>

                <span className="stat-icon">
                  ⌁
                </span>

              </div>

              <strong>
                {loading
                  ? "..."
                  : totalScans.toLocaleString()}
              </strong>

              <div className="stat-change">
                Threat intelligence scans
              </div>

            </div>

            {/* Unique IPs */}

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
                {loading
                  ? "..."
                  : uniqueIPs.toLocaleString()}
              </strong>

              <div className="stat-change">
                Unique addresses analyzed
              </div>

            </div>

            {/* Critical */}

            <div className="stat-card critical-card">

              <div className="stat-header">

                <span>
                  Critical Threats
                </span>

                <span className="stat-icon">
                  ⚠
                </span>

              </div>

              <strong>
                {loading
                  ? "..."
                  : criticalThreats.toLocaleString()}
              </strong>

              <div className="stat-change negative">
                Requires immediate attention
              </div>

            </div>

            {/* High */}

            <div className="stat-card">

              <div className="stat-header">

                <span>
                  High Threats
                </span>

                <span className="stat-icon">
                  !
                </span>

              </div>

              <strong>
                {loading
                  ? "..."
                  : highThreats.toLocaleString()}
              </strong>

              <div className="stat-change">
                High severity detections
              </div>

            </div>

          </div>

          {/* =================================================
              THREAT ACTIVITY + SEVERITY
          ================================================= */}

          <div className="dashboard-grid">

            {/* =================================================
                REAL THREAT ACTIVITY
            ================================================= */}

            <div className="panel large-panel">

              <div className="panel-header">

                <div>

                  <h4>
                    Threat Activity
                  </h4>

                  <p>
                    Threat detections over time
                  </p>

                </div>

              </div>

              <div className="threat-chart">

                {loading ? (

                  <div className="chart-message">
                    Loading threat activity...
                  </div>

                ) : threatTrends.length === 0 ? (

                  <div className="chart-message">
                    No threat activity data available.
                  </div>

                ) : (

                  <div className="chart-bars">

                    {threatTrends.map(
                      (item, index) => {

                        const count =
                          Number(
                            item.count ?? 0
                          );

                        const height =
                          Math.max(
                            (count /
                              maxTrendCount) *
                              100,
                            5
                          );

                        return (
                          <div
                            className="chart-column"
                            key={`${item.date}-${index}`}
                          >

                            <div className="chart-value">
                              {count}
                            </div>

                            <div
                              className="chart-bar"
                              style={{
                                height: `${height}%`,
                              }}
                            ></div>

                            <span className="chart-date">
                              {formatDate(
                                item.date
                              )}
                            </span>

                          </div>
                        );
                      }
                    )}

                  </div>
                )}

              </div>

            </div>

            {/* =================================================
                SEVERITY DISTRIBUTION
            ================================================= */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    Severity Distribution
                  </h4>

                  <p>
                    Current threat levels
                  </p>

                </div>

              </div>

              <div className="severity-list">

                {loading ? (

                  <div className="severity-item">

                    <span>
                      Loading...
                    </span>

                  </div>

                ) : (

                  <>

                    {/* Critical */}

                    <div className="severity-item">

                      <div>

                        <span className="severity-dot critical"></span>

                        Critical

                      </div>

                      <strong>
                        {criticalThreats}
                      </strong>

                    </div>

                    {/* High */}

                    <div className="severity-item">

                      <div>

                        <span className="severity-dot high"></span>

                        High

                      </div>

                      <strong>
                        {highThreats}
                      </strong>

                    </div>

                    {/* Medium */}

                    <div className="severity-item">

                      <div>

                        <span className="severity-dot medium"></span>

                        Medium

                      </div>

                      <strong>
                        {mediumThreats}
                      </strong>

                    </div>

                    {/* Low */}

                    <div className="severity-item">

                      <div>

                        <span className="severity-dot low"></span>

                        Low

                      </div>

                      <strong>
                        {lowThreats}
                      </strong>

                    </div>

                  </>

                )}

              </div>

            </div>

          </div>

          {/* =================================================
              TOP IPS + RECENT ALERTS
          ================================================= */}

          <div className="dashboard-grid">

            {/* =================================================
                TOP THREAT IPS
            ================================================= */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    Top Threat IPs
                  </h4>

                  <p>
                    Highest risk addresses
                  </p>

                </div>

                <button
                  className="text-button"
                  type="button"
                >
                  View All →
                </button>

              </div>

              <div className="ip-list">

                {loading ? (

                  <div className="ip-row">

                    <span>
                      Loading...
                    </span>

                  </div>

                ) : topIPs.length === 0 ? (

                  <div className="ip-row">

                    <span>
                      No threat IPs available
                    </span>

                  </div>

                ) : (

                  topIPs
                    .slice(0, 5)
                    .map(
                      (item, index) => {

                        const ip =
                          item.ip_address ||
                          item.ip ||
                          "Unknown IP";

                        const score =
                          item.score ?? 0;

                        const severityLevel =
                          String(
                            item.severity ||
                              "Low"
                          ).toLowerCase();

                        return (

                          <div
                            className="ip-row"
                            key={`${ip}-${index}`}
                          >

                            <div>

                              <strong>
                                {ip}
                              </strong>

                              <small>
                                Threat Score:{" "}
                                {score}
                              </small>

                            </div>

                            <span
                              className={`risk ${severityLevel}`}
                            >
                              {formatSeverity(
                                severityLevel
                              )}
                            </span>

                          </div>

                        );
                      }
                    )

                )}

              </div>

            </div>

            {/* =================================================
                RECENT ALERTS
            ================================================= */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <h4>
                    Recent Alerts
                  </h4>

                  <p>
                    Latest security events
                  </p>

                </div>

                <button
                  className="text-button"
                  type="button"
                >
                  View All →
                </button>

              </div>

              <div className="alert-list">

                {loading ? (

                  <div className="alert-row">

                    <span>
                      Loading...
                    </span>

                  </div>

                ) : recentAlerts.length === 0 ? (

                  <div className="alert-row">

                    <span>
                      No recent alerts
                    </span>

                  </div>

                ) : (

                  recentAlerts
                    .slice(0, 5)
                    .map(
                      (
                        alert,
                        index
                      ) => {

                        const level =
                          String(
                            alert.severity ||
                              "Low"
                          ).toLowerCase();

                        const ip =
                          alert.ip_address ||
                          "Unknown IP";

                        const score =
                          alert.score ?? 0;

                        const timestamp =
                          alert.created_at ||
                          "Recently";

                        let title =
                          "Security event detected";

                        if (
                          level ===
                          "critical"
                        ) {
                          title =
                            "Critical threat detected";
                        } else if (
                          level === "high"
                        ) {
                          title =
                            "High severity threat detected";
                        } else if (
                          level === "medium"
                        ) {
                          title =
                            "Medium severity threat detected";
                        } else if (
                          level === "low"
                        ) {
                          title =
                            "Low severity event detected";
                        }

                        return (

                          <div
                            className="alert-row"
                            key={`${ip}-${timestamp}-${index}`}
                          >

                            <span
                              className={`alert-icon ${level}`}
                            >
                              !
                            </span>

                            <div>

                              <strong>
                                {title}
                              </strong>

                              <small>
                                {ip} · Score{" "}
                                {score} ·{" "}
                                {formatDateTime(
                                  timestamp
                                )}
                              </small>

                            </div>

                          </div>

                        );
                      }
                    )

                )}

              </div>

            </div>

          </div>

        </section>

      </main>

    </div>
  );
}

export default App;