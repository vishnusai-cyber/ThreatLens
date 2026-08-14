import { useEffect, useMemo, useState } from "react";

import {
  getDashboardOverview,
  getSeverityDistribution,
  getTopThreatIPs,
  getRecentAlerts,
  getThreatTrends,
  correlateIP,
} from "./api";

import ThreatIntelligence from "./components/ThreatIntelligence";
import IntelligenceHistory from "./components/IntelligenceHistory";
import ThreatScores from "./components/ThreatScores";
import Alerts from "./components/Alerts";
import Incidents from "./components/Incidents";
import Correlation from "./components/Correlation";

import "./index.css";

// ==========================================================
// ThreatLens - Security Operations Center
// ==========================================================

function App() {
  // ========================================================
  // Dashboard State
  // ========================================================

  const [overview, setOverview] = useState(null);
  const [severity, setSeverity] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [trends, setTrends] = useState([]);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [dashboardError, setDashboardError] = useState("");

  // ========================================================
  // Component Refresh Keys
  // ========================================================

  const [alertsRefreshKey, setAlertsRefreshKey] = useState(0);
  const [threatIntelRefreshKey, setThreatIntelRefreshKey] =
    useState(0);
  const [incidentsRefreshKey, setIncidentsRefreshKey] =
    useState(0);
  const [threatScoresRefreshKey, setThreatScoresRefreshKey] =
    useState(0);
  const [historyRefreshKey, setHistoryRefreshKey] =
    useState(0);

  // ========================================================
  // Dashboard Refresh Timestamp
  // ========================================================

  const [lastDashboardRefresh, setLastDashboardRefresh] =
    useState(null);

  // ========================================================
  // Navigation
  // ========================================================

  const [activePage, setActivePage] = useState("Dashboard");

  // ========================================================
  // Settings
  // ========================================================

  const [settings, setSettings] = useState({
    realtimeMonitoring: true,
    automaticCorrelation: true,
    alertNotifications: true,
    soundNotifications: false,
    darkMode: true,
    autoRefresh: true,
    refreshInterval: "30",
  });

  // ========================================================
  // Dashboard Scan Modal
  // ========================================================

  const [showScanModal, setShowScanModal] = useState(false);
  const [scanIP, setScanIP] = useState("");
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState("");
  const [scanResult, setScanResult] = useState(null);

  // ========================================================
  // Normalize API Response
  // ========================================================

  function normalizeArray(response, extraKeys = []) {
    if (Array.isArray(response)) {
      return response;
    }

    if (!response || typeof response !== "object") {
      return [];
    }

    const possibleKeys = [
      "data",
      "items",
      "results",
      ...extraKeys,
    ];

    for (const key of possibleKeys) {
      if (Array.isArray(response[key])) {
        return response[key];
      }
    }

    return [];
  }

  // ========================================================
  // Dashboard Loading
  // ========================================================

  async function loadDashboard(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setDashboardError("");

      console.log(
        "=============================================="
      );

      console.log(
        "ThreatLens: Loading fresh dashboard data..."
      );

      console.log(
        "=============================================="
      );

      const [
        overviewData,
        severityData,
        topIPsData,
        recentAlertsData,
        trendsData,
      ] = await Promise.all([
        getDashboardOverview(),
        getSeverityDistribution(),
        getTopThreatIPs(10),
        getRecentAlerts(10),
        getThreatTrends(),
      ]);

      // ----------------------------------------------------
      // Overview
      // ----------------------------------------------------

      setOverview(overviewData);

      // ----------------------------------------------------
      // Severity
      // ----------------------------------------------------

      const normalizedSeverity =
        normalizeArray(severityData);

      setSeverity(normalizedSeverity);

      console.log(
        "ThreatLens severity refreshed:",
        normalizedSeverity
      );

      // ----------------------------------------------------
      // Top IPs
      // ----------------------------------------------------

      const normalizedTopIPs =
        normalizeArray(topIPsData);

      setTopIPs(normalizedTopIPs);

      console.log(
        "ThreatLens top IPs refreshed:",
        normalizedTopIPs
      );

      // ----------------------------------------------------
      // Recent Alerts
      // ----------------------------------------------------

      const normalizedAlerts =
        normalizeArray(recentAlertsData);

      setRecentAlerts(normalizedAlerts);

      console.log(
        "ThreatLens recent alerts refreshed:",
        normalizedAlerts
      );

      // ----------------------------------------------------
      // Threat Trends
      // ----------------------------------------------------

      const normalizedTrends =
        normalizeArray(
          trendsData,
          ["trends"]
        );

      setTrends(normalizedTrends);

      console.log(
        "ThreatLens threat trends refreshed:",
        normalizedTrends
      );

      // ----------------------------------------------------
      // Timestamp
      // ----------------------------------------------------

      setLastDashboardRefresh(
        new Date().toLocaleTimeString()
      );

      console.log(
        "ThreatLens: Dashboard refresh completed successfully."
      );
    } catch (error) {
      console.error(
        "ThreatLens dashboard loading error:",
        error
      );

      setDashboardError(
        error?.message ||
          "Unable to load dashboard data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial Dashboard Load
  // ========================================================

  useEffect(() => {
    loadDashboard(false).catch(() => {});
  }, []);

  // ========================================================
  // Automatic Dashboard Refresh
  // ========================================================

  useEffect(() => {
    if (!settings.autoRefresh) {
      return;
    }

    const intervalSeconds = Number(
      settings.refreshInterval
    );

    if (
      !Number.isFinite(intervalSeconds) ||
      intervalSeconds <= 0
    ) {
      return;
    }

    const interval = setInterval(() => {
      if (activePage === "Dashboard") {
        loadDashboard(true).catch(() => {});
      }
    }, intervalSeconds * 1000);

    return () => clearInterval(interval);
  }, [
    settings.autoRefresh,
    settings.refreshInterval,
    activePage,
  ]);

  // ========================================================
  // Settings Toggle
  // ========================================================

  function toggleSetting(settingName) {
    setSettings((previous) => ({
      ...previous,
      [settingName]: !previous[settingName],
    }));
  }

  // ========================================================
  // Settings Select
  // ========================================================

  function updateSetting(settingName, value) {
    setSettings((previous) => ({
      ...previous,
      [settingName]: value,
    }));
  }

  // ========================================================
  // Open Scan Modal
  // ========================================================

  function openScanModal() {
    setShowScanModal(true);
    setScanIP("");
    setScanError("");
    setScanResult(null);
  }

  // ========================================================
  // Close Scan Modal
  // ========================================================

  function closeScanModal() {
    if (scanLoading) {
      return;
    }

    setShowScanModal(false);
    setScanIP("");
    setScanError("");
    setScanResult(null);
  }

  // ========================================================
  // IPv4 Validation
  // ========================================================

  function isValidIPv4(ip) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return ipv4Regex.test(ip.trim());
  }

  // ========================================================
  // Threat Score Extraction
  // ========================================================

  function getThreatScore(result) {
    if (!result) {
      return 0;
    }

    const candidates = [
      result.threat_score,
      result.score,
      result.threatScore,
      result.threatlens_score,
      result.threatlensScore,

      result?.threatlens?.score,
      result?.correlation?.score,

      result?.data?.threat_score,
      result?.data?.score,
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
  // Severity Extraction
  // ========================================================

  function getThreatSeverity(result, score) {
    if (!result) {
      return "unknown";
    }

    const candidates = [
      result.severity,
      result.risk_level,
      result.riskLevel,
      result.threat_level,
      result.threatLevel,

      result?.threatlens?.severity,
      result?.correlation?.severity,
      result?.data?.severity,
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
  // Source Status
  // ========================================================

  function getSourceStatus(result, source) {
    if (!result) {
      return false;
    }

    const sourceLower =
      String(source).toLowerCase();

    // ------------------------------------------------------
    // Direct object source
    // ------------------------------------------------------

    if (
      result?.sources &&
      !Array.isArray(result.sources)
    ) {
      const matchingKey = Object.keys(
        result.sources
      ).find(
        (key) =>
          String(key).toLowerCase() ===
          sourceLower
      );

      if (
        matchingKey &&
        result.sources[matchingKey]
      ) {
        return true;
      }
    }

    // ------------------------------------------------------
    // Array based sources
    // ------------------------------------------------------

    if (
      result?.sources &&
      Array.isArray(result.sources)
    ) {
      return result.sources.some((item) => {
        const name =
          item?.source ||
          item?.name ||
          item?.provider ||
          "";

        return (
          String(name).toLowerCase() ===
          sourceLower
        );
      });
    }

    // ------------------------------------------------------
    // Correlation object
    // ------------------------------------------------------

    if (
      result?.correlation &&
      typeof result.correlation === "object"
    ) {
      const matchingKey = Object.keys(
        result.correlation
      ).find(
        (key) =>
          String(key).toLowerCase() ===
          sourceLower
      );

      if (
        matchingKey &&
        result.correlation[matchingKey]
      ) {
        return true;
      }
    }

    // ------------------------------------------------------
    // Explicit source names
    // ------------------------------------------------------

    const sourceText = JSON.stringify(result).toLowerCase();

    if (
      sourceLower === "virustotal" &&
      sourceText.includes("virustotal")
    ) {
      return true;
    }

    if (
      sourceLower === "abuseipdb" &&
      sourceText.includes("abuseipdb")
    ) {
      return true;
    }

    if (
      sourceLower === "otx" &&
      (
        sourceText.includes("alienvault") ||
        sourceText.includes('"otx"')
      )
    ) {
      return true;
    }

    return false;
  }

  // ========================================================
  // Refresh Everything After Scan
  // ========================================================

  async function refreshEverythingAfterScan() {
    console.log(
      "ThreatLens: Starting complete post-scan refresh..."
    );

    try {
      await loadDashboard(true);

      setAlertsRefreshKey(
        (value) => value + 1
      );

      setThreatIntelRefreshKey(
        (value) => value + 1
      );

      setIncidentsRefreshKey(
        (value) => value + 1
      );

      setThreatScoresRefreshKey(
        (value) => value + 1
      );

      setHistoryRefreshKey(
        (value) => value + 1
      );

      console.log(
        "ThreatLens: Complete post-scan refresh triggered."
      );
    } catch (error) {
      console.error(
        "ThreatLens: Post-scan refresh failed:",
        error
      );
    }
  }

  // ========================================================
  // Run Threat Scan
  // ========================================================

  async function handleThreatScan(event) {
    event.preventDefault();

    const ip = scanIP.trim();

    if (!ip) {
      setScanError(
        "Please enter an IP address."
      );
      return;
    }

    if (!isValidIPv4(ip)) {
      setScanError(
        "Please enter a valid IPv4 address. Example: 8.8.8.8"
      );
      return;
    }

    try {
      setScanLoading(true);
      setScanError("");
      setScanResult(null);

      console.log(
        "ThreatLens: Starting new threat scan:",
        ip
      );

      const result =
        await correlateIP(ip);

      console.log(
        "ThreatLens correlation result:",
        result
      );

      setScanResult({
        ...result,
        analyzed_ip: ip,
      });

      await refreshEverythingAfterScan();
    } catch (error) {
      console.error(
        "ThreatLens threat scan error:",
        error
      );

      setScanError(
        error?.message ||
          "Threat correlation failed. Please try again."
      );
    } finally {
      setScanLoading(false);
    }
  }

  // ========================================================
  // Dashboard Statistics
  // ========================================================

  const stats = useMemo(() => {
    return {
      totalScans:
        overview?.total_scans ??
        overview?.totalScans ??
        overview?.scans ??
        0,

      uniqueIPs:
        overview?.unique_ips ??
        overview?.uniqueIPs ??
        overview?.unique_ip_count ??
        0,

      critical:
        overview?.critical ??
        overview?.critical_threats ??
        overview?.criticalThreats ??
        0,

      high:
        overview?.high ??
        overview?.high_threats ??
        overview?.highThreats ??
        0,
    };
  }, [overview]);

  // ========================================================
  // Severity Statistics
  // ========================================================

  const severityStats = useMemo(() => {
    const result = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    if (Array.isArray(severity)) {
      severity.forEach((item) => {
        const severityName =
          String(
            item?.severity || ""
          ).toLowerCase();

        const count =
          Number(
            item?.count ?? 0
          );

        if (!Number.isFinite(count)) {
          return;
        }

        switch (severityName) {
          case "critical":
            result.critical = count;
            break;

          case "high":
            result.high = count;
            break;

          case "medium":
            result.medium = count;
            break;

          case "low":
            result.low = count;
            break;

          default:
            break;
        }
      });

      return result;
    }

    const source =
      severity || {};

    result.critical =
      Number(
        source.critical ??
          source.Critical ??
          source.critical_count ??
          0
      ) || 0;

    result.high =
      Number(
        source.high ??
          source.High ??
          source.high_count ??
          0
      ) || 0;

    result.medium =
      Number(
        source.medium ??
          source.Medium ??
          source.medium_count ??
          0
      ) || 0;

    result.low =
      Number(
        source.low ??
          source.Low ??
          source.low_count ??
          0
      ) || 0;

    return result;
  }, [severity]);

  // ========================================================
  // Threat Chart
  // ========================================================

  const chartData = useMemo(() => {
    if (!Array.isArray(trends)) {
      return [];
    }

    return trends
      .slice(-7)
      .map((item, index) => {
        const value =
          Number(
            item?.count ??
              item?.threats ??
              item?.detections ??
              item?.total ??
              item?.value ??
              0
          );

        const date =
          item?.date ||
          item?.day ||
          item?.label ||
          `Day ${index + 1}`;

        return {
          value:
            Number.isFinite(value)
              ? value
              : 0,
          date,
        };
      });
  }, [trends]);

  // ========================================================
  // Maximum Chart Value
  // ========================================================

  const maxChartValue = useMemo(() => {
    if (!chartData.length) {
      return 1;
    }

    return Math.max(
      ...chartData.map(
        (item) => item.value
      ),
      1
    );
  }, [chartData]);

  // ========================================================
  // Scan Result
  // ========================================================

  const scanScore =
    getThreatScore(scanResult);

  const scanSeverity =
    getThreatSeverity(
      scanResult,
      scanScore
    );

  // ========================================================
  // Navigation
  // ========================================================

  function handleNavigation(page) {
    setActivePage(page);

    if (page === "Dashboard") {
      loadDashboard(true)
        .catch(() => {});
    }
  }

  // ========================================================
  // TOPBAR SEARCH
  // ========================================================

  function handleSearchClick() {
    openScanModal();
  }

  // ========================================================
  // TOPBAR NOTIFICATIONS
  // ========================================================

  function handleNotificationClick() {
    handleNavigation("Alerts");
  }

  // ========================================================
  // TOPBAR PROFILE
  // ========================================================

  function handleProfileClick() {
    handleNavigation("Settings");
  }

  // ========================================================
  // Severity Label
  // ========================================================

  function formatSeverity(value) {
    if (!value) {
      return "Unknown";
    }

    const text =
      String(value);

    return (
      text.charAt(0).toUpperCase() +
      text.slice(1).toLowerCase()
    );
  }

  // ========================================================
  // SETTINGS PAGE
  // ========================================================

  function renderSettings() {
    return (
      <section className="settings-page">

        {/* HEADER */}

        <div className="settings-header">

          <h3>
            Settings
          </h3>

          <p>
            Configure ThreatLens monitoring,
            notifications and system preferences.
          </p>

        </div>

        {/* MONITORING */}

        <div className="settings-card">

          <div className="settings-card-header">

            <h4>
              Monitoring
            </h4>

            <p>
              Configure real-time threat
              monitoring behaviour.
            </p>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Real-time Monitoring
              </strong>

              <p>
                Continuously monitor incoming
                threat intelligence events.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.realtimeMonitoring
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "realtimeMonitoring"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Automatic Correlation
              </strong>

              <p>
                Automatically correlate threat
                intelligence from multiple sources.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.automaticCorrelation
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "automaticCorrelation"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Automatic Dashboard Refresh
              </strong>

              <p>
                Refresh dashboard statistics
                automatically.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.autoRefresh
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "autoRefresh"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Refresh Interval
              </strong>

              <p>
                Select how frequently the
                dashboard updates.
              </p>

            </div>

            <select
              className="settings-select"
              value={
                settings.refreshInterval
              }
              onChange={(event) =>
                updateSetting(
                  "refreshInterval",
                  event.target.value
                )
              }
              disabled={
                !settings.autoRefresh
              }
            >
              <option value="15">
                Every 15 seconds
              </option>

              <option value="30">
                Every 30 seconds
              </option>

              <option value="60">
                Every 1 minute
              </option>

              <option value="300">
                Every 5 minutes
              </option>
            </select>

          </div>

        </div>

        {/* NOTIFICATIONS */}

        <div className="settings-card">

          <div className="settings-card-header">

            <h4>
              Notifications
            </h4>

            <p>
              Configure security alert notifications.
            </p>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Alert Notifications
              </strong>

              <p>
                Receive notifications when High
                or Critical alerts are generated.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.alertNotifications
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "alertNotifications"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Sound Notifications
              </strong>

              <p>
                Play a sound when a new alert
                is detected.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.soundNotifications
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "soundNotifications"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

        </div>

        {/* APPEARANCE */}

        <div className="settings-card">

          <div className="settings-card-header">

            <h4>
              Appearance
            </h4>

            <p>
              Configure the ThreatLens interface.
            </p>

          </div>

          <div className="setting-row">

            <div className="setting-info">

              <strong>
                Dark Mode
              </strong>

              <p>
                Use the dark SOC interface for
                security operations.
              </p>

            </div>

            <button
              className={`settings-toggle ${
                settings.darkMode
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                toggleSetting(
                  "darkMode"
                )
              }
              type="button"
            >
              <span />
            </button>

          </div>

        </div>

        {/* SYSTEM INFORMATION */}

        <div className="settings-card">

          <div className="settings-card-header">

            <h4>
              System Information
            </h4>

            <p>
              ThreatLens platform information.
            </p>

          </div>

          <div className="settings-info-grid">

            <div className="settings-info-item">

              <span>
                PLATFORM
              </span>

              <strong>
                ThreatLens SOC
              </strong>

            </div>

            <div className="settings-info-item">

              <span>
                ENVIRONMENT
              </span>

              <strong>
                Development
              </strong>

            </div>

            <div className="settings-info-item">

              <span>
                BACKEND
              </span>

              <strong>
                FastAPI
              </strong>

            </div>

            <div className="settings-info-item">

              <span>
                DATABASE
              </span>

              <strong>
                PostgreSQL
              </strong>

            </div>

            <div className="settings-info-item">

              <span>
                INTELLIGENCE SOURCES
              </span>

              <strong>
                VirusTotal + AbuseIPDB + OTX
              </strong>

            </div>

            <div className="settings-info-item">

              <span>
                SYSTEM STATUS
              </span>

              <strong>
                Operational
              </strong>

            </div>

          </div>

        </div>

      </section>
    );
  }

  // ========================================================
  // RENDER
  // ========================================================

  return (
    <div className="app">

      {/* ==================================================
          SIDEBAR
      ================================================== */}

      <aside className="sidebar">

        {/* LOGO */}

        <div className="logo">

          <div className="logo-icon">
            T
          </div>

          <div>

            <h1>
              ThreatLens
            </h1>

            <span>
              SOC Platform
            </span>

          </div>

        </div>

        {/* NAVIGATION */}

        <nav className="navigation">

          {/* MAIN */}

          <div className="nav-section">

            <span className="nav-title">
              MAIN
            </span>

            <button
              className={`nav-item ${
                activePage === "Dashboard"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Dashboard"
                )
              }
              type="button"
            >
              <span>▣</span>
              Dashboard
            </button>

            <button
              className={`nav-item ${
                activePage ===
                "Threat Intelligence"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Threat Intelligence"
                )
              }
              type="button"
            >
              <span>⌕</span>
              Threat Intelligence
            </button>

            <button
              className={`nav-item ${
                activePage === "Alerts"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Alerts"
                )
              }
              type="button"
            >
              <span>⚠</span>
              Alerts
            </button>

            <button
              className={`nav-item ${
                activePage === "Incidents"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Incidents"
                )
              }
              type="button"
            >
              <span>◇</span>
              Incidents
            </button>

          </div>

          {/* ANALYSIS */}

          <div className="nav-section">

            <span className="nav-title">
              ANALYSIS
            </span>

            <button
              className={`nav-item ${
                activePage === "Correlation"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Correlation"
                )
              }
              type="button"
            >
              <span>◎</span>
              Correlation
            </button>

            <button
              className={`nav-item ${
                activePage === "Threat Scores"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Threat Scores"
                )
              }
              type="button"
            >
              <span>◎</span>
              Threat Scores
            </button>

            <button
              className={`nav-item ${
                activePage ===
                "Intelligence History"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Intelligence History"
                )
              }
              type="button"
            >
              <span>◌</span>
              Intelligence History
            </button>

          </div>

          {/* SYSTEM */}

          <div className="nav-section">

            <span className="nav-title">
              SYSTEM
            </span>

            <button
              className={`nav-item ${
                activePage === "Settings"
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                handleNavigation(
                  "Settings"
                )
              }
              type="button"
            >
              <span>⚙</span>
              Settings
            </button>

          </div>

        </nav>

        {/* SIDEBAR FOOTER */}

        <div className="sidebar-footer">

          <div className="system-status">

            <div className="status-dot" />

            <div>

              <strong>
                System Online
              </strong>

              <small>
                All services operational
              </small>

            </div>

          </div>

        </div>

      </aside>

      {/* ==================================================
          MAIN CONTENT
      ================================================== */}

      <main className="main-content">

        {/* ==================================================
            TOP BAR
        ================================================== */}

        <header className="topbar">

          {/* TITLE */}

          <div className="topbar-title">

            <h2>
              Security Operations Center
            </h2>

            <p>
              Real-time threat intelligence overview
            </p>

          </div>

          {/* ACTIONS */}

          <div className="topbar-actions">

            {/* SEARCH */}

            <button
              className="icon-button"
              title="Search / New Threat Scan"
              onClick={handleSearchClick}
              type="button"
            >
              ⌕
            </button>

            {/* NOTIFICATIONS */}

            <button
              className="icon-button notification-button"
              title="View Alerts"
              onClick={handleNotificationClick}
              type="button"
            >

              🔔

              {recentAlerts.length > 0 && (

                <span className="notification-badge">

                  {recentAlerts.length > 9
                    ? "9+"
                    : recentAlerts.length}

                </span>

              )}

            </button>

            {/* SEPARATOR */}

            <div className="topbar-separator" />

            {/* PROFILE */}

            <button
              className="profile profile-button"
              title="Open Settings"
              onClick={handleProfileClick}
              type="button"
            >

              <div className="avatar">
                A
              </div>

              <div className="profile-details">

                <strong>
                  Administrator
                </strong>

                <small>
                  Admin
                </small>

              </div>

              <span className="profile-arrow">
                ▾
              </span>

            </button>

          </div>

        </header>

        {/* ==================================================
            DASHBOARD
        ================================================== */}

        {activePage === "Dashboard" && (

          <section className="dashboard">

            <div className="page-heading">

              <div>

                <h3>
                  Dashboard
                </h3>

                <p>
                  Monitor your threat
                  landscape and security
                  posture.
                </p>

              </div>

              <div className="heading-actions">

                <button
                  className="secondary-button"
                  onClick={() =>
                    loadDashboard(
                      true
                    ).catch(() => {})
                  }
                  disabled={refreshing}
                  type="button"
                >
                  {refreshing
                    ? "↻ Refreshing..."
                    : "↻ Refresh Dashboard"}
                </button>

                <button
                  className="primary-button"
                  onClick={openScanModal}
                  disabled={scanLoading}
                  type="button"
                >
                  + New Threat Scan
                </button>

              </div>

            </div>

            {lastDashboardRefresh && (

              <div
                style={{
                  fontSize: "12px",
                  opacity: 0.6,
                  marginBottom: "12px",
                }}
              >
                Last updated:{" "}
                {lastDashboardRefresh}
              </div>

            )}

            {dashboardError && (

              <div className="dashboard-error">
                {dashboardError}
              </div>

            )}

            {loading && !overview ? (

              <div className="panel">

                <div className="chart-message">
                  Loading ThreatLens
                  dashboard...
                </div>

              </div>

            ) : (

              <>

                {/* STAT CARDS */}

                <div className="stats-grid">

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
                      {stats.totalScans}
                    </strong>

                    <div className="stat-change">
                      Threat intelligence
                      scans
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
                      {stats.uniqueIPs}
                    </strong>

                    <div className="stat-change">
                      Unique addresses
                      analyzed
                    </div>

                  </div>

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
                      {stats.critical}
                    </strong>

                    <div className="stat-change negative">
                      Requires immediate
                      attention
                    </div>

                  </div>

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
                      {stats.high}
                    </strong>

                    <div className="stat-change">
                      High severity
                      detections
                    </div>

                  </div>

                </div>

                {/* THREAT ACTIVITY + SEVERITY */}

                <div className="dashboard-grid">

                  <div className="panel">

                    <div className="panel-header">

                      <div>

                        <h4>
                          Threat Activity
                        </h4>

                        <p>
                          Threat detections
                          over time
                        </p>

                      </div>

                    </div>

                    <div className="threat-chart">

                      {chartData.length === 0 ? (

                        <div className="chart-message">
                          No threat activity
                          data available.
                        </div>

                      ) : (

                        <div className="chart-bars">

                          {chartData.map(
                            (
                              item,
                              index
                            ) => {

                              const height =
                                Math.max(
                                  (
                                    item.value /
                                    maxChartValue
                                  ) * 80,
                                  item.value > 0
                                    ? 4
                                    : 0
                                );

                              return (

                                <div
                                  className="chart-column"
                                  key={`${item.date}-${index}`}
                                >

                                  <div className="chart-value">
                                    {item.value}
                                  </div>

                                  <div
                                    className="chart-bar"
                                    style={{
                                      height: `${height}%`,
                                    }}
                                    title={`${item.value} threats`}
                                  />

                                  <div className="chart-date">
                                    {item.date}
                                  </div>

                                </div>

                              );
                            }
                          )}

                        </div>

                      )}

                    </div>

                  </div>

                  <div className="panel">

                    <div className="panel-header">

                      <div>

                        <h4>
                          Severity Distribution
                        </h4>

                        <p>
                          Current threat
                          levels
                        </p>

                      </div>

                    </div>

                    <div className="severity-list">

                      <div className="severity-item">

                        <div>
                          <span className="severity-dot critical" />
                          Critical
                        </div>

                        <strong>
                          {severityStats.critical}
                        </strong>

                      </div>

                      <div className="severity-item">

                        <div>
                          <span className="severity-dot high" />
                          High
                        </div>

                        <strong>
                          {severityStats.high}
                        </strong>

                      </div>

                      <div className="severity-item">

                        <div>
                          <span className="severity-dot medium" />
                          Medium
                        </div>

                        <strong>
                          {severityStats.medium}
                        </strong>

                      </div>

                      <div className="severity-item">

                        <div>
                          <span className="severity-dot low" />
                          Low
                        </div>

                        <strong>
                          {severityStats.low}
                        </strong>

                      </div>

                    </div>

                  </div>

                </div>

                {/* TOP IPS + ALERTS */}

                <div className="dashboard-grid">

                  <div className="panel">

                    <div className="panel-header">

                      <div>

                        <h4>
                          Top Threat IPs
                        </h4>

                        <p>
                          Most frequently
                          detected addresses
                        </p>

                      </div>

                      <button
                        className="text-button"
                        onClick={() =>
                          handleNavigation(
                            "Threat Intelligence"
                          )
                        }
                        type="button"
                      >
                        View all
                      </button>

                    </div>

                    <div className="ip-list">

                      {topIPs.length === 0 ? (

                        <div className="chart-message">
                          No threat IPs
                          available.
                        </div>

                      ) : (

                        topIPs
                          .slice(0, 5)
                          .map(
                            (
                              item,
                              index
                            ) => {

                              const ip =
                                item?.ip_address ||
                                item?.ip ||
                                item?.address ||
                                "Unknown IP";

                              const score =
                                Number(
                                  item?.score ??
                                    item?.threat_score ??
                                    item?.threatlens_score ??
                                    item?.threatScore ??
                                    0
                                );

                              let risk =
                                "low";

                              if (
                                score >= 80
                              ) {
                                risk =
                                  "critical";
                              } else if (
                                score >= 60
                              ) {
                                risk =
                                  "high";
                              } else if (
                                score >= 30
                              ) {
                                risk =
                                  "medium";
                              }

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
                                      Threat
                                      score:{" "}
                                      {score}
                                    </small>

                                  </div>

                                  <span
                                    className={`risk ${risk}`}
                                  >
                                    {formatSeverity(
                                      risk
                                    )}
                                  </span>

                                </div>

                              );
                            }
                          )

                      )}

                    </div>

                  </div>

                  <div className="panel">

                    <div className="panel-header">

                      <div>

                        <h4>
                          Recent Alerts
                        </h4>

                        <p>
                          Latest security
                          detections
                        </p>

                      </div>

                      <button
                        className="text-button"
                        onClick={() =>
                          handleNavigation(
                            "Alerts"
                          )
                        }
                        type="button"
                      >
                        View all
                      </button>

                    </div>

                    <div className="alert-list">

                      {recentAlerts.length === 0 ? (

                        <div className="chart-message">
                          No recent alerts.
                        </div>

                      ) : (

                        recentAlerts
                          .slice(0, 5)
                          .map(
                            (
                              alert,
                              index
                            ) => {

                              const alertSeverity =
                                String(
                                  alert?.severity ||
                                    alert?.level ||
                                    "low"
                                ).toLowerCase();

                              const ip =
                                alert?.ip_address ||
                                alert?.ip ||
                                "Unknown IP";

                              const score =
                                Number(
                                  alert?.score ??
                                    alert?.threat_score ??
                                    alert?.threatlens_score ??
                                    alert?.threatlensScore ??
                                    0
                                );

                              const title =
                                alert?.title ||
                                alert?.message ||
                                alert?.description ||
                                `${formatSeverity(
                                  alertSeverity
                                )} threat detected`;

                              return (

                                <div
                                  className="alert-row"
                                  key={
                                    alert?.id ||
                                    `${ip}-${alert?.created_at || index}`
                                  }
                                >

                                  <div
                                    className={`alert-icon ${alertSeverity}`}
                                  >
                                    ⚠
                                  </div>

                                  <div>

                                    <strong>
                                      {title}
                                    </strong>

                                    <small>
                                      {ip} • Threat
                                      score:{" "}
                                      {score}
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

              </>

            )}

          </section>

        )}

        {/* ==================================================
            THREAT INTELLIGENCE
        ================================================== */}

        {activePage ===
          "Threat Intelligence" && (

          <ThreatIntelligence
            key={threatIntelRefreshKey}
          />

        )}

        {/* ==================================================
            INTELLIGENCE HISTORY
        ================================================== */}

        {activePage ===
          "Intelligence History" && (

          <IntelligenceHistory
            key={historyRefreshKey}
          />

        )}

        {/* ==================================================
            THREAT SCORES
        ================================================== */}

        {activePage ===
          "Threat Scores" && (

          <ThreatScores
            key={threatScoresRefreshKey}
            refreshKey={threatScoresRefreshKey}
          />

        )}

        {/* ==================================================
            ALERTS
        ================================================== */}

        {activePage === "Alerts" && (

          <Alerts
            key={alertsRefreshKey}
            refreshKey={alertsRefreshKey}
          />

        )}

        {/* ==================================================
            INCIDENTS
        ================================================== */}

        {activePage === "Incidents" && (

          <Incidents
            key={incidentsRefreshKey}
            refreshKey={incidentsRefreshKey}
          />

        )}

        {/* ==================================================
            CORRELATION
        ================================================== */}

        {activePage === "Correlation" && (

          <Correlation />

        )}

        {/* ==================================================
            SETTINGS
        ================================================== */}

        {activePage === "Settings" &&
          renderSettings()}

      </main>

      {/* ==================================================
          DASHBOARD SCAN MODAL
      ================================================== */}

      {showScanModal && (

        <div
          className="modal-overlay"
          onMouseDown={(event) => {

            if (
              event.target ===
              event.currentTarget
            ) {
              closeScanModal();
            }

          }}
        >

          <div className="scan-modal">

            {/* MODAL HEADER */}

            <div className="scan-modal-header">

              <div>

                <span className="modal-label">
                  THREAT INTELLIGENCE
                </span>

                <h3>
                  New Threat Scan
                </h3>

                <p>
                  Analyze an IP address
                  using multiple threat
                  intelligence sources.
                </p>

              </div>

              <button
                className="modal-close"
                onClick={closeScanModal}
                disabled={scanLoading}
                aria-label="Close"
                type="button"
              >
                ×
              </button>

            </div>

            {/* ==================================================
                FORM
            ================================================== */}

            {!scanLoading &&
              !scanResult && (

                <form
                  className="scan-form"
                  onSubmit={handleThreatScan}
                >

                  <label htmlFor="scan-ip">
                    IP Address
                  </label>

                  <input
                    id="scan-ip"
                    type="text"
                    value={scanIP}
                    onChange={(event) => {

                      setScanIP(
                        event.target.value
                      );

                      setScanError("");

                    }}
                    placeholder="8.8.8.8"
                    autoComplete="off"
                    spellCheck="false"
                  />

                  <span className="input-hint">
                    Enter a public IPv4
                    address for threat
                    intelligence
                    correlation.
                  </span>

                  {scanError && (

                    <div className="scan-error">
                      {scanError}
                    </div>

                  )}

                  <button
                    type="submit"
                    className="scan-button"
                  >
                    Analyze IP
                  </button>

                </form>

              )}

            {/* ==================================================
                PROGRESS
            ================================================== */}

            {scanLoading && (

              <div className="scan-progress">

                <div className="spinner" />

                <strong>
                  Running Correlation
                  Engine...
                </strong>

                <span>
                  Querying VirusTotal,
                  AbuseIPDB and
                  AlienVault OTX.
                </span>

              </div>

            )}

            {/* ==================================================
                RESULTS
            ================================================== */}

            {!scanLoading &&
              scanResult && (

                <div className="scan-results">

                  {/* SCORE */}

                  <div className="score-card">

                    <div>

                      <span>
                        THREATLENS SCORE
                      </span>

                      <strong>
                        {scanScore}
                      </strong>

                    </div>

                    <span
                      className={`score-severity ${
                        scanSeverity ||
                        "unknown"
                      }`}
                    >
                      {formatSeverity(
                        scanSeverity
                      )}
                    </span>

                  </div>

                  {/* IP */}

                  <div className="result-ip">

                    <span>
                      ANALYZED IP ADDRESS
                    </span>

                    <strong>
                      {scanResult?.analyzed_ip ||
                        scanIP}
                    </strong>

                  </div>

                  {/* SOURCES */}

                  <div className="source-grid">

                    {/* VIRUSTOTAL */}

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
                            scanResult,
                            "VirusTotal"
                          )
                            ? "success"
                            : "warning"
                        }`}
                      >
                        {getSourceStatus(
                          scanResult,
                          "VirusTotal"
                        )
                          ? "Success"
                          : "Unavailable"}
                      </span>

                    </div>

                    {/* ABUSEIPDB */}

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
                            scanResult,
                            "AbuseIPDB"
                          )
                            ? "success"
                            : "warning"
                        }`}
                      >
                        {getSourceStatus(
                          scanResult,
                          "AbuseIPDB"
                        )
                          ? "Success"
                          : "Unavailable"}
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

                      <span
                        className={`source-status ${
                          getSourceStatus(
                            scanResult,
                            "OTX"
                          )
                            ? "success"
                            : "warning"
                        }`}
                      >
                        {getSourceStatus(
                          scanResult,
                          "OTX"
                        )
                          ? "Success"
                          : "Unavailable"}
                      </span>

                    </div>

                  </div>

                  {/* ACTIONS */}

                  <div className="result-actions">

                    <button
                      className="secondary-button"
                      onClick={() => {

                        setScanResult(null);
                        setScanError("");

                      }}
                      type="button"
                    >
                      Scan Another IP
                    </button>

                    <button
                      className="primary-button"
                      onClick={closeScanModal}
                      type="button"
                    >
                      Done
                    </button>

                  </div>

                </div>

              )}

          </div>

        </div>

      )}

    </div>
  );
}

// ==========================================================
// SINGLE DEFAULT EXPORT
// ==========================================================

export default App;