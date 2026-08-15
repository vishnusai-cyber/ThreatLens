import { useEffect, useMemo, useState } from "react";

import {
  getDashboardOverview,
  getSeverityDistribution,
  getTopThreatIPs,
  getRecentAlerts,
  getThreatTrends,
  correlateIP,
  loginUser,
  registerUser,
  getCurrentUser,
  getAuthToken,
  logoutUser,
} from "./api";

import ThreatIntelligence from "./components/ThreatIntelligence";
import IntelligenceHistory from "./components/IntelligenceHistory";
import ThreatScores from "./components/ThreatScores";
import Alerts from "./components/Alerts";
import Incidents from "./components/Incidents";
import Correlation from "./components/Correlation";

import "./index.css";

// ==========================================================
// ThreatLens - Default Settings
// ==========================================================

const DEFAULT_SETTINGS = {
  realtimeMonitoring: true,
  automaticCorrelation: true,
  alertNotifications: true,
  soundNotifications: false,
  darkMode: true,
  autoRefresh: true,
  refreshInterval: "30",
};

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
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);

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
  // Authentication
  // ========================================================

  const [authLoading, setAuthLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);

  const [authMode, setAuthMode] = useState("login");

  // ========================================================
  // Login
  // ========================================================

  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState("");

  // ========================================================
  // Register
  // ========================================================

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] =
    useState("");
  const [registerLoading, setRegisterLoading] = useState(false);
  const [registerError, setRegisterError] = useState("");
  const [registerSuccess, setRegisterSuccess] = useState("");

  // ========================================================
  // Profile
  // ========================================================

  const [profileMenuOpen, setProfileMenuOpen] = useState(false);

  // ========================================================
  // Settings
  // ========================================================

  const [settings, setSettings] = useState(() => {
    try {
      const savedSettings = localStorage.getItem(
        "threatlens_settings"
      );

      if (savedSettings) {
        return {
          ...DEFAULT_SETTINGS,
          ...JSON.parse(savedSettings),
        };
      }

      return DEFAULT_SETTINGS;
    } catch (error) {
      console.error(
        "ThreatLens: Failed to load settings:",
        error
      );

      return DEFAULT_SETTINGS;
    }
  });

  // ========================================================
  // Persist Settings
  // ========================================================

  useEffect(() => {
    try {
      localStorage.setItem(
        "threatlens_settings",
        JSON.stringify(settings)
      );
    } catch (error) {
      console.error(
        "ThreatLens: Failed to save settings:",
        error
      );
    }
  }, [settings]);

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
  // Authentication Verification
  // ========================================================

  useEffect(() => {
    let mounted = true;

    async function verifyAuthentication() {
      const token = getAuthToken();

      if (!token) {
        if (mounted) {
          setIsAuthenticated(false);
          setCurrentUser(null);
          setAuthLoading(false);
        }

        return;
      }

      try {
        const user = await getCurrentUser(token);

        if (!mounted) {
          return;
        }

        setCurrentUser(user);
        setIsAuthenticated(true);
      } catch (error) {
        console.error(
          "ThreatLens authentication verification failed:",
          error
        );

        logoutUser();

        if (mounted) {
          setIsAuthenticated(false);
          setCurrentUser(null);
        }
      } finally {
        if (mounted) {
          setAuthLoading(false);
        }
      }
    }

    verifyAuthentication();

    return () => {
      mounted = false;
    };
  }, []);

  // ========================================================
  // Login
  // ========================================================

  async function handleLogin(event) {
    event.preventDefault();

    setLoginError("");
    setRegisterSuccess("");

    const email = loginEmail.trim();

    if (!email) {
      setLoginError("Email is required.");
      return;
    }

    if (!loginPassword) {
      setLoginError("Password is required.");
      return;
    }

    setLoginLoading(true);

    try {
      const loginResponse = await loginUser(
        email,
        loginPassword
      );

      const token = loginResponse?.access_token;

      if (!token) {
        throw new Error(
          "Authentication token was not returned by the server."
        );
      }

      const user = await getCurrentUser(token);

      setCurrentUser(user);
      setIsAuthenticated(true);
      setLoginPassword("");
      setLoginError("");
      setActivePage("Dashboard");

      await loadDashboard(false);
    } catch (error) {
      console.error("ThreatLens login failed:", error);

      logoutUser();

      setIsAuthenticated(false);
      setCurrentUser(null);

      setLoginError(
        error?.message ||
          "Unable to login. Please verify your credentials."
      );
    } finally {
      setLoginLoading(false);
    }
  }

  // ========================================================
  // Register
  // ========================================================

  async function handleRegister(event) {
    event.preventDefault();

    setRegisterError("");
    setRegisterSuccess("");

    const username = registerUsername.trim();
    const email = registerEmail.trim();

    if (!username) {
      setRegisterError("Username is required.");
      return;
    }

    if (!email) {
      setRegisterError("Email is required.");
      return;
    }

    if (!registerPassword) {
      setRegisterError("Password is required.");
      return;
    }

    if (registerPassword.length < 6) {
      setRegisterError(
        "Password must be at least 6 characters."
      );
      return;
    }

    if (registerPassword !== registerConfirmPassword) {
      setRegisterError("Passwords do not match.");
      return;
    }

    setRegisterLoading(true);

    try {
      await registerUser({
        username,
        email,
        password: registerPassword,
        role: "viewer",
      });

      setRegisterUsername("");
      setRegisterEmail("");
      setRegisterPassword("");
      setRegisterConfirmPassword("");

      setRegisterSuccess(
        "Account created successfully. You can now sign in."
      );

      setAuthMode("login");
      setLoginEmail(email);
      setLoginPassword("");
      setLoginError("");
    } catch (error) {
      console.error(
        "ThreatLens registration failed:",
        error
      );

      setRegisterError(
        error?.message ||
          "Unable to create account. Please try again."
      );
    } finally {
      setRegisterLoading(false);
    }
  }

  // ========================================================
  // Logout
  // ========================================================

  function handleLogout() {
    logoutUser();

    setIsAuthenticated(false);
    setCurrentUser(null);
    setProfileMenuOpen(false);
    setActivePage("Dashboard");

    setOverview(null);
    setSeverity([]);
    setTopIPs([]);
    setRecentAlerts([]);
    setTrends([]);

    setLastDashboardRefresh(null);

    setLoginEmail("");
    setLoginPassword("");
    setLoginError("");

    setAuthMode("login");

    setRegisterUsername("");
    setRegisterEmail("");
    setRegisterPassword("");
    setRegisterConfirmPassword("");
    setRegisterError("");
    setRegisterSuccess("");
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

      setOverview(overviewData);
      setSeverity(normalizeArray(severityData));
      setTopIPs(normalizeArray(topIPsData));
      setRecentAlerts(normalizeArray(recentAlertsData));
      setTrends(
        normalizeArray(trendsData, ["trends"])
      );

      setLastDashboardRefresh(
        new Date().toLocaleTimeString()
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
    if (!isAuthenticated) {
      return;
    }

    loadDashboard(false).catch(() => {});
  }, [isAuthenticated]);

  // ========================================================
  // Automatic Dashboard Refresh
  // ========================================================

  useEffect(() => {
    if (
      !isAuthenticated ||
      !settings.autoRefresh
    ) {
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

    return () => {
      clearInterval(interval);
    };
  }, [
    isAuthenticated,
    settings.autoRefresh,
    settings.refreshInterval,
    activePage,
  ]);

  // ========================================================
  // Settings
  // ========================================================

  function toggleSetting(settingName) {
    setSettings((previous) => ({
      ...previous,
      [settingName]: !previous[settingName],
    }));
  }

  function updateSetting(settingName, value) {
    setSettings((previous) => ({
      ...previous,
      [settingName]: value,
    }));
  }

  function resetSettings() {
    setSettings(DEFAULT_SETTINGS);

    try {
      localStorage.setItem(
        "threatlens_settings",
        JSON.stringify(DEFAULT_SETTINGS)
      );
    } catch (error) {
      console.error(
        "ThreatLens: Failed to reset settings:",
        error
      );
    }
  }

  // ========================================================
  // Scan Modal
  // ========================================================

  function openScanModal() {
    setShowScanModal(true);
    setScanIP("");
    setScanError("");
    setScanResult(null);
  }

  function closeScanModal() {
    if (scanLoading) {
      return;
    }

    setShowScanModal(false);
    setScanIP("");
    setScanError("");
    setScanResult(null);
  }

  function isValidIPv4(ip) {
    const ipv4Regex =
      /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    return ipv4Regex.test(ip.trim());
  }

  // ========================================================
  // Threat Score
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
  // Severity
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

    const sourceLower = String(source).toLowerCase();

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

    const sourceText = JSON.stringify(
      result
    ).toLowerCase();

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
  // Post Scan Refresh
  // ========================================================

  async function refreshEverythingAfterScan() {
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

      const result = await correlateIP(ip);

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
        const severityName = String(
          item?.severity || ""
        ).toLowerCase();

        const count = Number(
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
    }

    return result;
  }, [severity]);

  // ========================================================
  // Threat Chart
  // ========================================================

  const chartData = useMemo(() => {
    if (!Array.isArray(trends)) {
      return [];
    }

    return trends.slice(-7).map(
      (item, index) => {
        const value = Number(
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
          value: Number.isFinite(value)
            ? value
            : 0,
          date,
        };
      }
    );
  }, [trends]);

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
      loadDashboard(true).catch(() => {});
    }
  }

  function handleSearchClick() {
    openScanModal();
  }

  function handleNotificationClick() {
    handleNavigation("Alerts");
  }

  function handleProfileClick() {
    setProfileMenuOpen(
      (previous) => !previous
    );
  }

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
  // Settings Page
  // ========================================================

  function renderSettings() {
    return (
      <section className="settings-page">
        <div className="settings-header">
          <h3>Settings</h3>

          <p>
            Configure ThreatLens monitoring,
            notifications and system preferences.
          </p>
        </div>

        <div className="settings-card">
          <div className="settings-card-header">
            <h4>Monitoring</h4>

            <p>
              Configure real-time threat monitoring
              behaviour.
            </p>
          </div>

          <div className="setting-row">
            <div className="setting-info">
              <strong>
                Real-time Monitoring
              </strong>

              <p>
                Continuously monitor incoming threat
                intelligence events.
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
              aria-pressed={
                settings.realtimeMonitoring
              }
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
              aria-pressed={
                settings.automaticCorrelation
              }
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
              aria-pressed={
                settings.autoRefresh
              }
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
                Select how frequently the dashboard
                updates.
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

        <div className="settings-card">
          <div className="settings-card-header">
            <h4>Notifications</h4>

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
                Receive notifications when High or
                Critical alerts are generated.
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
              aria-pressed={
                settings.alertNotifications
              }
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
                Play a sound when a new alert is
                detected.
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
              aria-pressed={
                settings.soundNotifications
              }
            >
              <span />
            </button>
          </div>
        </div>

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
                toggleSetting("darkMode")
              }
              type="button"
              aria-pressed={
                settings.darkMode
              }
            >
              <span />
            </button>
          </div>
        </div>

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
              <span>PLATFORM</span>

              <strong>
                ThreatLens SOC
              </strong>
            </div>

            <div className="settings-info-item">
              <span>ENVIRONMENT</span>

              <strong>
                Development
              </strong>
            </div>

            <div className="settings-info-item">
              <span>BACKEND</span>

              <strong>
                FastAPI
              </strong>
            </div>

            <div className="settings-info-item">
              <span>DATABASE</span>

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

        <div className="settings-card settings-reset-card">
          <div className="settings-card-header">
            <h4>Reset Settings</h4>

            <p>
              Restore all ThreatLens settings to their
              default values.
            </p>
          </div>

          <button
            type="button"
            className="settings-reset-button"
            onClick={resetSettings}
          >
            Reset to Defaults
          </button>
        </div>
      </section>
    );
  }

  // ========================================================
  // Authentication Loading
  // ========================================================

  if (authLoading) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="auth-logo">
            T
          </div>

          <h1>ThreatLens</h1>

          <p>
            Verifying authentication...
          </p>
        </div>
      </div>
    );
  }

  // ========================================================
  // Login
  // ========================================================

  if (!isAuthenticated && authMode === "login") {
    return (
      <div className="auth-screen">
        <form
          className="auth-card"
          onSubmit={handleLogin}
        >
          <div className="auth-brand">
            <div className="auth-logo">
              T
            </div>

            <div className="auth-brand-text">
              <h1>ThreatLens</h1>

              <span>
                Security Operations Platform
              </span>
            </div>
          </div>

          <div className="auth-heading">
            <h2>Welcome back</h2>
          </div>

          <div className="auth-field">
            <label htmlFor="login-email">
              Email
            </label>

            <input
              id="login-email"
              type="email"
              value={loginEmail}
              onChange={(event) => {
                setLoginEmail(
                  event.target.value
                );

                setLoginError("");
              }}
              autoComplete="email"
              placeholder="Enter your email"
              disabled={loginLoading}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="login-password">
              Password
            </label>

            <input
              id="login-password"
              type="password"
              value={loginPassword}
              onChange={(event) => {
                setLoginPassword(
                  event.target.value
                );

                setLoginError("");
              }}
              autoComplete="current-password"
              placeholder="Enter your password"
              disabled={loginLoading}
            />
          </div>

          {registerSuccess && (
            <div className="auth-success">
              {registerSuccess}
            </div>
          )}

          {loginError && (
            <div className="auth-error">
              {loginError}
            </div>
          )}

          <button
            type="submit"
            className="primary-button auth-submit"
            disabled={loginLoading}
          >
            {loginLoading
              ? "Signing in..."
              : "Sign In"}
          </button>

          <div className="auth-switch">
            <span>
              Do not have an account?
            </span>

            <button
              type="button"
              className="auth-link"
              onClick={() => {
                setAuthMode("register");
                setLoginError("");
                setRegisterError("");
                setRegisterSuccess("");
              }}
              disabled={loginLoading}
            >
              Sign Up
            </button>
          </div>
        </form>
      </div>
    );
  }

  // ========================================================
  // Register
  // ========================================================

  if (!isAuthenticated && authMode === "register") {
    return (
      <div className="auth-screen">
        <form
          className="auth-card register-card"
          onSubmit={handleRegister}
        >
          <div className="auth-brand">
            <div className="auth-logo">
              T
            </div>

            <div className="auth-brand-text">
              <h1>ThreatLens</h1>

              <span>
                Security Operations Platform
              </span>
            </div>
          </div>

          <div className="auth-heading">
            <h2>
              Create your account
            </h2>

            <p>
              Create a secure account to access
              ThreatLens.
            </p>
          </div>

          <div className="auth-field">
            <label htmlFor="register-username">
              Username
            </label>

            <input
              id="register-username"
              type="text"
              value={registerUsername}
              onChange={(event) => {
                setRegisterUsername(
                  event.target.value
                );

                setRegisterError("");
              }}
              autoComplete="username"
              placeholder="Create username"
              disabled={registerLoading}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="register-email">
              Email
            </label>

            <input
              id="register-email"
              type="email"
              value={registerEmail}
              onChange={(event) => {
                setRegisterEmail(
                  event.target.value
                );

                setRegisterError("");
              }}
              autoComplete="email"
              placeholder="Enter email address"
              disabled={registerLoading}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="register-password">
              Password
            </label>

            <input
              id="register-password"
              type="password"
              value={registerPassword}
              onChange={(event) => {
                setRegisterPassword(
                  event.target.value
                );

                setRegisterError("");
              }}
              autoComplete="new-password"
              placeholder="Create password"
              disabled={registerLoading}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="register-confirm-password">
              Confirm Password
            </label>

            <input
              id="register-confirm-password"
              type="password"
              value={registerConfirmPassword}
              onChange={(event) => {
                setRegisterConfirmPassword(
                  event.target.value
                );

                setRegisterError("");
              }}
              autoComplete="new-password"
              placeholder="Confirm password"
              disabled={registerLoading}
            />
          </div>

          {registerError && (
            <div className="auth-error">
              {registerError}
            </div>
          )}

          <button
            type="submit"
            className="primary-button auth-submit"
            disabled={registerLoading}
          >
            {registerLoading
              ? "Creating account..."
              : "Create Account"}
          </button>

          <div className="auth-switch">
            <span>
              Already have an account?
            </span>

            <button
              type="button"
              className="auth-link"
              onClick={() => {
                setAuthMode("login");
                setRegisterError("");
                setRegisterSuccess("");
              }}
              disabled={registerLoading}
            >
              Sign In
            </button>
          </div>
        </form>
      </div>
    );
  }

  // ========================================================
  // MAIN APPLICATION
  // ========================================================

  return (
    <div className="app">

      {/* ==================================================
          SIDEBAR
      ================================================== */}

      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">
            T
          </div>

          <div>
            <h1>ThreatLens</h1>

            <span>
              SOC Platform
            </span>
          </div>
        </div>

        <nav className="navigation">

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
                handleNavigation("Dashboard")
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
                handleNavigation("Alerts")
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
                handleNavigation("Incidents")
              }
              type="button"
            >
              <span>◇</span>
              Incidents
            </button>
          </div>

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
                activePage ===
                "Threat Scores"
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
                handleNavigation("Settings")
              }
              type="button"
            >
              <span>⚙</span>
              Settings
            </button>
          </div>
        </nav>

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
          <div className="topbar-title">
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
              title="Search / New Threat Scan"
              onClick={handleSearchClick}
              type="button"
            >
              ⌕
            </button>

            <button
              className="icon-button notification-button"
              title="View Alerts"
              onClick={
                handleNotificationClick
              }
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

            <div className="topbar-separator" />

            <div className="profile-menu-wrapper">
              <button
                className="profile profile-button"
                title="Open account menu"
                onClick={handleProfileClick}
                type="button"
                aria-expanded={
                  profileMenuOpen
                }
              >
                <div className="avatar">
                  {currentUser?.username
                    ? currentUser.username
                        .charAt(0)
                        .toUpperCase()
                    : "A"}
                </div>

                <div className="profile-details">
                  <strong>
                    {currentUser?.username ||
                      "Administrator"}
                  </strong>

                  <small>
                    {currentUser?.role ||
                      "Admin"}
                  </small>
                </div>

                <span className="profile-arrow">
                  ▾
                </span>
              </button>

              {profileMenuOpen && (
                <div className="profile-dropdown">

                  <div className="profile-dropdown-header">
                    <strong>
                      {currentUser?.username ||
                        "Administrator"}
                    </strong>

                    <small>
                      {currentUser?.role ||
                        "Admin"}
                    </small>
                  </div>

                  <button
                    type="button"
                    className="profile-dropdown-item"
                    onClick={() => {
                      setProfileMenuOpen(false);

                      handleNavigation(
                        "Settings"
                      );
                    }}
                  >
                    ⚙ Settings
                  </button>

                  <button
                    type="button"
                    className="profile-dropdown-item logout-item"
                    onClick={handleLogout}
                  >
                    ↪ Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* ==================================================
            DASHBOARD
        ================================================== */}

        {activePage === "Dashboard" && (
          <section className="dashboard">

            <div className="page-heading">
              <div>
                <h3>Dashboard</h3>

                <p>
                  Monitor your threat landscape
                  and security posture.
                </p>
              </div>

              <div className="heading-actions">

                <button
                  className="secondary-button"
                  onClick={() =>
                    loadDashboard(true).catch(
                      () => {}
                    )
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
              <div className="dashboard-last-refresh">
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

                {/* ==================================================
                    STATISTICS
                ================================================== */}

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

                {/* ==================================================
                    CHART + SEVERITY
                ================================================== */}

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

                      {chartData.length ===
                      0 ? (
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
                                  (item.value /
                                    maxChartValue) *
                                    80,
                                  item.value >
                                    0
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
                          {
                            severityStats.critical
                          }
                        </strong>
                      </div>

                      <div className="severity-item">
                        <div>
                          <span className="severity-dot high" />
                          High
                        </div>

                        <strong>
                          {
                            severityStats.high
                          }
                        </strong>
                      </div>

                      <div className="severity-item">
                        <div>
                          <span className="severity-dot medium" />
                          Medium
                        </div>

                        <strong>
                          {
                            severityStats.medium
                          }
                        </strong>
                      </div>

                      <div className="severity-item">
                        <div>
                          <span className="severity-dot low" />
                          Low
                        </div>

                        <strong>
                          {
                            severityStats.low
                          }
                        </strong>
                      </div>

                    </div>
                  </div>
                </div>

                {/* ==================================================
                    TOP IPS + ALERTS
                ================================================== */}

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

                      {topIPs.length ===
                      0 ? (
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
                                score >=
                                80
                              ) {
                                risk =
                                  "critical";
                              } else if (
                                score >=
                                60
                              ) {
                                risk =
                                  "high";
                              } else if (
                                score >=
                                30
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
                                      {
                                        score
                                      }
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

                      {recentAlerts.length ===
                      0 ? (
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
                                      {
                                        score
                                      }
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
            refreshKey={
              threatScoresRefreshKey
            }
          />
        )}

        {/* ==================================================
            ALERTS
        ================================================== */}

        {activePage === "Alerts" && (
          <Alerts
            key={alertsRefreshKey}
            refreshKey={
              alertsRefreshKey
            }
          />
        )}

        {/* ==================================================
            INCIDENTS
        ================================================== */}

        {activePage === "Incidents" && (
          <Incidents
            key={incidentsRefreshKey}
            refreshKey={
              incidentsRefreshKey
            }
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
          SCAN MODAL
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

            <div className="scan-modal-header">

              <div>
                <span className="modal-label">
                  THREAT INTELLIGENCE
                </span>

                <h3>
                  New Threat Scan
                </h3>

                <p>
                  Analyze an IP address using
                  multiple threat intelligence
                  sources.
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

            {!scanLoading &&
              !scanResult && (
                <form
                  className="scan-form"
                  onSubmit={
                    handleThreatScan
                  }
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
                    Enter a public IPv4 address
                    for threat intelligence
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

            {scanLoading && (
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
            )}

            {!scanLoading &&
              scanResult && (
                <div className="scan-results">

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

                  <div className="result-ip">

                    <span>
                      ANALYZED IP ADDRESS
                    </span>

                    <strong>
                      {scanResult?.analyzed_ip ||
                        scanIP}
                    </strong>
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
                      onClick={
                        closeScanModal
                      }
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