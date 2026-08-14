import { useEffect, useState } from "react";

/* ==========================================================
   ThreatLens - Default Settings
   ========================================================== */

const DEFAULT_SETTINGS = {
  autoRefresh: true,
  refreshInterval: "30",
  notifications: true,
  criticalAlerts: true,
  highAlerts: true,
  soundAlerts: false,
  darkMode: true,
};

/* ==========================================================
   ThreatLens - Settings Component
   ========================================================== */

function Settings() {
  /* ========================================================
     Load Settings
     ======================================================== */

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
        "ThreatLens: Failed to load settings",
        error
      );

      return DEFAULT_SETTINGS;
    }
  });

  /* ========================================================
     Persist Settings
     ======================================================== */

  useEffect(() => {
    try {
      localStorage.setItem(
        "threatlens_settings",
        JSON.stringify(settings)
      );
    } catch (error) {
      console.error(
        "ThreatLens: Failed to save settings",
        error
      );
    }
  }, [settings]);

  /* ========================================================
     Toggle Setting
     ======================================================== */

  const handleChange = (key) => {
    setSettings((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  /* ========================================================
     Refresh Interval
     ======================================================== */

  const handleIntervalChange = (event) => {
    setSettings((prev) => ({
      ...prev,
      refreshInterval: event.target.value,
    }));
  };

  /* ========================================================
     Reset Settings
     ======================================================== */

  const handleReset = () => {
    setSettings(DEFAULT_SETTINGS);
  };

  /* ========================================================
     Render
     ======================================================== */

  return (
    <div className="settings-page">

      {/* ====================================================
          PAGE HEADER
          ==================================================== */}

      <div className="settings-header">
        <div>
          <h3>Settings</h3>

          <p>
            Configure ThreatLens monitoring and notification
            preferences.
          </p>
        </div>
      </div>

      {/* ====================================================
          DASHBOARD SETTINGS
          ==================================================== */}

      <div className="settings-card">

        <div className="settings-card-header">
          <h4>Dashboard Settings</h4>

          <p>
            Control dashboard monitoring behaviour.
          </p>
        </div>

        {/* --------------------------------------------------
            Auto Refresh
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Auto Refresh</strong>

            <p>
              Automatically refresh dashboard threat data.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.autoRefresh ? "active" : ""
            }`}
            onClick={() => handleChange("autoRefresh")}
            aria-label="Toggle auto refresh"
            aria-pressed={settings.autoRefresh}
          >
            <span />
          </button>

        </div>

        {/* --------------------------------------------------
            Refresh Interval
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Refresh Interval</strong>

            <p>
              Choose how frequently ThreatLens refreshes data.
            </p>
          </div>

          <select
            className="settings-select"
            value={settings.refreshInterval}
            onChange={handleIntervalChange}
            disabled={!settings.autoRefresh}
          >
            <option value="15">
              15 seconds
            </option>

            <option value="30">
              30 seconds
            </option>

            <option value="60">
              1 minute
            </option>

            <option value="300">
              5 minutes
            </option>
          </select>

        </div>

        {/* --------------------------------------------------
            Dark Mode
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Dark Mode</strong>

            <p>
              Use the dark SOC monitoring interface.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.darkMode ? "active" : ""
            }`}
            onClick={() => handleChange("darkMode")}
            aria-label="Toggle dark mode"
            aria-pressed={settings.darkMode}
          >
            <span />
          </button>

        </div>

      </div>

      {/* ====================================================
          NOTIFICATION SETTINGS
          ==================================================== */}

      <div className="settings-card">

        <div className="settings-card-header">
          <h4>Notification Settings</h4>

          <p>
            Configure security alert notifications.
          </p>
        </div>

        {/* --------------------------------------------------
            Notifications
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Notifications</strong>

            <p>
              Enable ThreatLens security notifications.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.notifications ? "active" : ""
            }`}
            onClick={() => handleChange("notifications")}
            aria-label="Toggle notifications"
            aria-pressed={settings.notifications}
          >
            <span />
          </button>

        </div>

        {/* --------------------------------------------------
            Critical Alerts
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Critical Alerts</strong>

            <p>
              Receive notifications for critical threats.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.criticalAlerts ? "active" : ""
            }`}
            onClick={() => handleChange("criticalAlerts")}
            disabled={!settings.notifications}
            aria-label="Toggle critical alerts"
            aria-pressed={settings.criticalAlerts}
          >
            <span />
          </button>

        </div>

        {/* --------------------------------------------------
            High Severity Alerts
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>
              High Severity Alerts
            </strong>

            <p>
              Receive notifications for high severity threats.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.highAlerts ? "active" : ""
            }`}
            onClick={() => handleChange("highAlerts")}
            disabled={!settings.notifications}
            aria-label="Toggle high severity alerts"
            aria-pressed={settings.highAlerts}
          >
            <span />
          </button>

        </div>

        {/* --------------------------------------------------
            Sound Alerts
            -------------------------------------------------- */}

        <div className="setting-row">

          <div className="setting-info">
            <strong>Sound Alerts</strong>

            <p>
              Play a sound when a new security alert is detected.
            </p>
          </div>

          <button
            type="button"
            className={`settings-toggle ${
              settings.soundAlerts ? "active" : ""
            }`}
            onClick={() => handleChange("soundAlerts")}
            disabled={!settings.notifications}
            aria-label="Toggle sound alerts"
            aria-pressed={settings.soundAlerts}
          >
            <span />
          </button>

        </div>

      </div>

      {/* ====================================================
          SYSTEM INFORMATION
          ==================================================== */}

      <div className="settings-card">

        <div className="settings-card-header">
          <h4>System Information</h4>

          <p>
            ThreatLens platform information.
          </p>
        </div>

        <div className="settings-info-grid">

          {/* Platform */}

          <div className="settings-info-item">
            <span>Platform</span>
            <strong>
              ThreatLens
            </strong>
          </div>

          {/* Environment */}

          <div className="settings-info-item">
            <span>Environment</span>
            <strong>
              Development
            </strong>
          </div>

          {/* Backend */}

          <div className="settings-info-item">
            <span>Backend</span>
            <strong>
              FastAPI
            </strong>
          </div>

          {/* Database */}

          <div className="settings-info-item">
            <span>Database</span>
            <strong>
              PostgreSQL
            </strong>
          </div>

          {/* Threat Intelligence */}

          <div className="settings-info-item">
            <span>Threat Intelligence</span>

            <strong>
              VirusTotal + AbuseIPDB + OTX
            </strong>
          </div>

          {/* Correlation Engine */}

          <div className="settings-info-item">
            <span>Threat Correlation</span>

            <strong>
              ThreatLens Correlation Engine
            </strong>
          </div>

        </div>

      </div>

      {/* ====================================================
          RESET SETTINGS
          ==================================================== */}

      <div className="settings-card settings-reset-card">

        <div className="settings-card-header">
          <h4>Reset Settings</h4>

          <p>
            Restore all ThreatLens settings to their defaults.
          </p>
        </div>

        <button
          type="button"
          className="settings-reset-button"
          onClick={handleReset}
        >
          Reset to Defaults
        </button>

      </div>

    </div>
  );
}

export default Settings;