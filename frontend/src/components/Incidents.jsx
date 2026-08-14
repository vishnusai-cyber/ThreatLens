import { useEffect, useState } from "react";

import {
  getIncidents,
  createIncident,
  updateIncident,
  deleteIncident,
  getIncidentStats,
  getIncidentIntelligence,
  getIncidentScore,
} from "../api";

import "../index.css";

// ==========================================================
// ThreatLens - Incidents
// ==========================================================

function Incidents({ refreshKey = 0 }) {
  // ========================================================
  // State
  // ========================================================

  const [incidents, setIncidents] = useState([]);

  const [stats, setStats] = useState({
    total: 0,
    open: 0,
    investigating: 0,
    resolved: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [creating, setCreating] = useState(false);

  const [error, setError] = useState("");

  const [selectedIncident, setSelectedIncident] =
    useState(null);

  const [intelligence, setIntelligence] = useState([]);

  const [incidentScore, setIncidentScore] =
    useState(null);

  const [loadingIntelligence, setLoadingIntelligence] =
    useState(false);

  const [loadingScore, setLoadingScore] =
    useState(false);

  const [scoreError, setScoreError] =
    useState("");

  // ========================================================
  // Create Form
  // ========================================================

  const [form, setForm] = useState({
    title: "",
    description: "",
    severity: "medium",
    status: "open",
    ip_address: "",
  });

  // ========================================================
  // Normalize Array
  // ========================================================

  function normalizeArray(data, extraKeys = []) {
    if (Array.isArray(data)) {
      return data;
    }

    if (!data || typeof data !== "object") {
      return [];
    }

    const possibleKeys = [
      "data",
      "items",
      "results",
      "incidents",
      "intelligence",
      ...extraKeys,
    ];

    for (const key of possibleKeys) {
      if (Array.isArray(data[key])) {
        return data[key];
      }
    }

    return [];
  }

  // ========================================================
  // Safe Number
  // ========================================================

  function safeNumber(value) {
    const number = Number(value);

    return Number.isFinite(number) ? number : 0;
  }

  // ========================================================
  // Normalize Incident ID
  //
  // IMPORTANT:
  // FastAPI expects incident_id to be an INTEGER.
  // ========================================================

  function normalizeIncidentId(value) {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return null;
    }

    const numericId = Number(value);

    if (
      !Number.isInteger(numericId) ||
      numericId <= 0
    ) {
      return null;
    }

    return numericId;
  }

  // ========================================================
  // Normalize Severity
  // ========================================================

  function normalizeSeverity(value) {
    const severity = String(value || "medium")
      .trim()
      .toLowerCase();

    if (
      [
        "critical",
        "high",
        "medium",
        "low",
      ].includes(severity)
    ) {
      return severity;
    }

    return "medium";
  }

  // ========================================================
  // Normalize Status
  // ========================================================

  function normalizeStatus(value) {
    const status = String(value || "open")
      .trim()
      .toLowerCase();

    if (
      [
        "open",
        "investigating",
        "resolved",
      ].includes(status)
    ) {
      return status;
    }

    return "open";
  }

  // ========================================================
  // Normalize Incident
  // ========================================================

  function normalizeIncident(incident) {
    if (
      !incident ||
      typeof incident !== "object"
    ) {
      return null;
    }

    const id = normalizeIncidentId(
      incident.id
    );

    if (id === null) {
      console.warn(
        "ThreatLens: Ignoring incident with invalid ID:",
        incident
      );

      return null;
    }

    return {
      ...incident,

      id,

      title:
        incident.title
          ?.toString()
          .trim() ||
        "Untitled Incident",

      description:
        incident.description
          ?.toString()
          .trim() || "",

      ip_address:
        incident.ip_address
          ?.toString()
          .trim() || "",

      severity:
        normalizeSeverity(
          incident.severity
        ),

      status:
        normalizeStatus(
          incident.status
        ),
    };
  }

  // ========================================================
  // Load Incidents
  // ========================================================

  async function loadIncidents() {
    console.log(
      "ThreatLens Incidents: Loading incidents..."
    );

    const data = await getIncidents(
      0,
      100
    );

    console.log(
      "ThreatLens Incidents: API response:",
      data
    );

    const normalized =
      normalizeArray(data)
        .map(normalizeIncident)
        .filter(Boolean);

    setIncidents(normalized);

    console.log(
      "ThreatLens Incidents: Normalized incidents:",
      normalized
    );

    return normalized;
  }

  // ========================================================
  // Load Statistics
  // ========================================================

  async function loadStats() {
    console.log(
      "ThreatLens Incidents: Loading statistics..."
    );

    const data =
      await getIncidentStats();

    console.log(
      "ThreatLens Incidents: Statistics response:",
      data
    );

    const source =
      data?.data ||
      data?.statistics ||
      data ||
      {};

    const normalizedStats = {
      total: safeNumber(
        source.total ??
          source.total_incidents
      ),

      open: safeNumber(
        source.open ??
          source.open_incidents
      ),

      investigating: safeNumber(
        source.investigating ??
          source.investigating_incidents
      ),

      resolved: safeNumber(
        source.resolved ??
          source.resolved_incidents
      ),

      critical: safeNumber(
        source.critical ??
          source.critical_incidents
      ),

      high: safeNumber(
        source.high ??
          source.high_incidents
      ),

      medium: safeNumber(
        source.medium ??
          source.medium_incidents
      ),

      low: safeNumber(
        source.low ??
          source.low_incidents
      ),
    };

    setStats(normalizedStats);

    console.log(
      "ThreatLens Incidents: Normalized statistics:",
      normalizedStats
    );

    return normalizedStats;
  }

  // ========================================================
  // Refresh Incidents
  // ========================================================

  async function refreshIncidents(
    showRefresh = false
  ) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      console.log(
        "=============================================="
      );

      console.log(
        "ThreatLens: Refreshing incidents..."
      );

      const results =
        await Promise.allSettled([
          loadIncidents(),
          loadStats(),
        ]);

      const failed =
        results.find(
          (result) =>
            result.status ===
            "rejected"
        );

      if (failed) {
        throw failed.reason;
      }

      console.log(
        "ThreatLens: Incident refresh completed."
      );

      console.log(
        "=============================================="
      );
    } catch (err) {
      console.error(
        "ThreatLens incident refresh error:",
        err
      );

      setError(
        err?.message ||
          "Failed to load incident data."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial Load + Dashboard Refresh
  // ========================================================

  useEffect(() => {
    console.log(
      "ThreatLens Incidents: refreshKey:",
      refreshKey
    );

    refreshIncidents(
      refreshKey !== 0
    );

    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  // ========================================================
  // Form Change
  // ========================================================

  function handleChange(event) {
    const {
      name,
      value,
    } = event.target;

    setForm(
      (previous) => ({
        ...previous,
        [name]: value,
      })
    );

    setError("");
  }

  // ========================================================
  // Create Incident
  // ========================================================

  async function handleCreateIncident(
    event
  ) {
    event.preventDefault();

    const title =
      form.title.trim();

    if (!title) {
      setError(
        "Incident title is required."
      );

      return;
    }

    try {
      setCreating(true);
      setError("");

      const payload = {
        title,

        description:
          form.description.trim() ||
          null,

        severity:
          normalizeSeverity(
            form.severity
          ),

        status:
          normalizeStatus(
            form.status
          ),

        ip_address:
          form.ip_address.trim() ||
          null,
      };

      console.log(
        "ThreatLens: Creating incident:",
        payload
      );

      await createIncident(
        payload
      );

      console.log(
        "ThreatLens: Incident created successfully."
      );

      setForm({
        title: "",
        description: "",
        severity: "medium",
        status: "open",
        ip_address: "",
      });

      await refreshIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens CREATE INCIDENT ERROR:",
        err
      );

      setError(
        err?.message ||
          "Failed to create incident."
      );
    } finally {
      setCreating(false);
    }
  }

  // ========================================================
  // Update Status
  // ========================================================

  async function handleStatusChange(
    incident,
    newStatus
  ) {
    const incidentId =
      normalizeIncidentId(
        incident?.id
      );

    if (incidentId === null) {
      setError(
        "Invalid incident ID."
      );

      console.error(
        "ThreatLens: Invalid incident ID:",
        incident?.id
      );

      return;
    }

    const currentStatus =
      normalizeStatus(
        incident.status
      );

    const normalizedStatus =
      normalizeStatus(
        newStatus
      );

    if (
      currentStatus ===
      normalizedStatus
    ) {
      return;
    }

    try {
      setError("");

      console.log(
        "ThreatLens: Updating incident:",
        {
          incidentId,
          status:
            normalizedStatus,
        }
      );

      await updateIncident(
        incidentId,
        {
          status:
            normalizedStatus,
        }
      );

      if (
        selectedIncident?.id ===
        incidentId
      ) {
        setSelectedIncident(
          (previous) =>
            previous
              ? {
                  ...previous,
                  status:
                    normalizedStatus,
                }
              : null
        );
      }

      await refreshIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens UPDATE INCIDENT ERROR:",
        err
      );

      setError(
        err?.message ||
          "Failed to update incident."
      );
    }
  }

  // ========================================================
  // Delete Incident
  // ========================================================

  async function handleDeleteIncident(
    incident
  ) {
    const incidentId =
      normalizeIncidentId(
        incident?.id
      );

    if (incidentId === null) {
      setError(
        "Invalid incident ID."
      );

      return;
    }

    const confirmed =
      window.confirm(
        `Delete incident "${incident.title}"?`
      );

    if (!confirmed) {
      return;
    }

    try {
      setError("");

      console.log(
        "ThreatLens: Deleting incident:",
        incidentId
      );

      await deleteIncident(
        incidentId
      );

      if (
        selectedIncident?.id ===
        incidentId
      ) {
        setSelectedIncident(
          null
        );

        setIntelligence([]);

        setIncidentScore(null);

        setScoreError("");
      }

      await refreshIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens DELETE INCIDENT ERROR:",
        err
      );

      setError(
        err?.message ||
          "Failed to delete incident."
      );
    }
  }

  // ========================================================
  // Normalize Incident Score
  // ========================================================

  function normalizeIncidentScore(data) {
    if (
      data === null ||
      data === undefined
    ) {
      return null;
    }

    // Direct numeric response
    if (
      typeof data === "number" ||
      typeof data === "string"
    ) {
      const value = Number(data);

      return Number.isFinite(value)
        ? value
        : null;
    }

    if (
      typeof data !== "object"
    ) {
      return null;
    }

    const candidates = [
      data.threatlens_score,
      data.threatlensScore,
      data.threat_score,
      data.threatScore,
      data.score,
      data.total_score,
      data.overall_score,
      data.value,

      data.data?.threatlens_score,
      data.data?.threat_score,
      data.data?.score,
      data.data?.overall_score,

      data.score?.threatlens_score,
      data.score?.threat_score,
      data.score?.score,
      data.score?.overall_score,
    ];

    for (const candidate of candidates) {
      const value = Number(candidate);

      if (Number.isFinite(value)) {
        return value;
      }
    }

    return null;
  }

  // ========================================================
  // Normalize Score Response
  // ========================================================

  function normalizeScoreResponse(data) {
    if (
      !data ||
      typeof data !== "object"
    ) {
      return {
        score: normalizeIncidentScore(data),
        severity: null,
        sources: [],
        raw: data,
      };
    }

    const score =
      normalizeIncidentScore(data);

    const severity =
      normalizeSeverity(
        data.severity ||
          data.threat_severity ||
          data.data?.severity ||
          data.score?.severity ||
          selectedIncident?.severity
      );

    const possibleSources =
      data.sources ||
      data.intelligence_sources ||
      data.sources_used ||
      data.data?.sources ||
      data.data?.intelligence_sources ||
      data.score?.sources ||
      [];

    let sources = [];

    if (Array.isArray(possibleSources)) {
      sources = possibleSources
        .map((source) => {
          if (
            typeof source === "string"
          ) {
            return source;
          }

          if (
            source &&
            typeof source === "object"
          ) {
            return (
              source.source ||
              source.name ||
              source.provider ||
              source.type ||
              null
            );
          }

          return null;
        })
        .filter(Boolean);
    }

    return {
      score,
      severity,
      sources,
      raw: data,
    };
  }

  // ========================================================
  // Build Source List From Intelligence
  // ========================================================

  function getIntelligenceSources(
    items
  ) {
    if (!Array.isArray(items)) {
      return [];
    }

    const sources =
      items
        .map(
          (item) =>
            item?.source ||
            item?.provider ||
            item?.source_name ||
            null
        )
        .filter(Boolean);

    return [
      ...new Set(sources),
    ];
  }

  // ========================================================
  // View Intelligence + ThreatLens Score
  // ========================================================

  async function handleViewIntelligence(
    incident
  ) {
    const incidentId =
      normalizeIncidentId(
        incident?.id
      );

    if (incidentId === null) {
      setError(
        "Invalid incident ID. Expected a numeric incident ID."
      );

      console.error(
        "ThreatLens: Cannot load intelligence. Invalid ID:",
        incident?.id
      );

      return;
    }

    try {
      setSelectedIncident(
        {
          ...incident,
          id: incidentId,
        }
      );

      setLoadingIntelligence(
        true
      );

      setLoadingScore(true);

      setIntelligence([]);

      setIncidentScore(null);

      setScoreError("");

      setError("");

      console.log(
        "=============================================="
      );

      console.log(
        "ThreatLens: Loading incident investigation"
      );

      console.log(
        "Incident ID:",
        incidentId
      );

      console.log(
        "Incident ID type:",
        typeof incidentId
      );

      console.log(
        "Intelligence endpoint:",
        `/incidents/${incidentId}/intelligence`
      );

      console.log(
        "Score endpoint:",
        `/incidents/${incidentId}/score`
      );

      console.log(
        "=============================================="
      );

      // ----------------------------------------------------
      // Load intelligence and score simultaneously.
      // ----------------------------------------------------

      const [
        intelligenceResult,
        scoreResult,
      ] = await Promise.allSettled([
        getIncidentIntelligence(
          incidentId,
          100,
          0
        ),

        getIncidentScore(
          incidentId
        ),
      ]);

      // ----------------------------------------------------
      // Intelligence result
      // ----------------------------------------------------

      if (
        intelligenceResult.status ===
        "fulfilled"
      ) {
        const data =
          intelligenceResult.value;

        console.log(
          "ThreatLens: Intelligence response:",
          data
        );

        const normalized =
          normalizeArray(
            data?.intelligence
              ? data.intelligence
              : data,
            ["intelligence"]
          );

        setIntelligence(
          normalized
        );

        console.log(
          "ThreatLens: Normalized intelligence:",
          normalized
        );
      } else {
        console.error(
          "ThreatLens: Intelligence request failed:",
          intelligenceResult.reason
        );

        setError(
          intelligenceResult.reason
            ?.message ||
            "Failed to load incident intelligence."
        );

        setIntelligence([]);
      }

      // ----------------------------------------------------
      // Score result
      // ----------------------------------------------------

      if (
        scoreResult.status ===
        "fulfilled"
      ) {
        const data =
          scoreResult.value;

        console.log(
          "ThreatLens: Incident score response:",
          data
        );

        const normalizedScore =
          normalizeScoreResponse(
            data
          );

        setIncidentScore(
          normalizedScore
        );

        console.log(
          "ThreatLens: Normalized incident score:",
          normalizedScore
        );
      } else {
        console.error(
          "ThreatLens: Incident score request failed:",
          scoreResult.reason
        );

        setIncidentScore(null);

        setScoreError(
          scoreResult.reason
            ?.message ||
            "Failed to load ThreatLens score."
        );
      }
    } catch (err) {
      console.error(
        "ThreatLens INCIDENT INVESTIGATION ERROR:",
        err
      );

      setError(
        err?.message ||
          "Failed to load incident investigation."
      );
    } finally {
      setLoadingIntelligence(
        false
      );

      setLoadingScore(false);
    }
  }

  // ========================================================
  // Close Intelligence
  // ========================================================

  function closeIntelligence() {
    setSelectedIncident(
      null
    );

    setIntelligence([]);

    setIncidentScore(null);

    setScoreError("");

    setLoadingIntelligence(
      false
    );

    setLoadingScore(false);
  }

  // ========================================================
  // Severity Class
  // ========================================================

  function getSeverityClass(
    severity
  ) {
    return `incident-severity ${normalizeSeverity(
      severity
    )}`;
  }

  // ========================================================
  // Status Class
  // ========================================================

  function getStatusClass(
    status
  ) {
    return `incident-status ${normalizeStatus(
      status
    )}`;
  }

  // ========================================================
  // Date Formatter
  // ========================================================

  function formatDate(date) {
    if (!date) {
      return "—";
    }

    const parsed =
      new Date(date);

    if (
      Number.isNaN(
        parsed.getTime()
      )
    ) {
      return String(date);
    }

    return parsed.toLocaleString();
  }

  // ========================================================
  // Score Display
  // ========================================================

  function formatScore(score) {
    const numericScore =
      Number(score);

    if (
      !Number.isFinite(
        numericScore
      )
    ) {
      return "—";
    }

    return Math.round(
      numericScore
    );
  }

  // ========================================================
  // Score Severity
  // ========================================================

  function getScoreSeverity() {
    const scoreSeverity =
      incidentScore?.severity;

    if (
      scoreSeverity &&
      [
        "critical",
        "high",
        "medium",
        "low",
      ].includes(
        normalizeSeverity(
          scoreSeverity
        )
      )
    ) {
      return normalizeSeverity(
        scoreSeverity
      );
    }

    return normalizeSeverity(
      selectedIncident?.severity
    );
  }

  // ========================================================
  // Loading
  // ========================================================

  if (loading) {
    return (
      <section className="incidents-page">
        <div className="incidents-loading">
          Loading incidents...
        </div>
      </section>
    );
  }

  // ========================================================
  // Render
  // ========================================================

  return (
    <section className="incidents-page">

      {/* ==================================================
          HEADER
      ================================================== */}

      <div className="incidents-header">

        <div>
          <h2>
            Security Incidents
          </h2>

          <p>
            Investigate, manage and correlate
            security incidents.
          </p>
        </div>

        <button
          type="button"
          className="incident-refresh-button"
          onClick={() =>
            refreshIncidents(true)
          }
          disabled={
            refreshing ||
            creating
          }
        >
          {refreshing
            ? "↻ Refreshing..."
            : "↻ Refresh"}
        </button>

      </div>

      {/* ==================================================
          ERROR
      ================================================== */}

      {error && (
        <div className="incident-error">
          {error}
        </div>
      )}

      {/* ==================================================
          STATISTICS
      ================================================== */}

      <div className="incident-stat-grid">

        <div className="incident-stat-card">
          <span>
            Total Incidents
          </span>

          <strong>
            {stats.total}
          </strong>
        </div>

        <div className="incident-stat-card">
          <span>Open</span>

          <strong>
            {stats.open}
          </strong>
        </div>

        <div className="incident-stat-card">
          <span>
            Investigating
          </span>

          <strong>
            {stats.investigating}
          </strong>
        </div>

        <div className="incident-stat-card">
          <span>Resolved</span>

          <strong>
            {stats.resolved}
          </strong>
        </div>

        <div className="incident-stat-card critical">
          <span>Critical</span>

          <strong>
            {stats.critical}
          </strong>
        </div>

        <div className="incident-stat-card high">
          <span>High</span>

          <strong>
            {stats.high}
          </strong>
        </div>

        <div className="incident-stat-card medium">
          <span>Medium</span>

          <strong>
            {stats.medium}
          </strong>
        </div>

        <div className="incident-stat-card low">
          <span>Low</span>

          <strong>
            {stats.low}
          </strong>
        </div>

      </div>

      {/* ==================================================
          CREATE INCIDENT
      ================================================== */}

      <div className="incident-create-card">

        <div className="incident-section-title">

          <h3>
            Create Incident
          </h3>

          <p>
            Create a new security investigation.
          </p>

        </div>

        <form
          className="incident-form"
          onSubmit={
            handleCreateIncident
          }
        >

          <div className="incident-form-row">

            <div className="incident-form-group">

              <label htmlFor="incident-title">
                Title
              </label>

              <input
                id="incident-title"
                type="text"
                name="title"
                value={form.title}
                onChange={
                  handleChange
                }
                placeholder="Suspicious IP investigation"
                required
              />

            </div>

            <div className="incident-form-group">

              <label htmlFor="incident-ip">
                IP Address
              </label>

              <input
                id="incident-ip"
                type="text"
                name="ip_address"
                value={
                  form.ip_address
                }
                onChange={
                  handleChange
                }
                placeholder="8.8.8.8"
              />

            </div>

          </div>

          <div className="incident-form-row">

            <div className="incident-form-group">

              <label htmlFor="incident-severity">
                Severity
              </label>

              <select
                id="incident-severity"
                name="severity"
                value={
                  form.severity
                }
                onChange={
                  handleChange
                }
              >
                <option value="critical">
                  Critical
                </option>

                <option value="high">
                  High
                </option>

                <option value="medium">
                  Medium
                </option>

                <option value="low">
                  Low
                </option>
              </select>

            </div>

            <div className="incident-form-group">

              <label htmlFor="incident-status">
                Status
              </label>

              <select
                id="incident-status"
                name="status"
                value={
                  form.status
                }
                onChange={
                  handleChange
                }
              >
                <option value="open">
                  Open
                </option>

                <option value="investigating">
                  Investigating
                </option>

                <option value="resolved">
                  Resolved
                </option>
              </select>

            </div>

          </div>

          <div className="incident-form-group">

            <label htmlFor="incident-description">
              Description
            </label>

            <textarea
              id="incident-description"
              name="description"
              value={
                form.description
              }
              onChange={
                handleChange
              }
              placeholder="Describe the security incident..."
              rows="4"
            />

          </div>

          <button
            type="submit"
            className="incident-create-button"
            disabled={
              creating ||
              refreshing
            }
          >
            {creating
              ? "Creating..."
              : "Create Incident"}
          </button>

        </form>

      </div>

      {/* ==================================================
          INCIDENT QUEUE
      ================================================== */}

      <div className="incident-list-card">

        <div className="incident-section-title">

          <div>
            <h3>
              Incident Queue
            </h3>
          </div>

          <span>
            {incidents.length} incident
            {incidents.length === 1
              ? ""
              : "s"}
          </span>

        </div>

        {incidents.length === 0 ? (

          <div className="incident-empty">
            No security incidents found.
          </div>

        ) : (

          <div className="incident-table-wrapper">

            <table className="incident-table">

              <thead>
                <tr>
                  <th>ID</th>
                  <th>Incident</th>
                  <th>IP Address</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>

                {incidents.map(
                  (incident) => {

                    const incidentId =
                      normalizeIncidentId(
                        incident.id
                      );

                    const severity =
                      normalizeSeverity(
                        incident.severity
                      );

                    const status =
                      normalizeStatus(
                        incident.status
                      );

                    return (
                      <tr
                        key={
                          incidentId
                        }
                      >

                        {/* ID */}

                        <td>
                          <strong>
                            #{incidentId}
                          </strong>
                        </td>

                        {/* INCIDENT */}

                        <td>

                          <div className="incident-title">
                            {
                              incident.title
                            }
                          </div>

                          {incident.description && (
                            <div className="incident-description">
                              {
                                incident.description
                              }
                            </div>
                          )}

                        </td>

                        {/* IP */}

                        <td>
                          {incident.ip_address ? (
                            <code>
                              {
                                incident.ip_address
                              }
                            </code>
                          ) : (
                            "—"
                          )}
                        </td>

                        {/* SEVERITY */}

                        <td>
                          <span
                            className={getSeverityClass(
                              severity
                            )}
                          >
                            {severity.toUpperCase()}
                          </span>
                        </td>

                        {/* STATUS */}

                        <td>

                          <select
                            className={getStatusClass(
                              status
                            )}
                            value={
                              status
                            }
                            onChange={(
                              event
                            ) =>
                              handleStatusChange(
                                incident,
                                event
                                  .target
                                  .value
                              )
                            }
                            disabled={
                              refreshing ||
                              incidentId ===
                                null
                            }
                            aria-label={`Status for incident ${incidentId}`}
                          >

                            <option value="open">
                              Open
                            </option>

                            <option value="investigating">
                              Investigating
                            </option>

                            <option value="resolved">
                              Resolved
                            </option>

                          </select>

                        </td>

                        {/* CREATED */}

                        <td>
                          {formatDate(
                            incident.created_at
                          )}
                        </td>

                        {/* ACTIONS */}

                        <td>

                          <div className="incident-actions">

                            <button
                              type="button"
                              onClick={() =>
                                handleViewIntelligence(
                                  incident
                                )
                              }
                              disabled={
                                loadingIntelligence &&
                                selectedIncident?.id ===
                                  incidentId
                              }
                            >
                              {loadingIntelligence &&
                              selectedIncident?.id ===
                                incidentId
                                ? "Loading..."
                                : "Intelligence"}
                            </button>

                            <button
                              type="button"
                              className="danger"
                              onClick={() =>
                                handleDeleteIncident(
                                  incident
                                )
                              }
                              disabled={
                                refreshing ||
                                incidentId ===
                                  null
                              }
                            >
                              Delete
                            </button>

                          </div>

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

      {/* ==================================================
          INTELLIGENCE PANEL
      ================================================== */}

      {selectedIncident && (

        <div className="incident-intelligence-card">

          <div className="incident-section-title">

            <div>

              <h3>
                Incident Intelligence
              </h3>

              <p>
                #{selectedIncident.id}{" "}
                {selectedIncident.title}
              </p>

            </div>

            <button
              type="button"
              onClick={
                closeIntelligence
              }
            >
              Close
            </button>

          </div>

          {/* ==================================================
              INCIDENT THREAT ASSESSMENT
          ================================================== */}

          <div className="incident-threat-assessment">

            <div className="incident-threat-score-card">

              <span>
                ThreatLens Score
              </span>

              {loadingScore ? (

                <strong>
                  Calculating...
                </strong>

              ) : incidentScore?.score !== null &&
                incidentScore?.score !== undefined ? (

                <strong>
                  {formatScore(
                    incidentScore.score
                  )}
                  <small>
                    /100
                  </small>
                </strong>

              ) : (

                <strong>
                  —
                </strong>

              )}

            </div>

            <div className="incident-threat-severity-card">

              <span>
                Severity
              </span>

              <strong
                className={getSeverityClass(
                  getScoreSeverity()
                )}
              >
                {getScoreSeverity().toUpperCase()}
              </strong>

            </div>

            <div className="incident-threat-status-card">

              <span>
                Incident Status
              </span>

              <strong
                className={getStatusClass(
                  selectedIncident.status
                )}
              >
                {normalizeStatus(
                  selectedIncident.status
                ).toUpperCase()}
              </strong>

            </div>

          </div>

          {/* ==================================================
              SCORE ERROR
          ================================================== */}

          {scoreError && (
            <div className="incident-error">
              {scoreError}
            </div>
          )}

          {/* ==================================================
              INTELLIGENCE SOURCES
          ================================================== */}

          <div className="incident-sources-section">

            <div className="incident-section-title">

              <div>

                <h3>
                  Intelligence Sources
                </h3>

                <p>
                  Threat intelligence providers
                  contributing to this investigation.
                </p>

              </div>

            </div>

            <div className="incident-source-list">

              {(
                incidentScore?.sources?.length
                  ? incidentScore.sources
                  : getIntelligenceSources(
                      intelligence
                    )
              ).length > 0 ? (

                (
                  incidentScore?.sources?.length
                    ? incidentScore.sources
                    : getIntelligenceSources(
                        intelligence
                      )
                ).map(
                  (source, index) => (

                    <div
                      className="incident-source-badge"
                      key={`${source}-${index}`}
                    >
                      <span>
                        ✓
                      </span>

                      <strong>
                        {source}
                      </strong>
                    </div>

                  )
                )

              ) : (

                <div className="incident-empty">
                  No intelligence sources
                  reported for this incident.
                </div>

              )}

            </div>

          </div>

          {/* ==================================================
              INTELLIGENCE LOOKUPS
          ================================================== */}

          <div className="incident-lookups-section">

            <div className="incident-section-title">

              <div>

                <h3>
                  Intelligence Lookups
                </h3>

                <p>
                  Intelligence records associated
                  with this incident.
                </p>

              </div>

              {loadingIntelligence && (
                <span>
                  Loading...
                </span>
              )}

            </div>

            {loadingIntelligence ? (

              <div className="incident-empty">
                Loading intelligence...
              </div>

            ) : intelligence.length === 0 ? (

              <div className="incident-empty">
                No intelligence lookups are
                associated with this incident.
              </div>

            ) : (

              <div className="incident-intelligence-list">

                {intelligence.map(
                  (item, index) => (

                    <div
                      className="incident-intelligence-item"
                      key={
                        item.id ??
                        `${item.source || "source"}-${index}`
                      }
                    >

                      <div>
                        <span>
                          Source
                        </span>

                        <strong>
                          {item.source ||
                            "Unknown Source"}
                        </strong>
                      </div>

                      <div>
                        <span>
                          IP Address
                        </span>

                        <strong>
                          {item.ip ||
                            item.ip_address ||
                            "—"}
                        </strong>
                      </div>

                      <div>
                        <span>
                          Risk Score
                        </span>

                        <strong>
                          {item.risk_score ??
                            item.score ??
                            item.threatlens_score ??
                            "—"}
                        </strong>
                      </div>

                      <div>
                        <span>
                          Created
                        </span>

                        <strong>
                          {formatDate(
                            item.created_at
                          )}
                        </strong>
                      </div>

                    </div>

                  )
                )}

              </div>

            )}

          </div>

        </div>

      )}

    </section>
  );
}

export default Incidents;
