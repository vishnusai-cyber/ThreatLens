import { useEffect, useMemo, useState } from "react";

import {
  getIncidents,
  getIncidentStats,
  getIncident,
  getIncidentIntelligence,
  createIncident,
  updateIncident,
  deleteIncident,
} from "../api";

// ==========================================================
// ThreatLens - Incidents
// ==========================================================

function Incidents({ refreshKey = 0 }) {
  // ========================================================
  // State
  // ========================================================

  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  // ========================================================
  // Create Incident Modal
  // ========================================================

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState("");

  const [newIncident, setNewIncident] = useState({
    title: "",
    description: "",
    severity: "Medium",
    ip_address: "",
  });

  // ========================================================
  // Selected Incident
  // ========================================================

  const [selectedIncident, setSelectedIncident] = useState(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [selectedError, setSelectedError] = useState("");

  const [attachedIntelligence, setAttachedIntelligence] = useState([]);
  const [intelligenceLoading, setIntelligenceLoading] =
    useState(false);

  // ========================================================
  // Update / Delete
  // ========================================================

  const [updating, setUpdating] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // ========================================================
  // Search / Filter
  // ========================================================

  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  // ========================================================
  // Normalize Array
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
      "incidents",
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
  // Load Incidents
  // ========================================================

  async function loadIncidents(showRefresh = false) {
    try {
      if (showRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");

      const [incidentsResponse, statsResponse] =
        await Promise.all([
          getIncidents(),
          getIncidentStats(),
        ]);

      const incidentData = normalizeArray(incidentsResponse);

      setIncidents(incidentData);
      setStats(statsResponse || null);
    } catch (err) {
      console.error(
        "ThreatLens incidents loading error:",
        err
      );

      setError(
        err?.message || "Unable to load incidents."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  // ========================================================
  // Initial / Refresh-Key Load
  // ========================================================

  useEffect(() => {
    loadIncidents(false).catch(() => {});
  }, [refreshKey]);

  // ========================================================
  // Create Incident Modal
  // ========================================================

  function openCreateModal() {
    setNewIncident({
      title: "",
      description: "",
      severity: "Medium",
      ip_address: "",
    });

    setCreateError("");
    setShowCreateModal(true);
  }

  function closeCreateModal() {
    if (createLoading) {
      return;
    }

    setShowCreateModal(false);
    setCreateError("");
  }

  // ========================================================
  // Create Incident
  // ========================================================

  async function handleCreateIncident(event) {
    event.preventDefault();

    setCreateError("");

    const title = newIncident.title.trim();
    const description = newIncident.description.trim();
    const ipAddress = newIncident.ip_address.trim();

    if (!title) {
      setCreateError("Incident title is required.");
      return;
    }

    if (!description) {
      setCreateError(
        "Incident description is required."
      );
      return;
    }

    setCreateLoading(true);

    try {
      await createIncident({
        title,
        description,
        severity: newIncident.severity || "Medium",
        ip_address: ipAddress || null,
      });

      setShowCreateModal(false);

      setNewIncident({
        title: "",
        description: "",
        severity: "Medium",
        ip_address: "",
      });

      await loadIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens incident creation error:",
        err
      );

      setCreateError(
        err?.message || "Unable to create incident."
      );
    } finally {
      setCreateLoading(false);
    }
  }

  // ========================================================
  // Open Incident Details
  // ========================================================

  async function openIncident(incidentId) {
    if (!incidentId) {
      return;
    }

    try {
      setSelectedLoading(true);
      setSelectedError("");
      setSelectedIncident(null);
      setAttachedIntelligence([]);

      const incident = await getIncident(incidentId);

      setSelectedIncident(incident);

      try {
        setIntelligenceLoading(true);

        const intelligenceResponse =
          await getIncidentIntelligence(incidentId);

        setAttachedIntelligence(
          normalizeArray(intelligenceResponse, [
            "intelligence",
            "lookups",
          ])
        );
      } catch (intelError) {
        console.error(
          "ThreatLens incident intelligence loading error:",
          intelError
        );

        setAttachedIntelligence([]);
      } finally {
        setIntelligenceLoading(false);
      }
    } catch (err) {
      console.error(
        "ThreatLens incident detail error:",
        err
      );

      setSelectedError(
        err?.message ||
          "Unable to load incident details."
      );
    } finally {
      setSelectedLoading(false);
    }
  }

  // ========================================================
  // Close Incident Details
  // ========================================================

  function closeIncidentDetails() {
    if (updating || deleting) {
      return;
    }

    setSelectedIncident(null);
    setSelectedError("");
    setAttachedIntelligence([]);
  }

  // ========================================================
  // Update Incident Status
  // ========================================================

  async function handleStatusUpdate(status) {
    if (!selectedIncident?.id) {
      return;
    }

    try {
      setUpdating(true);
      setSelectedError("");

      const updated = await updateIncident(
        selectedIncident.id,
        {
          status,
        }
      );

      setSelectedIncident(
        updated || {
          ...selectedIncident,
          status,
        }
      );

      await loadIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens incident update error:",
        err
      );

      setSelectedError(
        err?.message ||
          "Unable to update incident."
      );
    } finally {
      setUpdating(false);
    }
  }

  // ========================================================
  // Delete Incident
  // ========================================================

  async function handleDeleteIncident() {
    if (!selectedIncident?.id) {
      return;
    }

    const confirmed = window.confirm(
      `Delete incident "${selectedIncident.title}"? This action cannot be undone.`
    );

    if (!confirmed) {
      return;
    }

    try {
      setDeleting(true);
      setSelectedError("");

      await deleteIncident(selectedIncident.id);

      setSelectedIncident(null);
      setAttachedIntelligence([]);

      await loadIncidents(true);
    } catch (err) {
      console.error(
        "ThreatLens incident deletion error:",
        err
      );

      setSelectedError(
        err?.message ||
          "Unable to delete incident."
      );
    } finally {
      setDeleting(false);
    }
  }

  // ========================================================
  // Helpers
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

  function normalizeSeverity(value) {
    return String(value || "")
      .trim()
      .toLowerCase();
  }

  function normalizeStatus(value) {
    return String(value || "")
      .trim()
      .toLowerCase();
  }

  function getSeverityClass(value) {
    const severity = normalizeSeverity(value);

    if (severity === "critical") {
      return "critical";
    }

    if (severity === "high") {
      return "high";
    }

    if (severity === "medium") {
      return "medium";
    }

    if (severity === "low") {
      return "low";
    }

    return "unknown";
  }

  function getStatusClass(value) {
    const status = normalizeStatus(value);

    if (
      status === "resolved" ||
      status === "closed"
    ) {
      return "resolved";
    }

    if (
      status === "investigating" ||
      status === "in_progress"
    ) {
      return "investigating";
    }

    if (status === "open") {
      return "open";
    }

    return "unknown";
  }

  function formatStatus(value) {
    if (!value) {
      return "Unknown";
    }

    const text = String(value)
      .replaceAll("_", " ")
      .trim();

    return (
      text.charAt(0).toUpperCase() +
      text.slice(1).toLowerCase()
    );
  }

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

  function getIncidentIP(incident) {
    return (
      incident?.ip_address ||
      incident?.ip ||
      incident?.source_ip ||
      "—"
    );
  }

  // ========================================================
  // Filtered Incidents
  // ========================================================

  const filteredIncidents = useMemo(() => {
    const search = searchTerm.trim().toLowerCase();

    return incidents.filter((incident) => {
      const title = String(
        incident?.title || ""
      ).toLowerCase();

      const description = String(
        incident?.description || ""
      ).toLowerCase();

      const ip = String(
        getIncidentIP(incident)
      ).toLowerCase();

      const incidentSeverity = normalizeSeverity(
        incident?.severity
      );

      const incidentStatus = normalizeStatus(
        incident?.status
      );

      const matchesSearch =
        !search ||
        title.includes(search) ||
        description.includes(search) ||
        ip.includes(search);

      const matchesSeverity =
        severityFilter === "all" ||
        incidentSeverity === severityFilter;

      const matchesStatus =
        statusFilter === "all" ||
        incidentStatus === statusFilter;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus
      );
    });
  }, [
    incidents,
    searchTerm,
    severityFilter,
    statusFilter,
  ]);

  // ========================================================
  // Statistics
  // ========================================================

  const incidentStats = useMemo(() => {
    const result = {
      total: incidents.length,
      open: 0,
      investigating: 0,
      resolved: 0,
      critical: 0,
      high: 0,
    };

    incidents.forEach((incident) => {
      const status = normalizeStatus(
        incident?.status
      );

      const severity = normalizeSeverity(
        incident?.severity
      );

      if (status === "open") {
        result.open += 1;
      }

      if (
        status === "investigating" ||
        status === "in_progress"
      ) {
        result.investigating += 1;
      }

      if (
        status === "resolved" ||
        status === "closed"
      ) {
        result.resolved += 1;
      }

      if (severity === "critical") {
        result.critical += 1;
      }

      if (severity === "high") {
        result.high += 1;
      }
    });

    if (stats) {
      result.total =
        stats.total ??
        stats.total_incidents ??
        stats.count ??
        result.total;

      result.open =
        stats.open ??
        stats.open_incidents ??
        result.open;

      result.investigating =
        stats.investigating ??
        stats.in_progress ??
        stats.investigating_incidents ??
        result.investigating;

      result.resolved =
        stats.resolved ??
        stats.resolved_incidents ??
        stats.closed ??
        result.resolved;
    }

    return result;
  }, [incidents, stats]);

  // ========================================================
  // Loading State
  // ========================================================

  if (loading) {
    return (
      <section className="incidents-page">
        <div className="incidents-content">
          <div className="page-heading">
            <div>
              <h3>Incidents</h3>

              <p>
                Track, investigate and manage
                security incidents.
              </p>
            </div>
          </div>

          <div className="panel">
            <div className="chart-message">
              Loading incidents...
            </div>
          </div>
        </div>
      </section>
    );
  }

  // ========================================================
  // Main Render
  // ========================================================

  return (
    <section className="incidents-page">
      <div className="incidents-content">

        {/* ==================================================
            PAGE HEADER
        ================================================== */}

        <div className="page-heading">
          <div>
            <h3>Incidents</h3>

            <p>
              Track, investigate and manage
              security incidents.
            </p>
          </div>

          <div className="heading-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={() =>
                loadIncidents(true).catch(() => {})
              }
              disabled={refreshing}
            >
              {refreshing
                ? "↻ Refreshing..."
                : "↻ Refresh"}
            </button>

            <button
              type="button"
              className="primary-button"
              onClick={openCreateModal}
            >
              + New Incident
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

        <div className="stats-grid incidents-stats">

          <div className="stat-card">
            <div className="stat-header">
              <span>Total Incidents</span>

              <span className="stat-icon">
                ◇
              </span>
            </div>

            <strong>
              {incidentStats.total}
            </strong>

            <div className="stat-change">
              Security incidents
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span>Open</span>

              <span className="stat-icon">
                !
              </span>
            </div>

            <strong>
              {incidentStats.open}
            </strong>

            <div className="stat-change">
              Awaiting investigation
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span>Investigating</span>

              <span className="stat-icon">
                ◎
              </span>
            </div>

            <strong>
              {incidentStats.investigating}
            </strong>

            <div className="stat-change">
              Currently under investigation
            </div>
          </div>

          <div className="stat-card critical-card">
            <div className="stat-header">
              <span>Critical / High</span>

              <span className="stat-icon">
                ⚠
              </span>
            </div>

            <strong>
              {incidentStats.critical +
                incidentStats.high}
            </strong>

            <div className="stat-change negative">
              High-priority incidents
            </div>
          </div>
        </div>

        {/* ==================================================
            INCIDENT MANAGEMENT
        ================================================== */}

        <div className="panel incidents-panel">

          <div className="panel-header">
            <div>
              <h4>Incident Management</h4>

              <p>
                Investigate and manage active
                security incidents.
              </p>
            </div>
          </div>

          {/* ==================================================
              FILTERS
          ================================================== */}

          <div className="incident-filters">

            <input
              type="text"
              className="incident-search"
              placeholder="Search title, description or IP..."
              value={searchTerm}
              onChange={(event) =>
                setSearchTerm(
                  event.target.value
                )
              }
            />

            <select
              className="settings-select"
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(
                  event.target.value
                )
              }
            >
              <option value="all">
                All Severities
              </option>

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

            <select
              className="settings-select"
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(
                  event.target.value
                )
              }
            >
              <option value="all">
                All Statuses
              </option>

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

          {/* ==================================================
              INCIDENT TABLE
          ================================================== */}

          {filteredIncidents.length === 0 ? (
            <div className="chart-message">
              {incidents.length === 0
                ? "No incidents have been created yet."
                : "No incidents match the selected filters."}
            </div>
          ) : (
            <div className="table-wrapper incidents-table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Incident</th>
                    <th>IP Address</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredIncidents.map(
                    (incident) => {
                      const severityClass =
                        getSeverityClass(
                          incident?.severity
                        );

                      const statusClass =
                        getStatusClass(
                          incident?.status
                        );

                      return (
                        <tr
                          key={incident?.id}
                        >
                          <td>
                            <strong>
                              #{incident?.id}
                            </strong>
                          </td>

                          <td>
                            <div className="incident-title-cell">
                              <strong>
                                {incident?.title ||
                                  "Untitled Incident"}
                              </strong>

                              <small>
                                {incident?.description ||
                                  "No description"}
                              </small>
                            </div>
                          </td>

                          <td>
                            <span className="mono-text">
                              {getIncidentIP(
                                incident
                              )}
                            </span>
                          </td>

                          <td>
                            <span
                              className={`risk ${severityClass}`}
                            >
                              {formatSeverity(
                                incident?.severity
                              )}
                            </span>
                          </td>

                          <td>
                            <span
                              className={`incident-status ${statusClass}`}
                            >
                              {formatStatus(
                                incident?.status
                              )}
                            </span>
                          </td>

                          <td>
                            <span className="date-text">
                              {formatDate(
                                incident?.created_at
                              )}
                            </span>
                          </td>

                          <td>
                            <button
                              type="button"
                              className="text-button"
                              onClick={() =>
                                openIncident(
                                  incident?.id
                                )
                              }
                            >
                              View
                            </button>
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
            CREATE INCIDENT MODAL
        ================================================== */}

        {showCreateModal && (
          <div
            className="modal-overlay"
            onMouseDown={(event) => {
              if (
                event.target ===
                event.currentTarget
              ) {
                closeCreateModal();
              }
            }}
          >
            <div className="scan-modal incident-modal">

              <div className="scan-modal-header">
                <div>
                  <span className="modal-label">
                    INCIDENT MANAGEMENT
                  </span>

                  <h3>
                    Create New Incident
                  </h3>

                  <p>
                    Create and track a new
                    security incident.
                  </p>
                </div>

                <button
                  type="button"
                  className="modal-close"
                  onClick={closeCreateModal}
                  disabled={createLoading}
                  aria-label="Close"
                >
                  ×
                </button>
              </div>

              <form
                className="scan-form"
                onSubmit={
                  handleCreateIncident
                }
              >
                <label htmlFor="incident-title">
                  Incident Title
                </label>

                <input
                  id="incident-title"
                  type="text"
                  value={newIncident.title}
                  onChange={(event) => {
                    setNewIncident(
                      (previous) => ({
                        ...previous,
                        title:
                          event.target.value,
                      })
                    );

                    setCreateError("");
                  }}
                  placeholder="Suspicious IP activity"
                  disabled={createLoading}
                />

                <label htmlFor="incident-description">
                  Description
                </label>

                <textarea
                  id="incident-description"
                  value={
                    newIncident.description
                  }
                  onChange={(event) => {
                    setNewIncident(
                      (previous) => ({
                        ...previous,
                        description:
                          event.target.value,
                      })
                    );

                    setCreateError("");
                  }}
                  placeholder="Describe the security incident..."
                  rows={5}
                  disabled={createLoading}
                />

                <label htmlFor="incident-ip">
                  IP Address
                </label>

                <input
                  id="incident-ip"
                  type="text"
                  value={
                    newIncident.ip_address
                  }
                  onChange={(event) => {
                    setNewIncident(
                      (previous) => ({
                        ...previous,
                        ip_address:
                          event.target.value,
                      })
                    );

                    setCreateError("");
                  }}
                  placeholder="185.220.101.1"
                  disabled={createLoading}
                />

                <label htmlFor="incident-severity">
                  Severity
                </label>

                <select
                  id="incident-severity"
                  value={
                    newIncident.severity
                  }
                  onChange={(event) =>
                    setNewIncident(
                      (previous) => ({
                        ...previous,
                        severity:
                          event.target.value,
                      })
                    )
                  }
                  disabled={createLoading}
                >
                  <option value="Critical">
                    Critical
                  </option>

                  <option value="High">
                    High
                  </option>

                  <option value="Medium">
                    Medium
                  </option>

                  <option value="Low">
                    Low
                  </option>
                </select>

                {createError && (
                  <div className="scan-error">
                    {createError}
                  </div>
                )}

                <div className="result-actions">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={closeCreateModal}
                    disabled={createLoading}
                  >
                    Cancel
                  </button>

                  <button
                    type="submit"
                    className="primary-button"
                    disabled={createLoading}
                  >
                    {createLoading
                      ? "Creating..."
                      : "Create Incident"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* ==================================================
            INCIDENT DETAILS MODAL
        ================================================== */}

        {(selectedLoading ||
          selectedIncident) && (
          <div
            className="modal-overlay"
            onMouseDown={(event) => {
              if (
                event.target ===
                  event.currentTarget &&
                !updating &&
                !deleting
              ) {
                closeIncidentDetails();
              }
            }}
          >
            <div className="scan-modal incident-details-modal">

              {selectedLoading ? (
                <div className="scan-progress">
                  <div className="spinner" />

                  <strong>
                    Loading Incident...
                  </strong>

                  <span>
                    Retrieving incident
                    intelligence.
                  </span>
                </div>
              ) : (
                <>
                  <div className="scan-modal-header">
                    <div>
                      <span className="modal-label">
                        INCIDENT #
                        {selectedIncident?.id}
                      </span>

                      <h3>
                        {
                          selectedIncident?.title
                        }
                      </h3>

                      <p>
                        Incident details and
                        attached threat
                        intelligence.
                      </p>
                    </div>

                    <button
                      type="button"
                      className="modal-close"
                      onClick={
                        closeIncidentDetails
                      }
                      disabled={
                        updating ||
                        deleting
                      }
                      aria-label="Close"
                    >
                      ×
                    </button>
                  </div>

                  {selectedError && (
                    <div className="scan-error">
                      {selectedError}
                    </div>
                  )}

                  {/* ==================================================
                      INCIDENT SUMMARY
                  ================================================== */}

                  <div className="incident-detail-grid">

                    <div className="incident-detail-card">
                      <span>
                        SEVERITY
                      </span>

                      <strong>
                        <span
                          className={`risk ${getSeverityClass(
                            selectedIncident?.severity
                          )}`}
                        >
                          {formatSeverity(
                            selectedIncident?.severity
                          )}
                        </span>
                      </strong>
                    </div>

                    <div className="incident-detail-card">
                      <span>
                        STATUS
                      </span>

                      <strong>
                        <span
                          className={`incident-status ${getStatusClass(
                            selectedIncident?.status
                          )}`}
                        >
                          {formatStatus(
                            selectedIncident?.status
                          )}
                        </span>
                      </strong>
                    </div>

                    <div className="incident-detail-card">
                      <span>
                        IP ADDRESS
                      </span>

                      <strong className="mono-text">
                        {getIncidentIP(
                          selectedIncident
                        )}
                      </strong>
                    </div>

                    <div className="incident-detail-card">
                      <span>
                        CREATED
                      </span>

                      <strong>
                        {formatDate(
                          selectedIncident?.created_at
                        )}
                      </strong>
                    </div>
                  </div>

                  {/* ==================================================
                      DESCRIPTION
                  ================================================== */}

                  <div className="incident-description">
                    <span>
                      DESCRIPTION
                    </span>

                    <p>
                      {selectedIncident
                        ?.description ||
                        "No description provided."}
                    </p>
                  </div>

                  {/* ==================================================
                      STATUS CONTROLS
                  ================================================== */}

                  <div className="incident-actions-section">
                    <div>
                      <strong>
                        Update Status
                      </strong>

                      <p>
                        Change the current
                        incident lifecycle
                        state.
                      </p>
                    </div>

                    <div className="incident-status-actions">

                      <button
                        type="button"
                        className={`incident-action-button ${
                          normalizeStatus(
                            selectedIncident?.status
                          ) === "open"
                            ? "selected"
                            : ""
                        }`}
                        onClick={() =>
                          handleStatusUpdate(
                            "Open"
                          )
                        }
                        disabled={
                          updating ||
                          deleting
                        }
                      >
                        Open
                      </button>

                      <button
                        type="button"
                        className={`incident-action-button ${
                          normalizeStatus(
                            selectedIncident?.status
                          ) === "investigating" ||
                          normalizeStatus(
                            selectedIncident?.status
                          ) === "in_progress"
                            ? "selected"
                            : ""
                        }`}
                        onClick={() =>
                          handleStatusUpdate(
                            "Investigating"
                          )
                        }
                        disabled={
                          updating ||
                          deleting
                        }
                      >
                        Investigating
                      </button>

                      <button
                        type="button"
                        className={`incident-action-button ${
                          normalizeStatus(
                            selectedIncident?.status
                          ) === "resolved"
                            ? "selected"
                            : ""
                        }`}
                        onClick={() =>
                          handleStatusUpdate(
                            "Resolved"
                          )
                        }
                        disabled={
                          updating ||
                          deleting
                        }
                      >
                        Resolved
                      </button>
                    </div>
                  </div>

                  {/* ==================================================
                      ATTACHED INTELLIGENCE
                  ================================================== */}

                  <div className="incident-intelligence">

                    <div className="panel-header">
                      <div>
                        <h4>
                          Attached Intelligence
                        </h4>

                        <p>
                          Threat intelligence
                          associated with this
                          incident.
                        </p>
                      </div>
                    </div>

                    {intelligenceLoading ? (
                      <div className="chart-message">
                        Loading attached
                        intelligence...
                      </div>
                    ) : attachedIntelligence.length ===
                      0 ? (
                      <div className="chart-message">
                        No intelligence
                        lookups are attached
                        to this incident.
                      </div>
                    ) : (
                      <div className="table-wrapper incidents-table-wrapper">
                        <table className="data-table">
                          <thead>
                            <tr>
                              <th>ID</th>
                              <th>
                                IP Address
                              </th>
                              <th>
                                Source
                              </th>
                              <th>
                                Created
                              </th>
                            </tr>
                          </thead>

                          <tbody>
                            {attachedIntelligence.map(
                              (
                                intelligence,
                                index
                              ) => (
                                <tr
                                  key={
                                    intelligence?.id ||
                                    index
                                  }
                                >
                                  <td>
                                    #
                                    {
                                      intelligence?.id
                                    }
                                  </td>

                                  <td>
                                    <span className="mono-text">
                                      {intelligence
                                        ?.ip_address ||
                                        intelligence
                                          ?.ip ||
                                        "—"}
                                    </span>
                                  </td>

                                  <td>
                                    {intelligence
                                      ?.source ||
                                      intelligence
                                        ?.provider ||
                                      "Threat Intelligence"}
                                  </td>

                                  <td>
                                    {formatDate(
                                      intelligence
                                        ?.created_at
                                    )}
                                  </td>
                                </tr>
                              )
                            )}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* ==================================================
                      BOTTOM ACTIONS
                  ================================================== */}

                  <div className="result-actions">

                    <button
                      type="button"
                      className="secondary-button"
                      onClick={
                        closeIncidentDetails
                      }
                      disabled={
                        updating ||
                        deleting
                      }
                    >
                      Close
                    </button>

                    <button
                      type="button"
                      className="settings-reset-button"
                      onClick={
                        handleDeleteIncident
                      }
                      disabled={
                        updating ||
                        deleting
                      }
                    >
                      {deleting
                        ? "Deleting..."
                        : "Delete Incident"}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// ==========================================================
// Export
// ==========================================================

export default Incidents;