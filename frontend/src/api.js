// ==========================================================
// ThreatLens API Client
// ==========================================================

// FastAPI backend
const API_BASE_URL = "http://127.0.0.1:8001";

// ==========================================================
// Generic API Request Helper
// ==========================================================

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;

  const {
    headers: customHeaders = {},
    ...fetchOptions
  } = options;

  const response = await fetch(url, {
    ...fetchOptions,

    headers: {
      "Content-Type": "application/json",
      ...customHeaders,
    },
  });

  // ========================================================
  // HTTP ERROR
  // ========================================================

  if (!response.ok) {
    let errorMessage =
      `API request failed: ${response.status}`;

    try {
      const contentType =
        response.headers.get("content-type") || "";

      if (contentType.includes("application/json")) {
        const errorData = await response.json();

        // FastAPI validation error
        if (Array.isArray(errorData?.detail)) {
          errorMessage = errorData.detail
            .map((item) => {
              const location = Array.isArray(item?.loc)
                ? item.loc.join(" → ")
                : "field";

              return `${location}: ${
                item?.msg || "Validation error"
              }`;
            })
            .join("\n");
        }

        // FastAPI HTTPException
        else if (errorData?.detail) {
          errorMessage =
            typeof errorData.detail === "string"
              ? errorData.detail
              : JSON.stringify(errorData.detail);
        }

        // Generic API message
        else if (errorData?.message) {
          errorMessage =
            typeof errorData.message === "string"
              ? errorData.message
              : JSON.stringify(errorData.message);
        }
      } else {
        const text = await response.text();

        if (text) {
          errorMessage = text;
        }
      }
    } catch {
      // Keep default HTTP error
    }

    throw new Error(errorMessage);
  }

  // ========================================================
  // EMPTY RESPONSE
  // ========================================================

  if (response.status === 204) {
    return null;
  }

  // ========================================================
  // RESPONSE CONTENT TYPE
  // ========================================================

  const contentType =
    response.headers.get("content-type") || "";

  if (!contentType.includes("application/json")) {
    return null;
  }

  // ========================================================
  // JSON RESPONSE
  // ========================================================

  return await response.json();
}

// ==========================================================
// DASHBOARD API
// ==========================================================

// ----------------------------------------------------------
// Dashboard Overview
// ----------------------------------------------------------

export async function getDashboardOverview() {
  return await apiRequest(
    "/dashboard/overview"
  );
}

// ----------------------------------------------------------
// Severity Distribution
// ----------------------------------------------------------

export async function getSeverityDistribution() {
  return await apiRequest(
    "/dashboard/severity"
  );
}

// ----------------------------------------------------------
// Top Threat IPs
// ----------------------------------------------------------

export async function getTopThreatIPs(
  limit = 10
) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 10, 1),
    500
  );

  return await apiRequest(
    `/dashboard/top-ips?limit=${safeLimit}`
  );
}

// ----------------------------------------------------------
// Recent Alerts
// ----------------------------------------------------------

export async function getRecentAlerts(
  limit = 10
) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 10, 1),
    100
  );

  return await apiRequest(
    `/dashboard/recent?limit=${safeLimit}`
  );
}

// ----------------------------------------------------------
// Threat Trends
// ----------------------------------------------------------

export async function getThreatTrends() {
  return await apiRequest(
    "/dashboard/trends"
  );
}

// ----------------------------------------------------------
// Source Statistics
// ----------------------------------------------------------

export async function getSourceStatistics() {
  return await apiRequest(
    "/dashboard/sources"
  );
}

// ----------------------------------------------------------
// Alert Statistics
// ----------------------------------------------------------

export async function getAlertStatistics() {
  return await apiRequest(
    "/dashboard/alerts"
  );
}

// ==========================================================
// THREAT INTELLIGENCE API
// ==========================================================

// ----------------------------------------------------------
// VirusTotal
// ----------------------------------------------------------

export async function getVirusTotalIP(ip) {
  if (!ip || !ip.trim()) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/ip/${encodeURIComponent(
      ip.trim()
    )}`
  );
}

// ----------------------------------------------------------
// AbuseIPDB
// ----------------------------------------------------------

export async function getAbuseIPDB(ip) {
  if (!ip || !ip.trim()) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/abuseipdb/${encodeURIComponent(
      ip.trim()
    )}`
  );
}

// ----------------------------------------------------------
// AlienVault OTX
// ----------------------------------------------------------

export async function getOTX(ip) {
  if (!ip || !ip.trim()) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/otx/${encodeURIComponent(
      ip.trim()
    )}`
  );
}

// ==========================================================
// CORRELATION ENGINE
// ==========================================================

export async function correlateIP(ip) {
  if (!ip || !ip.trim()) {
    throw new Error(
      "IP address is required."
    );
  }

  console.log(
    "ThreatLens API: Correlating IP:",
    ip.trim()
  );

  return await apiRequest(
    `/intelligence/correlate/${encodeURIComponent(
      ip.trim()
    )}`
  );
}

// ----------------------------------------------------------
// Threat Scan Alias
// ----------------------------------------------------------

export async function runThreatScan(ip) {
  return await correlateIP(ip);
}

// ==========================================================
// INTELLIGENCE HISTORY
// ==========================================================

export async function getIntelligenceHistory(
  limit = 10,
  offset = 0,
  ip = "",
  source = ""
) {
  const params =
    new URLSearchParams();

  params.set(
    "limit",
    String(limit)
  );

  params.set(
    "offset",
    String(offset)
  );

  if (ip?.trim()) {
    params.set(
      "ip",
      ip.trim()
    );
  }

  if (source?.trim()) {
    params.set(
      "source",
      source.trim()
    );
  }

  return await apiRequest(
    `/intelligence/history?${params.toString()}`
  );
}

// ==========================================================
// THREATS API
// ==========================================================

// ----------------------------------------------------------
// Get Threats
// ----------------------------------------------------------

export async function getThreats() {
  return await apiRequest(
    "/threats"
  );
}

// ----------------------------------------------------------
// Get Threat
// ----------------------------------------------------------

export async function getThreat(id) {
  if (!id) {
    throw new Error(
      "Threat ID is required."
    );
  }

  return await apiRequest(
    `/threats/${id}`
  );
}

// ----------------------------------------------------------
// Create Threat
// ----------------------------------------------------------

export async function createThreat(
  threatData
) {
  if (!threatData) {
    throw new Error(
      "Threat data is required."
    );
  }

  return await apiRequest(
    "/threats",
    {
      method: "POST",
      body: JSON.stringify(
        threatData
      ),
    }
  );
}

// ----------------------------------------------------------
// Delete Threat
// ----------------------------------------------------------

export async function deleteThreat(id) {
  if (!id) {
    throw new Error(
      "Threat ID is required."
    );
  }

  return await apiRequest(
    `/threats/${id}`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// ALERTS API
// ==========================================================

// ----------------------------------------------------------
// Get Alerts
// ----------------------------------------------------------

export async function getAlerts() {
  return await apiRequest(
    "/alerts"
  );
}

// ----------------------------------------------------------
// Get Alert
// ----------------------------------------------------------

export async function getAlert(id) {
  if (!id) {
    throw new Error(
      "Alert ID is required."
    );
  }

  return await apiRequest(
    `/alerts/${id}`
  );
}

// ----------------------------------------------------------
// Create Alert
// ----------------------------------------------------------

export async function createAlert(
  alertData
) {
  if (!alertData) {
    throw new Error(
      "Alert data is required."
    );
  }

  return await apiRequest(
    "/alerts",
    {
      method: "POST",
      body: JSON.stringify(
        alertData
      ),
    }
  );
}

// ----------------------------------------------------------
// Update Alert
// ----------------------------------------------------------

export async function updateAlert(
  id,
  alertData
) {
  if (!id) {
    throw new Error(
      "Alert ID is required."
    );
  }

  if (!alertData) {
    throw new Error(
      "Alert data is required."
    );
  }

  return await apiRequest(
    `/alerts/${id}`,
    {
      method: "PUT",
      body: JSON.stringify(
        alertData
      ),
    }
  );
}

// ----------------------------------------------------------
// Delete Alert
// ----------------------------------------------------------

export async function deleteAlert(id) {
  if (!id) {
    throw new Error(
      "Alert ID is required."
    );
  }

  return await apiRequest(
    `/alerts/${id}`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// INCIDENTS API
// ==========================================================

// ----------------------------------------------------------
// Get All Incidents
// ----------------------------------------------------------

export async function getIncidents(
  skip = 0,
  limit = 100
) {
  const safeSkip = Math.max(
    Number(skip) || 0,
    0
  );

  const safeLimit = Math.min(
    Math.max(Number(limit) || 100, 1),
    500
  );

  return await apiRequest(
    `/incidents?skip=${safeSkip}&limit=${safeLimit}`
  );
}

// ----------------------------------------------------------
// Get Single Incident
// ----------------------------------------------------------

export async function getIncident(id) {
  if (!id) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${id}`
  );
}

// ----------------------------------------------------------
// Create Incident
// ----------------------------------------------------------

export async function createIncident(
  incidentData
) {
  if (!incidentData) {
    throw new Error(
      "Incident data is required."
    );
  }

  const payload = {
    title:
      incidentData.title?.trim() || "",

    description:
      incidentData.description?.trim() ||
      null,

    severity:
      String(
        incidentData.severity ||
          "medium"
      ).toLowerCase(),

    status:
      String(
        incidentData.status ||
          "open"
      ).toLowerCase(),

    ip_address:
      incidentData.ip_address?.trim() ||
      null,
  };

  if (!payload.title) {
    throw new Error(
      "Incident title is required."
    );
  }

  console.log(
    "ThreatLens API: Creating incident:",
    payload
  );

  return await apiRequest(
    "/incidents",
    {
      method: "POST",
      body: JSON.stringify(
        payload
      ),
    }
  );
}

// ----------------------------------------------------------
// Update Incident
// ----------------------------------------------------------

export async function updateIncident(
  id,
  incidentData
) {
  if (!id) {
    throw new Error(
      "Incident ID is required."
    );
  }

  if (!incidentData) {
    throw new Error(
      "Incident data is required."
    );
  }

  const payload = {};

  if (
    incidentData.title !==
    undefined
  ) {
    payload.title =
      incidentData.title?.trim() ||
      "";
  }

  if (
    incidentData.description !==
    undefined
  ) {
    payload.description =
      incidentData.description?.trim() ||
      null;
  }

  if (
    incidentData.severity !==
    undefined
  ) {
    payload.severity =
      String(
        incidentData.severity
      ).toLowerCase();
  }

  if (
    incidentData.status !==
    undefined
  ) {
    payload.status =
      String(
        incidentData.status
      ).toLowerCase();
  }

  if (
    incidentData.ip_address !==
    undefined
  ) {
    payload.ip_address =
      incidentData.ip_address?.trim() ||
      null;
  }

  console.log(
    "ThreatLens API: Updating incident:",
    id,
    payload
  );

  return await apiRequest(
    `/incidents/${id}`,
    {
      method: "PUT",
      body: JSON.stringify(
        payload
      ),
    }
  );
}

// ----------------------------------------------------------
// Delete Incident
// ----------------------------------------------------------

export async function deleteIncident(
  id
) {
  if (!id) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${id}`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// INCIDENT STATISTICS
// ==========================================================

// Backend:
// GET /incidents/stats

export async function getIncidentStats() {
  return await apiRequest(
    "/incidents/stats"
  );
}

// ==========================================================
// INCIDENT DASHBOARD
// ==========================================================

// ----------------------------------------------------------
// Incident Dashboard Overview
// ----------------------------------------------------------

export async function getIncidentDashboardOverview() {
  return await apiRequest(
    "/incidents/dashboard/overview"
  );
}

// ----------------------------------------------------------
// Incident Severity Distribution
// ----------------------------------------------------------

export async function getIncidentSeverityDistribution() {
  return await apiRequest(
    "/incidents/dashboard/incidents/severity"
  );
}

// ----------------------------------------------------------
// Incident Status Distribution
// ----------------------------------------------------------

export async function getIncidentStatusDistribution() {
  return await apiRequest(
    "/incidents/dashboard/incidents/status"
  );
}

// ----------------------------------------------------------
// Recent Incidents
// ----------------------------------------------------------

export async function getRecentIncidents(
  limit = 10
) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 10, 1),
    100
  );

  return await apiRequest(
    `/incidents/dashboard/recent?limit=${safeLimit}`
  );
}

// ----------------------------------------------------------
// Incident Activity
// ----------------------------------------------------------

export async function getIncidentActivity(
  limit = 10
) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 10, 1),
    100
  );

  return await apiRequest(
    `/incidents/dashboard/activity?limit=${safeLimit}`
  );
}

// ==========================================================
// INCIDENT INTELLIGENCE
// ==========================================================

export async function getIncidentIntelligence(
  incidentId,
  limit = 10,
  offset = 0
) {
  if (!incidentId) {
    throw new Error(
      "Incident ID is required."
    );
  }

  const safeLimit = Math.min(
    Math.max(Number(limit) || 10, 1),
    100
  );

  const safeOffset = Math.max(
    Number(offset) || 0,
    0
  );

  return await apiRequest(
    `/incidents/${incidentId}/intelligence?limit=${safeLimit}&offset=${safeOffset}`
  );
}

// ==========================================================
// INCIDENT THREAT SCORE
// ==========================================================

// ----------------------------------------------------------
// Calculate Fresh Score
// ----------------------------------------------------------

export async function getIncidentScore(
  incidentId
) {
  if (!incidentId) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${incidentId}/score`
  );
}

// ----------------------------------------------------------
// Get Stored Score
// ----------------------------------------------------------

export async function getStoredIncidentScore(
  incidentId
) {
  if (!incidentId) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${incidentId}/stored-score`
  );
}

// ==========================================================
// INTELLIGENCE ↔ INCIDENT
// ==========================================================

// ----------------------------------------------------------
// Attach Lookup
// ----------------------------------------------------------

export async function attachLookupToIncident(
  lookupId,
  incidentId
) {
  if (!lookupId) {
    throw new Error(
      "Lookup ID is required."
    );
  }

  if (!incidentId) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/intelligence/lookup/${lookupId}/incident/${incidentId}`,
    {
      method: "POST",
    }
  );
}

// ----------------------------------------------------------
// Detach Lookup
// ----------------------------------------------------------

export async function detachLookupFromIncident(
  lookupId
) {
  if (!lookupId) {
    throw new Error(
      "Lookup ID is required."
    );
  }

  return await apiRequest(
    `/intelligence/lookup/${lookupId}/incident`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// THREAT MAP
// ==========================================================

export async function getGlobalThreatMap(
  limit = 100
) {
  const safeLimit = Math.min(
    Math.max(Number(limit) || 100, 1),
    500
  );

  return await apiRequest(
    `/threat-map?limit=${safeLimit}`
  );
}

// ==========================================================
// AUTHENTICATION
// ==========================================================

// ----------------------------------------------------------
// Register
// ----------------------------------------------------------

export async function registerUser(
  userData
) {
  if (!userData) {
    throw new Error(
      "User data is required."
    );
  }

  return await apiRequest(
    "/auth/register",
    {
      method: "POST",
      body: JSON.stringify(
        userData
      ),
    }
  );
}

// ----------------------------------------------------------
// Login
// ----------------------------------------------------------

export async function loginUser(
  username,
  password
) {
  if (!username?.trim()) {
    throw new Error(
      "Username is required."
    );
  }

  if (!password) {
    throw new Error(
      "Password is required."
    );
  }

  const formData =
    new URLSearchParams();

  formData.append(
    "username",
    username.trim()
  );

  formData.append(
    "password",
    password
  );

  const response = await fetch(
    `${API_BASE_URL}/auth/login`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },

      body: formData,
    }
  );

  if (!response.ok) {
    let errorMessage =
      `Login failed: ${response.status}`;

    try {
      const contentType =
        response.headers.get(
          "content-type"
        ) || "";

      if (
        contentType.includes(
          "application/json"
        )
      ) {
        const errorData =
          await response.json();

        if (
          Array.isArray(
            errorData?.detail
          )
        ) {
          errorMessage =
            errorData.detail
              .map(
                (item) =>
                  item?.msg ||
                  "Validation error"
              )
              .join("\n");
        } else if (
          errorData?.detail
        ) {
          errorMessage =
            typeof errorData.detail ===
            "string"
              ? errorData.detail
              : JSON.stringify(
                  errorData.detail
                );
        }
      }
    } catch {
      // Ignore malformed error response
    }

    throw new Error(
      errorMessage
    );
  }

  return await response.json();
}

// ==========================================================
// CURRENT USER
// ==========================================================

export async function getCurrentUser(
  token
) {
  if (!token) {
    throw new Error(
      "Authentication token is required."
    );
  }

  return await apiRequest(
    "/users/me",
    {
      headers: {
        Authorization:
          `Bearer ${token}`,
      },
    }
  );
}

// ==========================================================
// ADMIN
// ==========================================================

export async function getAdminDashboard(
  token
) {
  if (!token) {
    throw new Error(
      "Authentication token is required."
    );
  }

  return await apiRequest(
    "/admin/dashboard",
    {
      headers: {
        Authorization:
          `Bearer ${token}`,
      },
    }
  );
}

// ==========================================================
// HEALTH CHECK
// ==========================================================

export async function checkBackendHealth() {
  return await apiRequest("/");
}

// ==========================================================
// EXPORT
// ==========================================================

export {
  API_BASE_URL,
};