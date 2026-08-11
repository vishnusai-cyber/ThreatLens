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

  const response = await fetch(url, {
    ...options,

    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  // --------------------------------------------------------
  // Handle HTTP errors
  // --------------------------------------------------------

  if (!response.ok) {
    let errorMessage = `API request failed: ${response.status}`;

    try {
      const errorData = await response.json();

      if (errorData?.detail) {
        errorMessage =
          typeof errorData.detail === "string"
            ? errorData.detail
            : JSON.stringify(errorData.detail);
      } else if (errorData?.message) {
        errorMessage = errorData.message;
      }
    } catch {
      // Response was not JSON
    }

    throw new Error(errorMessage);
  }

  // --------------------------------------------------------
  // Handle empty / non-JSON response
  // --------------------------------------------------------

  const contentType = response.headers.get("content-type");

  if (
    !contentType ||
    !contentType.includes("application/json")
  ) {
    return null;
  }

  return await response.json();
}

// ==========================================================
// Dashboard API
// ==========================================================

// Dashboard overview
export async function getDashboardOverview() {
  return await apiRequest("/dashboard/overview");
}

// Severity distribution
export async function getSeverityDistribution() {
  return await apiRequest("/dashboard/severity");
}

// Top threat IPs
export async function getTopThreatIPs(limit = 10) {
  return await apiRequest(
    `/dashboard/top-ips?limit=${limit}`
  );
}

// Recent dashboard activity
export async function getRecentAlerts(limit = 10) {
  return await apiRequest(
    `/dashboard/recent?limit=${limit}`
  );
}

// ==========================================================
// Threat Activity / Trends API
// ==========================================================

export async function getThreatTrends() {
  return await apiRequest("/dashboard/trends");
}

// ==========================================================
// Intelligence Source Statistics
// ==========================================================

export async function getSourceStatistics() {
  return await apiRequest("/dashboard/sources");
}

// ==========================================================
// Alert Statistics
// ==========================================================

export async function getAlertStatistics() {
  return await apiRequest("/dashboard/alerts");
}

// ==========================================================
// Threat Intelligence API
// ==========================================================

// VirusTotal
export async function getVirusTotalIP(ip) {
  return await apiRequest(
    `/intelligence/ip/${encodeURIComponent(ip)}`
  );
}

// AbuseIPDB
export async function getAbuseIPDB(ip) {
  return await apiRequest(
    `/intelligence/abuseipdb/${encodeURIComponent(ip)}`
  );
}

// AlienVault OTX
export async function getOTX(ip) {
  return await apiRequest(
    `/intelligence/otx/${encodeURIComponent(ip)}`
  );
}

// Correlation
export async function correlateIP(ip) {
  return await apiRequest(
    `/intelligence/correlate/${encodeURIComponent(ip)}`
  );
}

// Intelligence history
export async function getIntelligenceHistory(
  limit = 10,
  offset = 0,
  ip = "",
  source = ""
) {
  const params = new URLSearchParams();

  params.append("limit", limit);
  params.append("offset", offset);

  if (ip) {
    params.append("ip", ip);
  }

  if (source) {
    params.append("source", source);
  }

  return await apiRequest(
    `/intelligence/history?${params.toString()}`
  );
}

// ==========================================================
// Threat API
// ==========================================================

// Get all threats
export async function getThreats() {
  return await apiRequest("/threats");
}

// Get single threat
export async function getThreat(id) {
  return await apiRequest(`/threats/${id}`);
}

// Create threat
export async function createThreat(threatData) {
  return await apiRequest("/threats", {
    method: "POST",
    body: JSON.stringify(threatData),
  });
}

// Delete threat
export async function deleteThreat(id) {
  return await apiRequest(`/threats/${id}`, {
    method: "DELETE",
  });
}

// ==========================================================
// Alerts API
// ==========================================================

// Get all alerts
export async function getAlerts() {
  return await apiRequest("/alerts");
}

// Get single alert
export async function getAlert(id) {
  return await apiRequest(`/alerts/${id}`);
}

// Create alert
export async function createAlert(alertData) {
  return await apiRequest("/alerts", {
    method: "POST",
    body: JSON.stringify(alertData),
  });
}

// ==========================================================
// Incidents API
// ==========================================================

// Get all incidents
export async function getIncidents() {
  return await apiRequest("/incidents");
}

// Get single incident
export async function getIncident(id) {
  return await apiRequest(`/incidents/${id}`);
}

// Create incident
export async function createIncident(incidentData) {
  return await apiRequest("/incidents", {
    method: "POST",
    body: JSON.stringify(incidentData),
  });
}

// ==========================================================
// Threat Map API
// ==========================================================

export async function getGlobalThreatMap() {
  return await apiRequest("/threat-map/global");
}

// ==========================================================
// Authentication API
// ==========================================================

// Register user
export async function registerUser(userData) {
  return await apiRequest("/auth/register", {
    method: "POST",
    body: JSON.stringify(userData),
  });
}

// Login user
export async function loginUser(username, password) {
  const formData = new URLSearchParams();

  formData.append("username", username);
  formData.append("password", password);

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

  // --------------------------------------------------------
  // Handle login errors
  // --------------------------------------------------------

  if (!response.ok) {
    let errorMessage =
      `Login failed: ${response.status}`;

    try {
      const errorData = await response.json();

      if (errorData?.detail) {
        errorMessage =
          typeof errorData.detail === "string"
            ? errorData.detail
            : JSON.stringify(errorData.detail);
      } else if (errorData?.message) {
        errorMessage = errorData.message;
      }
    } catch {
      // Ignore invalid JSON response
    }

    throw new Error(errorMessage);
  }

  return await response.json();
}

// ==========================================================
// Current User API
// ==========================================================

export async function getCurrentUser(token) {
  return await apiRequest("/users/me", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

// ==========================================================
// Admin API
// ==========================================================

export async function getAdminDashboard(token) {
  return await apiRequest("/admin/dashboard", {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
}

// ==========================================================
// Health Check
// ==========================================================

export async function checkBackendHealth() {
  return await apiRequest("/");
}

// ==========================================================
// Export API configuration
// ==========================================================

export { API_BASE_URL };