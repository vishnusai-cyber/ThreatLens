// ==========================================================
// ThreatLens API Client
// Production Ready
// ==========================================================

// ==========================================================
// API BASE URL
// ==========================================================

const API_BASE_URL =
  "https://threatlens-backend-skzr.onrender.com";

// ==========================================================
// Token Storage
// ==========================================================

const TOKEN_KEY = "threatlens_access_token";

// ==========================================================
// Generic API Request
// ==========================================================

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;

  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };

  // Automatically add JSON content type
  // for JSON request bodies.
  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !(options.body instanceof URLSearchParams) &&
    typeof options.body === "string"
  ) {
    headers["Content-Type"] = "application/json";
  }

  // Add JWT token automatically.
  const token = getAuthToken();

  if (token && !headers.Authorization) {
    headers.Authorization = `Bearer ${token}`;
  }

  let response;

  try {
    response = await fetch(url, {
      ...options,
      headers,
    });
  } catch (error) {
    console.error(
      "[ThreatLens API] Connection error:",
      error
    );

    throw new Error(
      "Unable to connect to ThreatLens API. Please verify that the backend is running."
    );
  }

  // ========================================================
  // Read Response
  // ========================================================

  const contentType =
    response.headers.get("content-type") || "";

  let data = null;

  try {
    if (
      contentType.includes(
        "application/json"
      )
    ) {
      data = await response.json();
    } else {
      data = await response.text();
    }
  } catch {
    data = null;
  }

  // ========================================================
  // Unauthorized
  // ========================================================

  if (response.status === 401) {
    logoutUser();

    throw new Error(
      "Your session has expired. Please sign in again."
    );
  }

  // ========================================================
  // API Errors
  // ========================================================

  if (!response.ok) {
    let message =
      `Request failed with status ${response.status}`;

    if (
      typeof data === "string" &&
      data.trim()
    ) {
      message = data;
    } else if (data?.detail) {
      if (Array.isArray(data.detail)) {
        message = data.detail
          .map((item) => {
            if (typeof item === "string") {
              return item;
            }

            return (
              item?.msg ||
              item?.message ||
              JSON.stringify(item)
            );
          })
          .join(", ");
      } else {
        message = String(data.detail);
      }
    } else if (data?.message) {
      message = String(data.message);
    }

    throw new Error(message);
  }

  return data;
}

// ==========================================================
// AUTHENTICATION
// ==========================================================

export function getAuthToken() {
  try {
    return localStorage.getItem(
      TOKEN_KEY
    );
  } catch {
    return null;
  }
}

function saveAuthToken(token) {
  if (!token) {
    return;
  }

  try {
    localStorage.setItem(
      TOKEN_KEY,
      token
    );
  } catch (error) {
    console.error(
      "[ThreatLens] Unable to save authentication token:",
      error
    );
  }
}

export function logoutUser() {
  try {
    localStorage.removeItem(
      TOKEN_KEY
    );
  } catch (error) {
    console.error(
      "[ThreatLens] Unable to remove authentication token:",
      error
    );
  }
}

// ==========================================================
// LOGIN
// ==========================================================

export async function loginUser(
  email,
  password
) {
  const cleanEmail =
    String(email || "").trim();

  if (!cleanEmail) {
    throw new Error(
      "Email is required."
    );
  }

  if (!password) {
    throw new Error(
      "Password is required."
    );
  }

  console.log(
    "[ThreatLens] POST /auth/login",
    {
      email: cleanEmail,
    }
  );

  const data = await apiRequest(
    "/auth/login",
    {
      method: "POST",

      body: JSON.stringify({
        email: cleanEmail,
        password,
      }),
    }
  );

  if (!data?.access_token) {
    throw new Error(
      "Login succeeded, but the server did not return an access token."
    );
  }

  saveAuthToken(
    data.access_token
  );

  return data;
}

// ==========================================================
// REGISTER
// ==========================================================

export async function registerUser(
  userData
) {
  if (!userData) {
    throw new Error(
      "Registration data is required."
    );
  }

  const username =
    String(
      userData.username || ""
    ).trim();

  const email =
    String(
      userData.email || ""
    ).trim();

  const password =
    userData.password || "";

  const role =
    userData.role || "viewer";

  if (!username) {
    throw new Error(
      "Username is required."
    );
  }

  if (!email) {
    throw new Error(
      "Email is required."
    );
  }

  if (!password) {
    throw new Error(
      "Password is required."
    );
  }

  console.log(
    "[ThreatLens] POST /auth/register",
    {
      username,
      email,
      role,
    }
  );

  return await apiRequest(
    "/auth/register",
    {
      method: "POST",

      body: JSON.stringify({
        username,
        email,
        password,
        role,
      }),
    }
  );
}

// ==========================================================
// CURRENT USER
// ==========================================================

export async function getCurrentUser(
  token = null
) {
  const authToken =
    token || getAuthToken();

  if (!authToken) {
    throw new Error(
      "No authentication token."
    );
  }

  return await apiRequest(
    "/auth/me",
    {
      method: "GET",

      headers: {
        Authorization:
          `Bearer ${authToken}`,
      },
    }
  );
}

// ==========================================================
// DASHBOARD
// ==========================================================

export async function getDashboardOverview() {
  return await apiRequest(
    "/dashboard/overview",
    {
      method: "GET",
    }
  );
}

export async function getSeverityDistribution() {
  return await apiRequest(
    "/dashboard/severity",
    {
      method: "GET",
    }
  );
}

export async function getTopThreatIPs(
  limit = 10
) {
  return await apiRequest(
    `/dashboard/top-ips?limit=${encodeURIComponent(
      limit
    )}`,
    {
      method: "GET",
    }
  );
}

export async function getRecentAlerts(
  limit = 10
) {
  return await apiRequest(
    `/dashboard/recent?limit=${encodeURIComponent(
      limit
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// THREAT TRENDS
// ==========================================================

export async function getThreatTrends() {
  return await apiRequest(
    "/dashboard/trends",
    {
      method: "GET",
    }
  );
}

// ==========================================================
// THREAT INTELLIGENCE
// ==========================================================

export async function getThreatIntelligence(
  ip
) {
  const cleanIP =
    String(ip || "").trim();

  if (!cleanIP) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/ip/${encodeURIComponent(
      cleanIP
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// ABUSEIPDB
// ==========================================================

export async function getAbuseIPDB(
  ip
) {
  const cleanIP =
    String(ip || "").trim();

  if (!cleanIP) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/abuseipdb/${encodeURIComponent(
      cleanIP
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// ALIENVAULT OTX
// ==========================================================

export async function getOTX(ip) {
  const cleanIP =
    String(ip || "").trim();

  if (!cleanIP) {
    throw new Error(
      "IP address is required."
    );
  }

  return await apiRequest(
    `/intelligence/otx/${encodeURIComponent(
      cleanIP
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// CORRELATION ENGINE
// ==========================================================

export async function correlateIP(
  ip
) {
  const cleanIP =
    String(ip || "").trim();

  if (!cleanIP) {
    throw new Error(
      "IP address is required."
    );
  }

  console.log(
    `[ThreatLens] Correlating IP: ${cleanIP}`
  );

  return await apiRequest(
    `/intelligence/correlate/${encodeURIComponent(
      cleanIP
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// INTELLIGENCE HISTORY
// ==========================================================

export async function getIntelligenceHistory(
  limit = 20,
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

  if (ip) {
    params.set(
      "ip",
      String(ip).trim()
    );
  }

  if (source) {
    params.set(
      "source",
      String(source).trim()
    );
  }

  return await apiRequest(
    `/intelligence/history?${params.toString()}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// THREATS
// ==========================================================

export async function getThreats() {
  return await apiRequest(
    "/threats",
    {
      method: "GET",
    }
  );
}

export async function getThreat(
  id
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Threat ID is required."
    );
  }

  return await apiRequest(
    `/threats/${encodeURIComponent(
      id
    )}`,
    {
      method: "GET",
    }
  );
}

export async function createThreat(
  data
) {
  if (!data) {
    throw new Error(
      "Threat data is required."
    );
  }

  return await apiRequest(
    "/threats",
    {
      method: "POST",
      body: JSON.stringify(data),
    }
  );
}

export async function updateThreat(
  id,
  data
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Threat ID is required."
    );
  }

  return await apiRequest(
    `/threats/${encodeURIComponent(
      id
    )}`,
    {
      method: "PUT",
      body: JSON.stringify(data),
    }
  );
}

export async function deleteThreat(
  id
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Threat ID is required."
    );
  }

  return await apiRequest(
    `/threats/${encodeURIComponent(
      id
    )}`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// ALERTS
// ==========================================================

export async function getAlerts() {
  return await apiRequest(
    "/alerts",
    {
      method: "GET",
    }
  );
}

export async function createAlert(
  data
) {
  if (!data) {
    throw new Error(
      "Alert data is required."
    );
  }

  return await apiRequest(
    "/alerts",
    {
      method: "POST",
      body: JSON.stringify(data),
    }
  );
}

export async function updateAlert(
  id,
  data
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Alert ID is required."
    );
  }

  return await apiRequest(
    `/alerts/${encodeURIComponent(
      id
    )}`,
    {
      method: "PUT",
      body: JSON.stringify(data),
    }
  );
}

// ==========================================================
// INCIDENTS
// ==========================================================

export async function getIncidents() {
  return await apiRequest(
    "/incidents",
    {
      method: "GET",
    }
  );
}

export async function getIncident(
  id
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${encodeURIComponent(
      id
    )}`,
    {
      method: "GET",
    }
  );
}

export async function getIncidentStats() {
  return await apiRequest(
    "/incidents/stats",
    {
      method: "GET",
    }
  );
}

// ==========================================================
// CREATE INCIDENT
// ==========================================================

export async function createIncident(data) {
  if (!data || typeof data !== "object") {
    throw new Error(
      "Incident data is required."
    );
  }

  // --------------------------------------------------------
  // Normalize severity.
  //
  // FastAPI expects ONLY:
  // critical / high / medium / low
  // --------------------------------------------------------

  const severity = String(
    data.severity || "medium"
  )
    .trim()
    .toLowerCase();

  const allowedSeverities = [
    "critical",
    "high",
    "medium",
    "low",
  ];

  if (
    !allowedSeverities.includes(
      severity
    )
  ) {
    throw new Error(
      "Invalid severity. Please select Critical, High, Medium or Low."
    );
  }

  // --------------------------------------------------------
  // Build clean payload
  // --------------------------------------------------------

  const payload = {
    title: String(
      data.title || ""
    ).trim(),

    description: String(
      data.description || ""
    ).trim(),

    severity,

    ip_address:
      data.ip_address === null ||
      data.ip_address === undefined ||
      String(
        data.ip_address
      ).trim() === ""
        ? null
        : String(
            data.ip_address
          ).trim(),
  };

  // --------------------------------------------------------
  // Validation
  // --------------------------------------------------------

  if (!payload.title) {
    throw new Error(
      "Incident title is required."
    );
  }

  if (!payload.description) {
    throw new Error(
      "Incident description is required."
    );
  }

  // --------------------------------------------------------
  // Debug
  // --------------------------------------------------------

  console.log(
    "[ThreatLens] POST /incidents payload:",
    payload
  );

  // --------------------------------------------------------
  // Send request
  // --------------------------------------------------------

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

// ==========================================================
// UPDATE INCIDENT
// ==========================================================

export async function updateIncident(
  id,
  data
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Incident ID is required."
    );
  }

  if (!data || typeof data !== "object") {
    throw new Error(
      "Incident update data is required."
    );
  }

  // --------------------------------------------------------
  // Normalize severity if it is included in an update.
  // --------------------------------------------------------

  const payload = {
    ...data,
  };

  if (
    payload.severity !==
      undefined &&
    payload.severity !== null
  ) {
    payload.severity = String(
      payload.severity
    )
      .trim()
      .toLowerCase();

    const allowedSeverities = [
      "critical",
      "high",
      "medium",
      "low",
    ];

    if (
      !allowedSeverities.includes(
        payload.severity
      )
    ) {
      throw new Error(
        "Invalid severity. Please select Critical, High, Medium or Low."
      );
    }
  }

  // --------------------------------------------------------
  // Normalize status if included.
  // --------------------------------------------------------

  if (
    payload.status !==
      undefined &&
    payload.status !== null
  ) {
    payload.status = String(
      payload.status
    )
      .trim()
      .toLowerCase()
      .replaceAll(" ", "_");
  }

  console.log(
    "[ThreatLens] PUT /incidents payload:",
    payload
  );

  return await apiRequest(
    `/incidents/${encodeURIComponent(
      id
    )}`,
    {
      method: "PUT",
      body: JSON.stringify(
        payload
      ),
    }
  );
}

// ==========================================================
// DELETE INCIDENT
// ==========================================================

export async function deleteIncident(
  id
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${encodeURIComponent(
      id
    )}`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// INCIDENT INTELLIGENCE
// ==========================================================

export async function getIncidentIntelligence(
  incidentId
) {
  if (
    incidentId === undefined ||
    incidentId === null
  ) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/incidents/${encodeURIComponent(
      incidentId
    )}/intelligence`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// ATTACH INTELLIGENCE TO INCIDENT
// ==========================================================

export async function attachIntelligenceToIncident(
  lookupId,
  incidentId
) {
  if (
    lookupId === undefined ||
    lookupId === null
  ) {
    throw new Error(
      "Lookup ID is required."
    );
  }

  if (
    incidentId === undefined ||
    incidentId === null
  ) {
    throw new Error(
      "Incident ID is required."
    );
  }

  return await apiRequest(
    `/intelligence/lookup/${encodeURIComponent(
      lookupId
    )}/incident/${encodeURIComponent(
      incidentId
    )}`,
    {
      method: "POST",
    }
  );
}

// ==========================================================
// DETACH INTELLIGENCE FROM INCIDENT
// ==========================================================

export async function detachIntelligenceFromIncident(
  lookupId
) {
  if (
    lookupId === undefined ||
    lookupId === null
  ) {
    throw new Error(
      "Lookup ID is required."
    );
  }

  return await apiRequest(
    `/intelligence/lookup/${encodeURIComponent(
      lookupId
    )}/incident`,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// THREAT SCORES
// ==========================================================

export async function getThreatScores(
  limit = 10,
  offset = 0
) {
  return await apiRequest(
    `/threat-scores?limit=${encodeURIComponent(
      limit
    )}&offset=${encodeURIComponent(
      offset
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// SINGLE THREAT SCORE
// ==========================================================

export async function getThreatScore(
  id
) {
  if (
    id === undefined ||
    id === null
  ) {
    throw new Error(
      "Threat score ID is required."
    );
  }

  return await apiRequest(
    `/threat-scores/${encodeURIComponent(
      id
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// THREAT MAP
// ==========================================================

export async function getThreatMap(
  limit = 100
) {
  return await apiRequest(
    `/threat-map?limit=${encodeURIComponent(
      limit
    )}`,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// GENERIC GET
// ==========================================================

export async function apiGet(
  endpoint
) {
  if (!endpoint) {
    throw new Error(
      "API endpoint is required."
    );
  }

  return await apiRequest(
    endpoint,
    {
      method: "GET",
    }
  );
}

// ==========================================================
// GENERIC POST
// ==========================================================

export async function apiPost(
  endpoint,
  data
) {
  if (!endpoint) {
    throw new Error(
      "API endpoint is required."
    );
  }

  return await apiRequest(
    endpoint,
    {
      method: "POST",
      body: JSON.stringify(data),
    }
  );
}

// ==========================================================
// GENERIC PUT
// ==========================================================

export async function apiPut(
  endpoint,
  data
) {
  if (!endpoint) {
    throw new Error(
      "API endpoint is required."
    );
  }

  return await apiRequest(
    endpoint,
    {
      method: "PUT",
      body: JSON.stringify(data),
    }
  );
}

// ==========================================================
// GENERIC DELETE
// ==========================================================

export async function apiDelete(
  endpoint
) {
  if (!endpoint) {
    throw new Error(
      "API endpoint is required."
    );
  }

  return await apiRequest(
    endpoint,
    {
      method: "DELETE",
    }
  );
}

// ==========================================================
// API CONFIGURATION
// ==========================================================

export {
  API_BASE_URL,
};