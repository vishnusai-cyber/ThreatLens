# ==========================================================
# ThreatLens - Correlation Schemas
# ==========================================================

from pydantic import BaseModel


# ==========================================================
# VirusTotal Summary
# ==========================================================

class VirusTotalSummary(BaseModel):

    malicious: int

    suspicious: int

    harmless: int

    undetected: int

    reputation: int


# ==========================================================
# AbuseIPDB Summary
# ==========================================================

class AbuseIPDBSummary(BaseModel):

    confidence_score: int

    total_reports: int

    country: str | None = None

    isp: str | None = None


# ==========================================================
# AlienVault OTX Summary
# ==========================================================

class OTXSummary(BaseModel):

    pulse_count: int

    tags: list[str]


# ==========================================================
# Correlation Sources
# ==========================================================

class CorrelationSources(BaseModel):

    virustotal: VirusTotalSummary

    abuseipdb: AbuseIPDBSummary

    otx: OTXSummary


# ==========================================================
# Correlation Response
# ==========================================================

class CorrelationResponse(BaseModel):

    # ------------------------------------------------------
    # Target IP
    # ------------------------------------------------------

    ip: str

    # ------------------------------------------------------
    # Incident
    #
    # None when the scan is not associated with an incident.
    # ------------------------------------------------------

    incident_id: int | None = None

    # ------------------------------------------------------
    # ThreatLens Score
    # ------------------------------------------------------

    threatlens_score: int

    # ------------------------------------------------------
    # Severity
    # ------------------------------------------------------

    severity: str

    # ------------------------------------------------------
    # Recommended Action
    # ------------------------------------------------------

    recommendation: str

    # ------------------------------------------------------
    # Alert Information
    # ------------------------------------------------------

    alert_created: bool

    alert_id: int | None = None

    # ------------------------------------------------------
    # Intelligence Sources
    # ------------------------------------------------------

    sources: CorrelationSources