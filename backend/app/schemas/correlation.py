from pydantic import BaseModel


class VirusTotalSummary(BaseModel):
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    reputation: int


class AbuseIPDBSummary(BaseModel):
    confidence_score: int
    total_reports: int
    country: str | None = None
    isp: str | None = None


class OTXSummary(BaseModel):
    pulse_count: int
    tags: list[str]


class CorrelationSources(BaseModel):
    virustotal: VirusTotalSummary
    abuseipdb: AbuseIPDBSummary
    otx: OTXSummary


class CorrelationResponse(BaseModel):
    ip: str
    threatlens_score: int
    severity: str
    recommendation: str
    alert_created: bool
    alert_id: int | None = None
    sources: CorrelationSources