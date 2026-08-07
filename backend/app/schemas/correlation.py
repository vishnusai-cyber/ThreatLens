from pydantic import BaseModel
from typing import List


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
    tags: List[str]


class CorrelationSources(BaseModel):
    virustotal: VirusTotalSummary
    abuseipdb: AbuseIPDBSummary
    otx: OTXSummary


class CorrelationResponse(BaseModel):
    ip: str
    threatlens_score: int
    severity: str
    recommendation: str
    sources: CorrelationSources