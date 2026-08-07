from datetime import datetime, date

from pydantic import BaseModel


# ==========================================================
# Dashboard Overview
# ==========================================================
class DashboardOverview(BaseModel):
    total_scans: int
    unique_ips: int
    critical: int
    high: int
    medium: int
    low: int


# ==========================================================
# Severity Distribution
# ==========================================================
class SeverityItem(BaseModel):
    severity: str
    count: int


# ==========================================================
# Top Malicious IPs
# ==========================================================
class TopIP(BaseModel):
    ip_address: str
    score: int
    severity: str


# ==========================================================
# Recent Activity
# ==========================================================
class RecentActivity(BaseModel):
    ip_address: str
    score: int
    severity: str
    created_at: datetime


# ==========================================================
# Intelligence Source Statistics
# ==========================================================
class SourceStatistic(BaseModel):
    source: str
    count: int


# ==========================================================
# Threat Trends
# ==========================================================
class TrendItem(BaseModel):
    date: date
    count: int