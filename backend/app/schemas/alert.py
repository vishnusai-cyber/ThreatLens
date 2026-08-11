from datetime import datetime

from pydantic import BaseModel


# ==========================================================
# Alert Base
# ==========================================================

class AlertBase(BaseModel):
    ip_address: str
    threatlens_score: int
    severity: str
    title: str
    description: str | None = None
    status: str = "Open"
    recommendation: str | None = None


# ==========================================================
# Alert Create
# ==========================================================

class AlertCreate(AlertBase):
    threat_score_id: int | None = None


# ==========================================================
# Alert Update
# ==========================================================

class AlertUpdate(BaseModel):
    status: str | None = None
    description: str | None = None
    recommendation: str | None = None


# ==========================================================
# Alert Response
# ==========================================================

class AlertResponse(AlertBase):
    id: int
    threat_score_id: int | None = None
    created_at: datetime | None = None
    resolved_at: datetime | None = None

    class Config:
        from_attributes = True


# ==========================================================
# Alert Statistics Response
# ==========================================================

class AlertStatsResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    resolved_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int