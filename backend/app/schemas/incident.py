
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, IPvAnyAddress


# ==========================================================
# Incident Base Schema
# ==========================================================

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    status: str = "open"
    ip_address: Optional[IPvAnyAddress] = None


# ==========================================================
# Create Incident
# ==========================================================

class IncidentCreate(IncidentBase):
    pass


# ==========================================================
# Update Incident
# ==========================================================

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    ip_address: Optional[IPvAnyAddress] = None


# ==========================================================
# Incident Response
# ==========================================================

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    ip_address: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Incident Intelligence Item
# ==========================================================

class IncidentIntelligenceItem(BaseModel):
    id: int
    ip: str
    source: str
    risk_score: Optional[int] = None
    incident_id: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Incident Intelligence Response
# ==========================================================

class IncidentIntelligenceResponse(BaseModel):
    incident: IncidentResponse

    filters: dict

    pagination: dict

    intelligence: list[IncidentIntelligenceItem]


# ==========================================================
# Incident Statistics
# ==========================================================

class IncidentStats(BaseModel):
    total: int

    open: int
    investigating: int
    resolved: int

    critical: int
    high: int
    medium: int
    low: int
    
    
    # ==========================================================
# Incident Dashboard Schemas
# ==========================================================

class IncidentSeverityStats(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class IncidentStatusStats(BaseModel):
    open: int
    investigating: int
    resolved: int


class IncidentDashboardOverview(BaseModel):
    total_incidents: int

    severity: IncidentSeverityStats

    status: IncidentStatusStats

