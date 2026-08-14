from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
)


# ==========================================================
# ThreatLens - Incident Schemas
# ==========================================================


# ==========================================================
# Severity Enum
# ==========================================================

class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ==========================================================
# Status Enum
# ==========================================================

class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


# ==========================================================
# Incident Base
# ==========================================================

class IncidentBase(BaseModel):

    title: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    description: Optional[str] = Field(
        default=None,
        max_length=5000,
    )

    severity: IncidentSeverity = (
        IncidentSeverity.MEDIUM
    )

    status: IncidentStatus = (
        IncidentStatus.OPEN
    )

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

    title: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=255,
    )

    description: Optional[str] = Field(
        default=None,
        max_length=5000,
    )

    severity: Optional[IncidentSeverity] = None

    status: Optional[IncidentStatus] = None

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

    intelligence: list[
        IncidentIntelligenceItem
    ]


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
# Incident Severity Statistics
# ==========================================================

class IncidentSeverityStats(BaseModel):

    critical: int

    high: int

    medium: int

    low: int


# ==========================================================
# Incident Status Statistics
# ==========================================================

class IncidentStatusStats(BaseModel):

    open: int

    investigating: int

    resolved: int


# ==========================================================
# Incident Dashboard Overview
# ==========================================================

class IncidentDashboardOverview(BaseModel):

    total_incidents: int

    severity: IncidentSeverityStats

    status: IncidentStatusStats