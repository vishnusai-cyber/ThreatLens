from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


# =========================
# Base Schema
# =========================

class ThreatBase(BaseModel):
    title: str
    ioc_type: str
    ioc_value: str
    severity: str
    status: str = "Open"
    source: Optional[str] = None
    description: Optional[str] = None


# =========================
# Create Threat
# =========================

class ThreatCreate(ThreatBase):
    pass


# =========================
# Update Threat
# =========================

class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    source: Optional[str] = None
    description: Optional[str] = None


# =========================
# Response Schema
# =========================

class ThreatResponse(ThreatBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)