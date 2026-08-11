from pydantic import BaseModel
from datetime import datetime


class IntelligenceHistoryResponse(BaseModel):
    id: int
    ip: str
    source: str
    risk_score: int
    incident_id: int | None = None
    created_at: datetime

    class Config:
        from_attributes = True
