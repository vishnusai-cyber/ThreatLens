from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.sql import func

from app.database.database import Base


class IntelligenceLookup(Base):
    __tablename__ = "intelligence_lookups"

    id = Column(Integer, primary_key=True, index=True)

    ip = Column(String, nullable=False, index=True)

    source = Column(String, nullable=False)

    risk_score = Column(Integer, default=0)

    raw_response = Column(JSON, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )