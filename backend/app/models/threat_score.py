from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.database.database import Base


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id = Column(Integer, primary_key=True, index=True)

    ip_address = Column(String, nullable=False, index=True)

    threatlens_score = Column(Integer, nullable=False)

    severity = Column(String, nullable=False)

    recommendation = Column(String, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )