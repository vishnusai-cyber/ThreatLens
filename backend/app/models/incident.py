from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database.base import Base


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String(255),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    severity = Column(
        String(50),
        nullable=False,
        default="medium"
    )

    status = Column(
        String(50),
        nullable=False,
        default="open"
    )

    ip_address = Column(
        String(45),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # ==========================================================
    # Intelligence Relationship
    # ==========================================================

    intelligence_lookups = relationship(
        "IntelligenceLookup",
        back_populates="incident"
    )

    # ==========================================================
    # Threat Score Relationship
    # ==========================================================

    threat_scores = relationship(
        "ThreatScore",
        back_populates="incident",
        cascade="all, delete-orphan"
    )