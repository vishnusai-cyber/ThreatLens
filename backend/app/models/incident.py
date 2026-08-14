from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.database.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    # ======================================================
    # Primary Key
    # ======================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ======================================================
    # Incident Information
    # ======================================================

    title = Column(
        String,
        nullable=False,
    )

    description = Column(
        Text,
        nullable=True,
    )

    severity = Column(
        String,
        nullable=False,
        default="medium",
        index=True,
    )

    status = Column(
        String,
        nullable=False,
        default="open",
        index=True,
    )

    ip_address = Column(
        String,
        nullable=True,
        index=True,
    )

    # ======================================================
    # Timestamps
    # ======================================================

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    # ======================================================
    # ThreatScore Relationship
    # ======================================================

    threat_scores = relationship(
        "ThreatScore",
        back_populates="incident",
        cascade="all, delete-orphan",
    )

    # ======================================================
    # Intelligence Lookup Relationship
    # ======================================================

    intelligence_lookups = relationship(
        "IntelligenceLookup",
        back_populates="incident",
    )

    # ======================================================
    # Alert Relationship
    # ======================================================

    alerts = relationship(
        "Alert",
        back_populates="incident",
    )