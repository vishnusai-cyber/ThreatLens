# ==========================================================
# ThreatLens - Threat Score Model
# ==========================================================

from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
)

from sqlalchemy.sql import func

from sqlalchemy.orm import relationship

from app.database.base import Base


# ==========================================================
# Threat Score
# ==========================================================

class ThreatScore(Base):

    __tablename__ = "threat_scores"

    # ======================================================
    # Primary Key
    # ======================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ======================================================
    # IP Address
    # ======================================================

    ip_address = Column(
        String,
        nullable=False,
        index=True,
    )

    # ======================================================
    # ThreatLens Score
    # ======================================================

    threatlens_score = Column(
        Integer,
        nullable=False,
    )

    # ======================================================
    # Severity
    # ======================================================

    severity = Column(
        String,
        nullable=False,
        index=True,
    )

    # ======================================================
    # Recommendation
    # ======================================================

    recommendation = Column(
        String,
        nullable=False,
    )

    # ======================================================
    # Incident Relationship
    # ======================================================

    incident_id = Column(
        Integer,
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    incident = relationship(
        "Incident",
        back_populates="threat_scores",
    )

    # ======================================================
    # Created At
    # ======================================================

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )