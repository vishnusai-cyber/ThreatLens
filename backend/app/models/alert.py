# ==========================================================
# ThreatLens - Alert Model
# ==========================================================

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
)

from sqlalchemy.orm import relationship

from sqlalchemy.sql import func

from app.database.base import Base


# ==========================================================
# Alert Model
# ==========================================================

class Alert(Base):

    __tablename__ = "alerts"

    # ======================================================
    # Primary Key
    # ======================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ======================================================
    # Threat Score Relationship
    # ======================================================

    threat_score_id = Column(
        Integer,
        nullable=True,
        index=True,
    )

    # ======================================================
    # Incident Relationship
    #
    # Existing PostgreSQL column:
    #
    # alerts.incident_id
    #     ↓
    # incidents.id
    #
    # No new migration is required because the column
    # already exists in the database.
    # ======================================================

    incident_id = Column(
        Integer,
        ForeignKey(
            "incidents.id",
            name="fk_alerts_incident_id_incidents",
        ),
        nullable=True,
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
    # Alert Title
    # ======================================================

    title = Column(
        String,
        nullable=False,
    )

    # ======================================================
    # Description
    # ======================================================

    description = Column(
        String,
        nullable=False,
    )

    # ======================================================
    # Recommendation
    # ======================================================

    recommendation = Column(
        String,
        nullable=False,
    )

    # ======================================================
    # Status
    # ======================================================

    status = Column(
        String,
        nullable=False,
        default="Open",
        index=True,
    )

    # ======================================================
    # Created At
    # ======================================================

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    # ======================================================
    # Resolved At
    # ======================================================

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ======================================================
    # Incident Relationship
    #
    # Alert → Incident
    # ======================================================

    incident = relationship(
        "Incident",
        back_populates="alerts",
    )