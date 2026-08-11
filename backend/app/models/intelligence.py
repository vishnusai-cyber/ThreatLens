from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    ForeignKey,
)

from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database.base import Base


class IntelligenceLookup(Base):

    __tablename__ = "intelligence_lookups"

    # ==========================================================
    # Primary Key
    # ==========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ==========================================================
    # Incident Foreign Key
    # ==========================================================

    incident_id = Column(
        Integer,
        ForeignKey(
            "incidents.id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    # ==========================================================
    # IP Address
    # ==========================================================

    ip = Column(
        String,
        nullable=False,
        index=True,
    )

    # ==========================================================
    # Intelligence Source
    # ==========================================================

    source = Column(
        String,
        nullable=False,
    )

    # ==========================================================
    # Risk Score
    # ==========================================================

    risk_score = Column(
        Integer,
        default=0,
    )

    # ==========================================================
    # Raw Intelligence Response
    # ==========================================================

    raw_response = Column(
        JSON,
        nullable=False,
    )

    # ==========================================================
    # Created At
    # ==========================================================

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    # ==========================================================
    # Incident Relationship
    # ==========================================================

    incident = relationship(
        "Incident",
        back_populates="intelligence_lookups",
    )