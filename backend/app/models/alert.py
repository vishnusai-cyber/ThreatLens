from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.database.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    threat_score_id = Column(
        Integer,
        nullable=True,
        index=True
    )

    ip_address = Column(
        String,
        nullable=False,
        index=True
    )

    threatlens_score = Column(
        Integer,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(
        String,
        nullable=False
    )

    recommendation = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="Open",
        index=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True
    )