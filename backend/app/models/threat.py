from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
)
from sqlalchemy.sql import func

from app.database.base import Base


class Threat(Base):
    __tablename__ = "threats"

    # Primary Key
    id = Column(Integer, primary_key=True, index=True)

    # Threat Information
    title = Column(String(255), nullable=False)

    description = Column(Text, nullable=True)

    # IOC Information
    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(String(255), nullable=False)

    # Threat Details
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="Open")
    source = Column(String(100), nullable=True)

    # Audit Fields
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
