from sqlalchemy.orm import Session

from app.models.threat import Threat
from app.schemas.threat import ThreatCreate, ThreatUpdate


# =========================
# Create Threat
# =========================

def create_threat(db: Session, threat: ThreatCreate):
    db_threat = Threat(
        title=threat.title,
        ioc_type=threat.ioc_type,
        ioc_value=threat.ioc_value,
        severity=threat.severity,
        status=threat.status,
        source=threat.source,
        description=threat.description,
    )

    db.add(db_threat)
    db.commit()
    db.refresh(db_threat)

    return db_threat


# =========================
# Get All Threats
# =========================

def get_threats(db: Session):
    return (
        db.query(Threat)
        .order_by(Threat.id.desc())
        .all()
    )


# =========================
# Get Threat by ID
# =========================

def get_threat_by_id(db: Session, threat_id: int):
    return (
        db.query(Threat)
        .filter(Threat.id == threat_id)
        .first()
    )


# =========================
# Update Threat
# =========================

def update_threat(
    db: Session,
    db_threat: Threat,
    threat: ThreatUpdate,
):
    update_data = threat.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(db_threat, key, value)

    db.commit()
    db.refresh(db_threat)

    return db_threat


# =========================
# Delete Threat
# =========================

def delete_threat(
    db: Session,
    db_threat: Threat,
):
    db.delete(db_threat)
    db.commit()

    return db_threat