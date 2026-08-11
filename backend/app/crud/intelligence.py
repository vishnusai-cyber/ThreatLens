from sqlalchemy.orm import Session

from app.models.intelligence import IntelligenceLookup


# ==========================================================
# Create Intelligence Lookup
# ==========================================================

def create_lookup(
    db: Session,
    ip: str,
    source: str,
    risk_score: int,
    raw_response: dict,
    incident_id: int | None = None,
):
    lookup = IntelligenceLookup(
        ip=ip,
        source=source,
        risk_score=risk_score,
        raw_response=raw_response,
        incident_id=incident_id,
    )

    db.add(lookup)
    db.commit()
    db.refresh(lookup)

    return lookup


# ==========================================================
# Get Intelligence Lookup History
# ==========================================================

def get_lookup_history(
    db: Session,
    limit: int = 10,
    offset: int = 0,
    ip: str | None = None,
    source: str | None = None,
):
    query = db.query(IntelligenceLookup)

    # ------------------------------------------------------
    # Filter by IP address
    # ------------------------------------------------------

    if ip:
        query = query.filter(
            IntelligenceLookup.ip == ip
        )

    # ------------------------------------------------------
    # Filter by intelligence source
    # ------------------------------------------------------

    if source:
        query = query.filter(
            IntelligenceLookup.source == source
        )

    return (
        query
        .order_by(
            IntelligenceLookup.created_at.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


# ==========================================================
# Get Intelligence By Incident
# ==========================================================

def get_intelligence_by_incident(
    db: Session,
    incident_id: int,
    limit: int = 10,
    offset: int = 0,
):
    """
    Get intelligence lookups associated
    with a specific incident.
    """

    return (
        db.query(IntelligenceLookup)
        .filter(
            IntelligenceLookup.incident_id == incident_id
        )
        .order_by(
            IntelligenceLookup.created_at.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


# ==========================================================
# Attach Intelligence Lookup To Incident
# ==========================================================

def attach_lookup_to_incident(
    db: Session,
    lookup_id: int,
    incident_id: int,
):
    lookup = (
        db.query(IntelligenceLookup)
        .filter(
            IntelligenceLookup.id == lookup_id
        )
        .first()
    )

    if not lookup:
        return None

    lookup.incident_id = incident_id

    db.commit()
    db.refresh(lookup)

    return lookup


# ==========================================================
# Detach Intelligence Lookup From Incident
# ==========================================================

def detach_lookup_from_incident(
    db: Session,
    lookup_id: int,
):
    lookup = (
        db.query(IntelligenceLookup)
        .filter(
            IntelligenceLookup.id == lookup_id
        )
        .first()
    )

    if not lookup:
        return None

    lookup.incident_id = None

    db.commit()
    db.refresh(lookup)

    return lookup