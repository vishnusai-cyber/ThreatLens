from sqlalchemy.orm import Session

from app.models.intelligence import IntelligenceLookup


def create_lookup(
    db: Session,
    ip: str,
    source: str,
    risk_score: int,
    raw_response: dict
):
    lookup = IntelligenceLookup(
        ip=ip,
        source=source,
        risk_score=risk_score,
        raw_response=raw_response
    )

    db.add(lookup)
    db.commit()
    db.refresh(lookup)

    return lookup


def get_lookup_history(
    db: Session,
    limit: int = 10,
    offset: int = 0,
    ip: str | None = None,
    source: str | None = None
):
    query = db.query(IntelligenceLookup)

    # Filter by IP address
    if ip:
        query = query.filter(
            IntelligenceLookup.ip == ip
        )

    # Filter by intelligence source
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