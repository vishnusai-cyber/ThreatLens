from sqlalchemy.orm import Session

from app.models.threat_score import ThreatScore


def create_threat_score(
    db: Session,
    ip_address: str,
    threatlens_score: int,
    severity: str,
    recommendation: str,
):
    record = ThreatScore(
        ip_address=ip_address,
        threatlens_score=threatlens_score,
        severity=severity,
        recommendation=recommendation,
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return record