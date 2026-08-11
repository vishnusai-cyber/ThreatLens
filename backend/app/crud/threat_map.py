from sqlalchemy.orm import Session

from app.models.threat_score import ThreatScore


# ==========================================================
# Global Threat Map
# ==========================================================

def get_global_threat_map(
    db: Session,
    limit: int = 100,
):
    """
    Get threat intelligence data
    required for the global threat map.
    """

    threat_scores = (
        db.query(ThreatScore)
        .order_by(
            ThreatScore.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    results = []

    for threat in threat_scores:
        results.append(
            {
                "ip_address": threat.ip_address,
                "threatlens_score": threat.threatlens_score,
                "severity": threat.severity,
                "created_at": threat.created_at,
            }
        )

    return results