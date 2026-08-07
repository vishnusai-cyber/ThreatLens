from sqlalchemy import func, cast, Date
from sqlalchemy.orm import Session

from app.models.threat_score import ThreatScore
from app.models.intelligence import IntelligenceLookup


# ==========================================================
# Dashboard Overview
# ==========================================================
def get_dashboard_overview(db: Session):

    total = db.query(ThreatScore).count()

    critical = db.query(ThreatScore).filter(
        ThreatScore.severity == "Critical"
    ).count()

    high = db.query(ThreatScore).filter(
        ThreatScore.severity == "High"
    ).count()

    medium = db.query(ThreatScore).filter(
        ThreatScore.severity == "Medium"
    ).count()

    low = db.query(ThreatScore).filter(
        ThreatScore.severity == "Low"
    ).count()

    unique_ips = db.query(
        func.count(func.distinct(ThreatScore.ip_address))
    ).scalar()

    return {
        "total_scans": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "unique_ips": unique_ips,
    }


# ==========================================================
# Severity Distribution
# ==========================================================
def get_severity_distribution(db: Session):

    result = (
        db.query(
            ThreatScore.severity,
            func.count(ThreatScore.id).label("count")
        )
        .group_by(ThreatScore.severity)
        .all()
    )

    return [
        {
            "severity": row.severity,
            "count": row.count
        }
        for row in result
    ]


# ==========================================================
# Top Malicious IPs
# ==========================================================
def get_top_ips(db: Session, limit: int = 10):

    results = (
        db.query(ThreatScore)
        .order_by(
            ThreatScore.threatlens_score.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "ip_address": row.ip_address,
            "score": row.threatlens_score,
            "severity": row.severity,
        }
        for row in results
    ]


# ==========================================================
# Recent Activity
# ==========================================================
def get_recent_activity(db: Session, limit: int = 10):

    results = (
        db.query(ThreatScore)
        .order_by(
            ThreatScore.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "ip_address": row.ip_address,
            "score": row.threatlens_score,
            "severity": row.severity,
            "created_at": row.created_at,
        }
        for row in results
    ]


# ==========================================================
# Intelligence Source Statistics
# ==========================================================
def get_source_statistics(db: Session):

    results = (
        db.query(
            IntelligenceLookup.source,
            func.count(IntelligenceLookup.id).label("count")
        )
        .group_by(
            IntelligenceLookup.source
        )
        .all()
    )

    return [
        {
            "source": row.source,
            "count": row.count,
        }
        for row in results
    ]


# ==========================================================
# Threat Trends
# ==========================================================
def get_threat_trends(db: Session):

    results = (
        db.query(
            cast(ThreatScore.created_at, Date).label("date"),
            func.count(ThreatScore.id).label("count")
        )
        .group_by(
            cast(ThreatScore.created_at, Date)
        )
        .order_by(
            cast(ThreatScore.created_at, Date)
        )
        .all()
    )

    return [
        {
            "date": row.date,
            "count": row.count,
        }
        for row in results
    ]