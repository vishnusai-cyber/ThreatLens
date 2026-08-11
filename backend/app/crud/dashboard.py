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
#
# IMPORTANT:
# Return only ONE record per IP.
#
# If the same IP has been scanned multiple times, we select
# the highest ThreatLens score for that IP.
#
# If two scans have the same score, the newest scan wins.
# ==========================================================

def get_top_ips(db: Session, limit: int = 10):

    ranked_scores = (
        db.query(
            ThreatScore.id.label("id"),
            ThreatScore.ip_address.label("ip_address"),
            ThreatScore.threatlens_score.label("score"),
            ThreatScore.severity.label("severity"),
            ThreatScore.created_at.label("created_at"),

            func.row_number()
            .over(
                partition_by=ThreatScore.ip_address,
                order_by=(
                    ThreatScore.threatlens_score.desc(),
                    ThreatScore.created_at.desc(),
                    ThreatScore.id.desc(),
                ),
            )
            .label("row_number"),
        )
        .subquery()
    )

    results = (
        db.query(ranked_scores)
        .filter(ranked_scores.c.row_number == 1)
        .order_by(
            ranked_scores.c.score.desc(),
            ranked_scores.c.created_at.desc(),
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "ip_address": row.ip_address,
            "score": row.score,
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