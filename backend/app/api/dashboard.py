from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.crud.dashboard import (
    get_dashboard_overview,
    get_severity_distribution,
    get_top_ips,
    get_recent_activity,
    get_source_statistics,
    get_threat_trends,
)

from app.schemas.dashboard import (
    DashboardOverview,
    SeverityItem,
    TopIP,
    RecentActivity,
    SourceStatistic,
    TrendItem,
)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


# ==========================================================
# Dashboard Overview
# ==========================================================
@router.get(
    "/overview",
    response_model=DashboardOverview
)
def dashboard_overview(
    db: Session = Depends(get_db)
):
    return get_dashboard_overview(db)


# ==========================================================
# Severity Distribution
# ==========================================================
@router.get(
    "/severity",
    response_model=list[SeverityItem]
)
def severity_distribution(
    db: Session = Depends(get_db)
):
    return get_severity_distribution(db)


# ==========================================================
# Top Malicious IPs
# ==========================================================
@router.get(
    "/top-ips",
    response_model=list[TopIP]
)
def top_ips(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    return get_top_ips(db, limit)


# ==========================================================
# Recent Activity
# ==========================================================
@router.get(
    "/recent",
    response_model=list[RecentActivity]
)
def recent_activity(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    return get_recent_activity(db, limit)


# ==========================================================
# Intelligence Source Statistics
# ==========================================================
@router.get(
    "/sources",
    response_model=list[SourceStatistic]
)
def source_statistics(
    db: Session = Depends(get_db)
):
    return get_source_statistics(db)


# ==========================================================
# Threat Trends
# ==========================================================
@router.get(
    "/trends",
    response_model=list[TrendItem]
)
def threat_trends(
    db: Session = Depends(get_db)
):
    return get_threat_trends(db)