from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.threat_score import ThreatScore


# ==========================================================
# ThreatLens - Threat Score API
# ==========================================================

router = APIRouter(
    prefix="/threat-scores",
    tags=["Threat Scores"],
)


# ==========================================================
# GET ALL THREAT SCORES
# ==========================================================

@router.get("")
def get_threat_scores(
    limit: int = Query(
        10,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        0,
        ge=0,
    ),
    db: Session = Depends(get_db),
):
    """
    Return stored ThreatLens threat scores.

    Supports:
        ?limit=10
        ?offset=0
    """

    scores = (
        db.query(ThreatScore)
        .order_by(
            ThreatScore.created_at.desc(),
            ThreatScore.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    total = (
        db.query(ThreatScore)
        .count()
    )

    return {
        "items": [
            {
                "id": score.id,
                "ip_address": score.ip_address,
                "threatlens_score": score.threatlens_score,
                "severity": score.severity,
                "recommendation": getattr(
                    score,
                    "recommendation",
                    None,
                ),
                "incident_id": score.incident_id,
                "created_at": score.created_at,
            }
            for score in scores
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


# ==========================================================
# GET THREAT SCORE BY ID
# ==========================================================

@router.get("/{threat_score_id}")
def get_threat_score(
    threat_score_id: int,
    db: Session = Depends(get_db),
):
    """
    Return one stored ThreatScore by its database ID.
    """

    score = (
        db.query(ThreatScore)
        .filter(
            ThreatScore.id == threat_score_id
        )
        .first()
    )

    if not score:
        raise HTTPException(
            status_code=404,
            detail="Threat score not found",
        )

    return {
        "id": score.id,
        "ip_address": score.ip_address,
        "threatlens_score": score.threatlens_score,
        "severity": score.severity,
        "recommendation": getattr(
            score,
            "recommendation",
            None,
        ),
        "incident_id": score.incident_id,
        "created_at": score.created_at,
    }


# ==========================================================
# GET THREAT SCORES BY IP
# ==========================================================

@router.get("/ip/{ip_address}")
def get_threat_scores_by_ip(
    ip_address: str,
    limit: int = Query(
        20,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        0,
        ge=0,
    ),
    db: Session = Depends(get_db),
):
    """
    Return historical threat scores for an IP.
    """

    scores = (
        db.query(ThreatScore)
        .filter(
            ThreatScore.ip_address == ip_address
        )
        .order_by(
            ThreatScore.created_at.desc(),
            ThreatScore.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": score.id,
            "ip_address": score.ip_address,
            "threatlens_score": score.threatlens_score,
            "severity": score.severity,
            "recommendation": getattr(
                score,
                "recommendation",
                None,
            ),
            "incident_id": score.incident_id,
            "created_at": score.created_at,
        }
        for score in scores
    ]