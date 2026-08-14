from typing import List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.models.threat_score import ThreatScore

from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentResponse,
    IncidentStats,
)

from app.crud.incident import (
    create_incident,
    get_incidents,
    get_incident_by_id,
    update_incident,
    delete_incident,
    get_incident_stats,
    get_incident_dashboard_overview,
    get_incident_severity_distribution,
    get_incident_status_distribution,
    get_recent_incidents,
    get_incident_activity,
)

from app.crud.intelligence import (
    get_intelligence_by_incident,
)

from app.services.correlation import (
    CorrelationService,
)


# ==========================================================
# ThreatLens - Incident API
# ==========================================================

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)

correlation_service = CorrelationService()


# ==========================================================
# CREATE INCIDENT
# ==========================================================

@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident_endpoint(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
):
    try:
        return create_incident(
            db=db,
            incident_data=incident_data,
        )

    except Exception as e:
        db.rollback()

        print("CREATE INCIDENT ERROR:")
        print(str(e))

        raise HTTPException(
            status_code=500,
            detail=f"Failed to create incident: {str(e)}",
        )


# ==========================================================
# GET ALL INCIDENTS
# ==========================================================

@router.get(
    "",
    response_model=List[IncidentResponse],
)
def get_all_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return get_incidents(
        db=db,
        skip=skip,
        limit=limit,
    )


# ==========================================================
# INCIDENT STATISTICS
# ==========================================================

@router.get(
    "/stats",
    response_model=IncidentStats,
)
def incident_statistics_short(
    db: Session = Depends(get_db),
):
    return get_incident_stats(db)


@router.get(
    "/statistics/summary",
    response_model=IncidentStats,
)
def incident_statistics(
    db: Session = Depends(get_db),
):
    return get_incident_stats(db)


# ==========================================================
# INCIDENT DASHBOARD
# ==========================================================

@router.get(
    "/dashboard/overview",
)
def incident_dashboard_overview(
    db: Session = Depends(get_db),
):
    return get_incident_dashboard_overview(db)


@router.get(
    "/dashboard/incidents/severity",
)
def incident_severity_distribution(
    db: Session = Depends(get_db),
):
    return get_incident_severity_distribution(db)


@router.get(
    "/dashboard/incidents/status",
)
def incident_status_distribution(
    db: Session = Depends(get_db),
):
    return get_incident_status_distribution(db)


@router.get(
    "/dashboard/recent",
)
def incident_dashboard_recent(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return get_recent_incidents(
        db=db,
        limit=limit,
    )


@router.get(
    "/dashboard/activity",
)
def incident_dashboard_activity(
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return get_incident_activity(
        db=db,
        limit=limit,
    )


# ==========================================================
# INCIDENT INTELLIGENCE
# IMPORTANT:
# These routes are deliberately ABOVE /{incident_id}
# ==========================================================

@router.get(
    "/{incident_id}/intelligence",
)
def get_incident_intelligence(
    incident_id: int,
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Get intelligence associated with an incident.
    """

    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    intelligence = get_intelligence_by_incident(
        db=db,
        incident_id=incident_id,
        limit=limit,
        offset=offset,
    )

    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "ip_address": (
                str(incident.ip_address)
                if incident.ip_address
                else None
            ),
            "created_at": incident.created_at,
            "updated_at": incident.updated_at,
        },
        "filters": {
            "incident_id": incident_id,
        },
        "pagination": {
            "limit": limit,
            "offset": offset,
        },
        "intelligence": intelligence,
    }


# ==========================================================
# INCIDENT THREAT SCORE
# ==========================================================

@router.get(
    "/{incident_id}/score",
)
async def get_incident_score(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    if not incident.ip_address:
        raise HTTPException(
            status_code=400,
            detail="Incident does not contain an IP address",
        )

    try:
        intelligence = await correlation_service.correlate_ip(
            str(incident.ip_address),
            db,
            incident_id=incident.id,
        )

        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "ip_address": str(incident.ip_address),
            },
            "threat_score": intelligence,
        }

    except Exception as e:
        import traceback

        traceback.print_exc()
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Incident threat scoring failed: {str(e)}",
        )


# ==========================================================
# STORED THREAT SCORE
# ==========================================================

@router.get(
    "/{incident_id}/stored-score",
)
def get_stored_incident_score(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    threat_score = (
        db.query(ThreatScore)
        .filter(
            ThreatScore.incident_id == incident_id
        )
        .order_by(
            ThreatScore.created_at.desc()
        )
        .first()
    )

    if not threat_score:
        raise HTTPException(
            status_code=404,
            detail="No threat score found for this incident",
        )

    return {
        "incident_id": incident.id,
        "incident_title": incident.title,
        "threat_score": {
            "id": threat_score.id,
            "ip_address": threat_score.ip_address,
            "threatlens_score": threat_score.threatlens_score,
            "severity": threat_score.severity,
            "recommendation": threat_score.recommendation,
            "incident_id": threat_score.incident_id,
            "created_at": threat_score.created_at,
        },
    }


# ==========================================================
# GET INCIDENT BY ID
# IMPORTANT:
# Keep this AFTER all nested routes
# ==========================================================

@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def get_single_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident


# ==========================================================
# UPDATE INCIDENT
# ==========================================================

@router.put(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def update_incident_endpoint(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
):
    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    try:
        return update_incident(
            db=db,
            incident_id=incident_id,
            incident_data=incident_data,
        )

    except Exception as e:
        db.rollback()

        print("UPDATE INCIDENT ERROR:")
        print(str(e))

        raise HTTPException(
            status_code=500,
            detail=f"Failed to update incident: {str(e)}",
        )


# ==========================================================
# DELETE INCIDENT
# ==========================================================

@router.delete(
    "/{incident_id}",
)
def delete_incident_endpoint(
    incident_id: int,
    db: Session = Depends(get_db),
):
    incident = get_incident_by_id(
        db=db,
        incident_id=incident_id,
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    try:
        delete_incident(
            db=db,
            incident_id=incident_id,
        )

        return {
            "message": "Incident deleted successfully",
            "incident_id": incident_id,
        }

    except Exception as e:
        db.rollback()

        print("DELETE INCIDENT ERROR:")
        print(str(e))

        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete incident: {str(e)}",
        )