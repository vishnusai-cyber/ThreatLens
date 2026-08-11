from typing import List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
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
# Router
# ==========================================================

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


# ==========================================================
# Correlation Service
# ==========================================================

correlation_service = CorrelationService()


# ==========================================================
# Create Incident
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
    """
    Create a new security incident.
    """

    try:

        return create_incident(
            db,
            incident_data,
        )

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create incident: {str(e)}",
        )


# ==========================================================
# Get Incident Statistics
# ==========================================================

@router.get(
    "/statistics/summary",
    response_model=IncidentStats,
)
def incident_statistics(
    db: Session = Depends(get_db),
):
    """
    Get incident statistics.
    """

    return get_incident_stats(
        db
    )


# ==========================================================
# Incident Dashboard - Overview
# ==========================================================

@router.get(
    "/dashboard/overview"
)
def incident_dashboard_overview(
    db: Session = Depends(get_db),
):
    """
    Get overall incident dashboard overview.
    """

    return get_incident_dashboard_overview(
        db
    )


# ==========================================================
# Incident Dashboard - Severity Distribution
# ==========================================================

@router.get(
    "/dashboard/incidents/severity"
)
def incident_severity_distribution(
    db: Session = Depends(get_db),
):
    """
    Get incident counts grouped by severity.
    """

    return get_incident_severity_distribution(
        db
    )


# ==========================================================
# Incident Dashboard - Status Distribution
# ==========================================================

@router.get(
    "/dashboard/incidents/status"
)
def incident_status_distribution(
    db: Session = Depends(get_db),
):
    """
    Get incident counts grouped by status.
    """

    return get_incident_status_distribution(
        db
    )


# ==========================================================
# Incident Dashboard - Recent Incidents
# ==========================================================

@router.get(
    "/dashboard/recent"
)
def incident_dashboard_recent(
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """
    Get recently created incidents.
    """

    if limit < 1:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be greater than 0",
        )

    if limit > 100:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit cannot exceed 100",
        )

    return get_recent_incidents(
        db,
        limit=limit,
    )


# ==========================================================
# Incident Dashboard - Activity
# ==========================================================

@router.get(
    "/dashboard/activity"
)
def incident_dashboard_activity(
    limit: int = 10,
    db: Session = Depends(get_db),
):
    """
    Get recent incident activity.
    """

    if limit < 1:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be greater than 0",
        )

    if limit > 100:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit cannot exceed 100",
        )

    return get_incident_activity(
        db,
        limit=limit,
    )


# ==========================================================
# Get All Incidents
# ==========================================================

@router.get(
    "",
    response_model=List[IncidentResponse],
)
def get_all_incidents(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """
    Get all incidents with pagination.
    """

    return get_incidents(
        db,
        skip=skip,
        limit=limit,
    )


# ==========================================================
# Get Incident By ID
# ==========================================================

@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def get_single_incident(
    incident_id: int,
    db: Session = Depends(get_db),
):
    """
    Get a single incident by ID.
    """

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident


# ==========================================================
# Update Incident
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
    """
    Update an existing incident.
    """

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    try:

        return update_incident(
            db,
            incident_id,
            incident_data,
        )

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update incident: {str(e)}",
        )


# ==========================================================
# Delete Incident
# ==========================================================

@router.delete(
    "/{incident_id}",
)
def delete_incident_endpoint(
    incident_id: int,
    db: Session = Depends(get_db),
):
    """
    Delete an incident.
    """

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    try:

        delete_incident(
            db,
            incident_id,
        )

        return {
            "message": "Incident deleted successfully",
            "incident_id": incident_id,
        }

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete incident: {str(e)}",
        )


# ==========================================================
# Incident Intelligence
# ==========================================================

@router.get(
    "/{incident_id}/intelligence",
)
def get_incident_intelligence(
    incident_id: int,
    limit: int = 10,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """
    Get intelligence lookups associated with an incident.
    """

    # ------------------------------------------------------
    # Validate pagination
    # ------------------------------------------------------

    if limit < 1:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit must be greater than 0",
        )

    if limit > 100:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Limit cannot exceed 100",
        )

    if offset < 0:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Offset cannot be negative",
        )

    # ------------------------------------------------------
    # Check incident
    # ------------------------------------------------------

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # ------------------------------------------------------
    # Check IP
    # ------------------------------------------------------

    if not incident.ip_address:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident does not contain an IP address",
        )

    # ------------------------------------------------------
    # Get intelligence
    # ------------------------------------------------------

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
            "severity": incident.severity,
            "status": incident.status,
            "ip_address": str(
                incident.ip_address
            ),
        },
        "intelligence": intelligence,
        "limit": limit,
        "offset": offset,
    }


# ==========================================================
# Calculate Incident Threat Score
# ==========================================================

@router.get(
    "/{incident_id}/score",
)
async def get_incident_score(
    incident_id: int,
    db: Session = Depends(get_db),
):
    """
    Calculate a fresh ThreatLens score for an incident.

    The incident IP is sent through:

        VirusTotal
        AbuseIPDB
        AlienVault OTX

    The resulting ThreatScore is associated
    with the incident.
    """

    # ------------------------------------------------------
    # Check incident
    # ------------------------------------------------------

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # ------------------------------------------------------
    # Check IP
    # ------------------------------------------------------

    if not incident.ip_address:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident does not contain an IP address",
        )

    # ------------------------------------------------------
    # Run correlation engine
    # ------------------------------------------------------

    try:

        intelligence = await correlation_service.correlate_ip(
            str(
                incident.ip_address
            ),
            db,
            incident_id=incident.id,
        )

        return {
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "ip_address": str(
                    incident.ip_address
                ),
            },
            "threat_score": intelligence,
        }

    except Exception as e:

        import traceback

        traceback.print_exc()

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Incident threat scoring failed: "
                f"{str(e)}"
            ),
        )


# ==========================================================
# Get Stored Incident Threat Score
# ==========================================================

@router.get(
    "/{incident_id}/stored-score",
)
def get_stored_incident_score(
    incident_id: int,
    db: Session = Depends(get_db),
):
    """
    Get the latest ThreatScore already stored
    for an incident.

    This endpoint does NOT call:

        VirusTotal
        AbuseIPDB
        AlienVault OTX

    It only reads the latest ThreatScore
    from PostgreSQL.
    """

    # ------------------------------------------------------
    # Check incident
    # ------------------------------------------------------

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # ------------------------------------------------------
    # Get latest stored ThreatScore
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # No stored score
    # ------------------------------------------------------

    if not threat_score:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No threat score found "
                "for this incident"
            ),
        )

    # ------------------------------------------------------
    # Return stored score
    # ------------------------------------------------------

    return {
        "incident_id": incident.id,

        "incident_title": incident.title,

        "threat_score": {

            "id": threat_score.id,

            "ip_address": (
                threat_score.ip_address
            ),

            "threatlens_score": (
                threat_score.threatlens_score
            ),

            "severity": (
                threat_score.severity
            ),

            "recommendation": (
                threat_score.recommendation
            ),

            "incident_id": (
                threat_score.incident_id
            ),

            "created_at": (
                threat_score.created_at
            ),
        },
    }