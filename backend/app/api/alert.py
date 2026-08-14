# ==========================================================
# ThreatLens - Alerts API
# ==========================================================

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from sqlalchemy.orm import Session

from app.database.database import get_db

from app.schemas.alert import (
    AlertCreate,
    AlertUpdate,
    AlertResponse,
    AlertStatsResponse,
)

from app.crud.alert import (
    create_alert,
    get_alerts,
    get_alert_by_id,
    update_alert,
    delete_alert,
    get_alert_stats,
)


# ==========================================================
# Router
# ==========================================================

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


# ==========================================================
# Create Alert
# ==========================================================

@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_alert_endpoint(
    alert_data: AlertCreate,
    db: Session = Depends(get_db),
):
    try:

        return create_alert(
            db=db,
            alert_data=alert_data,
        )

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create alert: {str(e)}",
        )


# ==========================================================
# Get Alerts
#
# Supports:
# - pagination
# - status filtering
# - severity filtering
# - incident filtering
# ==========================================================

@router.get(
    "",
    response_model=list[AlertResponse],
)
def get_all_alerts(
    skip: int = Query(
        0,
        ge=0,
    ),

    limit: int = Query(
        100,
        ge=1,
        le=500,
    ),

    status_filter: str | None = Query(
        None,
        alias="status",
    ),

    severity: str | None = Query(
        None,
    ),

    incident_id: int | None = Query(
        None,
        ge=1,
    ),

    db: Session = Depends(get_db),
):

    return get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        status=status_filter,
        severity=severity,
        incident_id=incident_id,
    )


# ==========================================================
# Alert Statistics
#
# IMPORTANT:
# This route must appear BEFORE /{alert_id}
# ==========================================================

@router.get(
    "/stats",
    response_model=AlertStatsResponse,
)
def get_alert_statistics(
    db: Session = Depends(get_db),
):

    return get_alert_stats(
        db=db,
    )


# ==========================================================
# Get Alert By ID
# ==========================================================

@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
)
def get_single_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):

    alert = get_alert_by_id(
        db=db,
        alert_id=alert_id,
    )

    if not alert:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return alert


# ==========================================================
# Update Alert
# ==========================================================

@router.put(
    "/{alert_id}",
    response_model=AlertResponse,
)
def update_alert_endpoint(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db),
):

    try:

        alert = update_alert(
            db=db,
            alert_id=alert_id,
            alert_data=alert_data,
        )

        if not alert:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found",
            )

        return alert

    except HTTPException:
        raise

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert: {str(e)}",
        )


# ==========================================================
# Delete Alert
# ==========================================================

@router.delete(
    "/{alert_id}",
)
def delete_alert_endpoint(
    alert_id: int,
    db: Session = Depends(get_db),
):

    try:

        alert = delete_alert(
            db=db,
            alert_id=alert_id,
        )

        if not alert:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found",
            )

        return {
            "message": "Alert deleted successfully",
            "alert_id": alert_id,
        }

    except HTTPException:
        raise

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete alert: {str(e)}",
        )