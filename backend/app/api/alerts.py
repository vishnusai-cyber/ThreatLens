from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.schemas.alert import (
    AlertCreate,
    AlertUpdate,
    AlertResponse,
)

from app.crud.alert import (
    create_alert,
    get_alerts,
    get_alert_by_id,
    update_alert,
    delete_alert,
)


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"]
)


# ==========================================================
# Create Alert
# ==========================================================
@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED
)
def create_alert_endpoint(
    alert_data: AlertCreate,
    db: Session = Depends(get_db)
):
    return create_alert(
        db,
        alert_data
    )


# ==========================================================
# Get Alerts
# ==========================================================
@router.get(
    "",
    response_model=list[AlertResponse]
)
def get_all_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status_filter: str | None = Query(
        None,
        alias="status"
    ),
    severity: str | None = None,
    db: Session = Depends(get_db)
):
    return get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        status=status_filter,
        severity=severity,
    )


# ==========================================================
# Get Alert By ID
# ==========================================================
@router.get(
    "/{alert_id}",
    response_model=AlertResponse
)
def get_single_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = get_alert_by_id(
        db,
        alert_id
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return alert


# ==========================================================
# Update Alert
# ==========================================================
@router.put(
    "/{alert_id}",
    response_model=AlertResponse
)
def update_alert_endpoint(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db)
):
    alert = update_alert(
        db,
        alert_id,
        alert_data
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return alert


# ==========================================================
# Delete Alert
# ==========================================================
@router.delete(
    "/{alert_id}"
)
def delete_alert_endpoint(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = delete_alert(
        db,
        alert_id
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return {
        "message": "Alert deleted successfully",
        "alert_id": alert_id
    }