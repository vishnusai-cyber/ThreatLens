from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.schemas.threat import (
    ThreatCreate,
    ThreatUpdate,
    ThreatResponse,
)

from app.crud.threat import (
    create_threat,
    get_threats,
    get_threat_by_id,
    update_threat,
    delete_threat,
)

from app.auth.dependencies import (
    require_admin,
    require_analyst,
    require_viewer,
)

router = APIRouter(
    prefix="/threats",
    tags=["Threats"],
)


# =====================================
# Create Threat
# Admin & Analyst
# =====================================

@router.post(
    "/",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_new_threat(
    threat: ThreatCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    return create_threat(db, threat)


# =====================================
# Get All Threats
# Viewer+
# =====================================

@router.get(
    "/",
    response_model=List[ThreatResponse],
)
def read_all_threats(
    db: Session = Depends(get_db),
    current_user=Depends(require_viewer),
):
    return get_threats(db)


# =====================================
# Get Threat By ID
# Viewer+
# =====================================

@router.get(
    "/{threat_id}",
    response_model=ThreatResponse,
)
def read_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_viewer),
):
    threat = get_threat_by_id(db, threat_id)

    if threat is None:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    return threat


# =====================================
# Update Threat
# Analyst+
# =====================================

@router.put(
    "/{threat_id}",
    response_model=ThreatResponse,
)
def update_existing_threat(
    threat_id: int,
    threat: ThreatUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    db_threat = get_threat_by_id(db, threat_id)

    if db_threat is None:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    return update_threat(
        db,
        db_threat,
        threat,
    )


# =====================================
# Delete Threat
# Admin Only
# =====================================

@router.delete(
    "/{threat_id}",
)
def remove_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    db_threat = get_threat_by_id(db, threat_id)

    if db_threat is None:
        raise HTTPException(
            status_code=404,
            detail="Threat not found",
        )

    delete_threat(
        db,
        db_threat,
    )

    return {
        "message": "Threat deleted successfully"
    }