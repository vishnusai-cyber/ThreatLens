from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.crud.threat_map import (
    get_global_threat_map,
)


# ==========================================================
# Router
# ==========================================================

router = APIRouter(
    prefix="/threat-map",
    tags=["Threat Map"],
)


# ==========================================================
# Global Threat Map
# ==========================================================

@router.get("")
def global_threat_map(
    limit: int = Query(
        100,
        ge=1,
        le=1000,
    ),
    db: Session = Depends(get_db),
):
    """
    Get threat data for the global threat map.
    """

    try:

        return get_global_threat_map(
            db=db,
            limit=limit,
        )

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Failed to retrieve global threat map: "
                f"{str(e)}"
            ),
        )