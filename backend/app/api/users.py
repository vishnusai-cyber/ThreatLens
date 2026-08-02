from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)

@router.get("/me")
def read_current_user(current_user=Depends(get_current_user)):
    return current_user