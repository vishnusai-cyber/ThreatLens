from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.user import UserCreate, UserResponse, UserLogin
from app.auth.security import verify_password, create_access_token
from app.auth.dependencies import get_current_user

from app.crud.user import (
    create_user,
    get_user_by_email,
    get_user_by_username,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# =========================
# Register User
# =========================

@router.post("/register", response_model=UserResponse)
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    # Check email already exists
    existing_email = get_user_by_email(
        db,
        user.email
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )


    # Check username already exists
    existing_username = get_user_by_username(
        db,
        user.username
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )


    # Create new user
    new_user = create_user(
        db,
        user
    )

    return new_user



# =========================
# Login User
# =========================

@router.post("/login")
def login_user(
    user: UserLogin,
    db: Session = Depends(get_db)
):

    # Find user by email
    db_user = get_user_by_email(
        db,
        user.email
    )


    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    # Verify password
    if not verify_password(
        user.password,
        db_user.password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )


    # Generate JWT token
    access_token = create_access_token(
        data={
            "sub": db_user.email,
            "username": db_user.username,
            "role": db_user.role
        }
    )


    return {
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "bearer"
    }



# =========================
# Current Logged-in User
# =========================

@router.get(
    "/me",
    response_model=UserResponse
)
def get_logged_in_user(
    current_user = Depends(get_current_user)
):

    return current_user