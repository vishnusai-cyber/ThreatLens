from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.database import get_db
from app.crud.user import get_user_by_email

# IMPORTANT:
# This should point to the OAuth2 login endpoint
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# ==========================================
# Get Current Logged-in User
# ==========================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )

        email = payload.get("sub")

        if email is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user_by_email(db, email)

    if user is None:
        raise credentials_exception

    return user


# ==========================================
# Admin Only
# ==========================================

def require_admin(
    current_user=Depends(get_current_user)
):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Admin privileges required."
        )

    return current_user


# ==========================================
# Admin + Analyst
# ==========================================

def require_analyst(
    current_user=Depends(get_current_user)
):
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Analyst privileges required."
        )

    return current_user


# ==========================================
# Admin + Analyst + Viewer
# ==========================================

def require_viewer(
    current_user=Depends(get_current_user)
):
    if current_user.role not in ["admin", "analyst", "viewer"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )

    return current_user