"""Authentication endpoints (UI login)."""
import secrets
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.utils.auth import create_access_token, verify_login_password

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    """
    Authenticate with UI credentials.
    Password is verified against the DB-stored bcrypt hash (set via /settings/change-password
    or seeded from UI_PASSWORD in .env on first startup).
    """
    user_ok = secrets.compare_digest(body.username, settings.ui_username)
    pass_ok = verify_login_password(body.password)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return TokenResponse(access_token=create_access_token(sub=body.username))


@router.get("/me")
def me():
    """Validate a token and return the username. The middleware already checked auth."""
    return {"username": settings.ui_username}
