"""Settings endpoints — manage API tokens and admin password from the UI."""
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from passlib.context import CryptContext

from app.database import (
    get_db, set_setting, get_setting,
    SETTING_TOKEN_READ, SETTING_TOKEN_WRITE, SETTING_PASSWORD,
    pwd_context,
)
from app.config import settings
from app.utils.auth import token_cache, reload_token_cache, verify_login_password

_DEMO_BLOCKED = HTTPException(status_code=403, detail="Not available in demo mode")

router = APIRouter(prefix="/settings", tags=["settings"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class TokensResponse(BaseModel):
    read_token_preview:  str   # first 8 chars + "••••••••"
    write_token_preview: str


class RegenerateRequest(BaseModel):
    token_type: str   # "read" or "write"


class RegenerateResponse(BaseModel):
    token_type: str
    token: str        # full new token (only time it's shown in full)
    preview: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _preview(token: str) -> str:
    if not token or len(token) < 8:
        return "••••••••"
    return token[:8] + "••••••••"

def _gen_token() -> str:
    return secrets.token_urlsafe(48)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/tokens", response_model=TokensResponse)
def get_tokens():
    """Return masked previews of the current API tokens."""
    read  = get_setting(SETTING_TOKEN_READ)  or ""
    write = get_setting(SETTING_TOKEN_WRITE) or ""
    return TokensResponse(
        read_token_preview=_preview(read),
        write_token_preview=_preview(write),
    )


@router.post("/regenerate-token", response_model=RegenerateResponse)
def regenerate_token(body: RegenerateRequest, db: Session = Depends(get_db)):
    """Generate a new random token for the given type and persist it to DB."""
    if settings.demo_mode:
        raise _DEMO_BLOCKED
    if body.token_type not in ("read", "write"):
        raise HTTPException(status_code=422, detail="token_type must be 'read' or 'write'")

    new_token = _gen_token()
    key = SETTING_TOKEN_READ if body.token_type == "read" else SETTING_TOKEN_WRITE
    set_setting(db, key, new_token)
    db.commit()

    # Refresh in-memory cache so the new token is valid immediately
    reload_token_cache()

    return RegenerateResponse(
        token_type=body.token_type,
        token=new_token,
        preview=_preview(new_token),
    )


@router.post("/change-password")
def change_password(body: ChangePasswordRequest, db: Session = Depends(get_db)):
    """Change the admin password. Requires the current password for confirmation."""
    if settings.demo_mode:
        raise _DEMO_BLOCKED
    if not verify_login_password(body.current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=422, detail="New password must be at least 8 characters")

    new_hash = pwd_context.hash(body.new_password)
    set_setting(db, SETTING_PASSWORD, new_hash)
    db.commit()
    return {"detail": "Password updated successfully"}
