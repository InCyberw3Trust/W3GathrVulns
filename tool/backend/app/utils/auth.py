"""
Authentication utilities:
  - JWT creation / verification (UI sessions)
  - API token validation with DB-backed in-memory cache
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.config import settings

ALGORITHM = "HS256"

# ── In-memory token cache ─────────────────────────────────────────────────────
# Populated at startup from DB and refreshed after token regeneration.
# Avoids a DB query on every authenticated request.
token_cache: dict[str, Optional[str]] = {
    "read":  None,
    "write": None,
}


def reload_token_cache():
    """Re-read tokens from DB into the in-memory cache.
    Called at startup and after any token regeneration.
    Import is deferred to avoid circular imports with database.py.
    """
    from app.database import get_setting, SETTING_TOKEN_READ, SETTING_TOKEN_WRITE
    token_cache["read"]  = get_setting(SETTING_TOKEN_READ)
    token_cache["write"] = get_setting(SETTING_TOKEN_WRITE)


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(sub: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expire_hours)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def verify_token(token: str) -> Optional[str]:
    """Return the subject (username) if the JWT is valid, else None."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ── API tokens ────────────────────────────────────────────────────────────────

def check_api_token(token: str, method: str) -> bool:
    """
    Returns True if the given API token grants access for the HTTP method.

    - write token: full access (GET + POST + PATCH + DELETE)
    - read  token: GET-only access

    Tokens are validated exclusively against the DB-backed in-memory cache.
    The .env values are NOT used here — they are only consumed once at first
    startup by _seed_settings() to populate the DB.
    """
    write = token_cache.get("write")
    read  = token_cache.get("read")

    if write and secrets.compare_digest(token, write):
        return True
    if read and secrets.compare_digest(token, read) and method.upper() == "GET":
        return True
    return False


# ── Login password verification ───────────────────────────────────────────────

def verify_login_password(plain: str) -> bool:
    """
    Verify a login attempt against the DB-stored bcrypt hash only.
    The .env UI_PASSWORD is consumed once at startup by _seed_settings()
    to populate the DB — it is never used for direct authentication.
    """
    from app.database import verify_password as db_verify
    return db_verify(plain)


# ── Public paths (skip auth check) ───────────────────────────────────────────

PUBLIC_PATHS = {
    "/api/health",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/app-config",
}


def is_public(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    if path.startswith("/api/docs") or path.startswith("/api/redoc"):
        return True
    return False
