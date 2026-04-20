"""
Pytest configuration and shared fixtures.

Uses an in-memory SQLite database so tests never touch a real PostgreSQL instance.
Auth settings are overridden to fixed known values for predictable testing.
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set env vars BEFORE importing app modules so Settings() picks them up.
# Use direct assignment (not setdefault) so existing env vars don't interfere.
os.environ["DATABASE_URL"]   = "sqlite:///:memory:"
os.environ["SECRET_KEY"]     = "test-secret-key-that-is-long-enough-32chars"
os.environ["UI_USERNAME"]    = "testuser"
os.environ["UI_PASSWORD"]    = "testpass"
os.environ["API_TOKEN_READ"]  = "read-token-for-tests"
os.environ["API_TOKEN_WRITE"] = "write-token-for-tests"

from sqlalchemy.pool import StaticPool
import app.database as db_module        # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app               # noqa: E402

# ── In-memory SQLite engine ───────────────────────────────────────────────────
# StaticPool: one shared connection across all threads (required for in-memory SQLite).
# We also REPLACE database.py's engine and SessionLocal so that get_setting(),
# set_setting(), and _seed_settings() all hit the same test DB as get_db().
SQLITE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Patch database module so ALL internal DB access (get_setting, SessionLocal) uses test DB
db_module.engine = engine
db_module.SessionLocal = TestingSession


def override_get_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def fresh_db():
    """Create all tables before each test, seed settings, drop after."""
    Base.metadata.create_all(engine)

    # Seed known tokens and password hash so auth works without startup events.
    from app.database import (
        AppSetting, SETTING_TOKEN_READ, SETTING_TOKEN_WRITE,
        SETTING_PASSWORD, pwd_context,
    )
    from app.utils.auth import token_cache
    db = TestingSession()
    db.add(AppSetting(key=SETTING_TOKEN_READ,  value="read-token-for-tests"))
    db.add(AppSetting(key=SETTING_TOKEN_WRITE, value="write-token-for-tests"))
    db.add(AppSetting(key=SETTING_PASSWORD,    value=pwd_context.hash("testpass")))
    db.commit()
    db.close()

    # Populate the in-memory token cache so check_api_token() works immediately.
    token_cache["read"]  = "read-token-for-tests"
    token_cache["write"] = "write-token-for-tests"

    yield

    token_cache["read"]  = None
    token_cache["write"] = None
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def authed_client():
    """TestClient with a valid JWT from login."""
    c = TestClient(app, raise_server_exceptions=False)
    resp = c.post("/api/v1/auth/login", json={"username": "testuser", "password": "testpass"})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    c.headers.update({"Authorization": f"Bearer {token}"})
    return c


@pytest.fixture
def read_client():
    """TestClient authenticated with the read-only API token."""
    c = TestClient(app, raise_server_exceptions=False)
    c.headers.update({"Authorization": "Bearer read-token-for-tests"})
    return c


@pytest.fixture
def write_client():
    """TestClient authenticated with the read+write API token."""
    c = TestClient(app, raise_server_exceptions=False)
    c.headers.update({"Authorization": "Bearer write-token-for-tests"})
    return c
