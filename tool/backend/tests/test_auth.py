"""Integration tests for authentication.

Tests:
  - UI login (valid / invalid credentials)
  - JWT token usage
  - API token access (read vs write)
  - Unauthenticated requests are rejected
"""
import pytest
from app.utils.auth import create_access_token, verify_token, check_api_token


# ── JWT utils ─────────────────────────────────────────────────────────────────

class TestJWTUtils:
    def test_create_and_verify(self):
        token = create_access_token("admin")
        sub = verify_token(token)
        assert sub == "admin"

    def test_invalid_token_returns_none(self):
        assert verify_token("not-a-token") is None
        assert verify_token("") is None
        assert verify_token("eyJhbGciOiJub25lIn0.e30.") is None

    def test_tampered_token_returns_none(self):
        token = create_access_token("admin")
        tampered = token[:-4] + "XXXX"
        assert verify_token(tampered) is None


# ── API token logic ───────────────────────────────────────────────────────────

class TestAPITokenCheck:
    def test_write_token_allows_all_methods(self):
        for method in ("GET", "POST", "PATCH", "DELETE", "PUT"):
            assert check_api_token("write-token-for-tests", method)

    def test_read_token_allows_get_only(self):
        assert check_api_token("read-token-for-tests", "GET")
        assert not check_api_token("read-token-for-tests", "POST")
        assert not check_api_token("read-token-for-tests", "PATCH")
        assert not check_api_token("read-token-for-tests", "DELETE")

    def test_wrong_token_denied(self):
        assert not check_api_token("wrong-token", "GET")
        assert not check_api_token("", "GET")


# ── Login endpoint ────────────────────────────────────────────────────────────

class TestLogin:
    def test_valid_login_returns_token(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "testuser", "password": "testpass"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Token must be valid
        assert verify_token(data["access_token"]) == "testuser"

    def test_wrong_password_rejected(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "testuser", "password": "wrongpass"
        })
        assert resp.status_code == 401

    def test_wrong_username_rejected(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "username": "hacker", "password": "testpass"
        })
        assert resp.status_code == 401

    def test_empty_body_rejected(self, client):
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422  # Pydantic validation error


# ── Protected route access ────────────────────────────────────────────────────

class TestProtectedAccess:
    def test_unauthenticated_request_rejected(self, client):
        resp = client.get("/api/v1/findings")
        assert resp.status_code == 401

    def test_jwt_allows_access(self, authed_client):
        resp = authed_client.get("/api/v1/findings")
        assert resp.status_code == 200

    def test_write_token_allows_get(self, write_client):
        resp = write_client.get("/api/v1/findings")
        assert resp.status_code == 200

    def test_read_token_allows_get(self, read_client):
        resp = read_client.get("/api/v1/findings")
        assert resp.status_code == 200

    def test_read_token_blocks_post(self, read_client):
        # Read token should not be able to POST (write operation)
        resp = read_client.post("/api/v1/projects", json={"name": "test"})
        assert resp.status_code == 401

    def test_health_endpoint_is_public(self, client):
        """Health check must be accessible without auth."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_invalid_bearer_token_rejected(self, client):
        resp = client.get("/api/v1/findings", headers={"Authorization": "Bearer invalid-garbage"})
        assert resp.status_code == 401

    def test_missing_bearer_prefix_rejected(self, client):
        resp = client.get("/api/v1/findings", headers={"Authorization": "write-token-for-tests"})
        assert resp.status_code == 401


# ── /auth/me endpoint ─────────────────────────────────────────────────────────

class TestMeEndpoint:
    def test_me_returns_username(self, authed_client):
        resp = authed_client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        assert resp.json()["username"] == "testuser"
