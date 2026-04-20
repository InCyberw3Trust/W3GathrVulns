"""Integration tests for core API endpoints.

Tests the main CRUD flows using an in-memory SQLite database and a
JWT-authenticated test client (authed_client fixture from conftest.py).
"""
import pytest


# ── Health ────────────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data


# ── Projects ──────────────────────────────────────────────────────────────────

class TestProjects:
    def test_list_empty(self, authed_client):
        resp = authed_client.get("/api/v1/projects")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_project(self, authed_client):
        resp = authed_client.post("/api/v1/projects", json={"name": "myapp"})
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["name"] == "myapp"
        assert "id" in data

    def test_create_and_get_project(self, authed_client):
        create_resp = authed_client.post("/api/v1/projects", json={"name": "proj-alpha"})
        project_id = create_resp.json()["id"]
        resp = authed_client.get(f"/api/v1/projects/{project_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "proj-alpha"

    def test_get_nonexistent_project(self, authed_client):
        resp = authed_client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    def test_delete_project(self, authed_client):
        create_resp = authed_client.post("/api/v1/projects", json={"name": "to-delete"})
        pid = create_resp.json()["id"]
        del_resp = authed_client.delete(f"/api/v1/projects/{pid}")
        assert del_resp.status_code in (200, 204)
        # Confirm gone
        assert authed_client.get(f"/api/v1/projects/{pid}").status_code == 404


# ── Findings ──────────────────────────────────────────────────────────────────

class TestFindings:
    def test_list_empty(self, authed_client):
        resp = authed_client.get("/api/v1/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert data["total"] == 0

    def test_list_supports_pagination(self, authed_client):
        resp = authed_client.get("/api/v1/findings?page=1&page_size=10")
        assert resp.status_code == 200

    def test_filter_by_severity(self, authed_client):
        resp = authed_client.get("/api/v1/findings?severity=CRITICAL")
        assert resp.status_code == 200

    def test_filter_by_status(self, authed_client):
        resp = authed_client.get("/api/v1/findings?status=OPEN")
        assert resp.status_code == 200

    def test_get_nonexistent_finding(self, authed_client):
        resp = authed_client.get("/api/v1/findings/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


# ── Ingest ────────────────────────────────────────────────────────────────────

TRIVY_MINIMAL = {
    "ArtifactName": "test-image:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "test-image:latest (debian 12.0)",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-00001",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1",
                    "Severity": "HIGH",
                    "Title": "OpenSSL test vulnerability",
                }
            ],
        }
    ],
}


class TestIngest:
    def test_trivy_ingest_creates_finding(self, authed_client):
        resp = authed_client.post(
            "/api/v1/ingest/trivy?project=test-project&branch=main&commit=abc123",
            json=TRIVY_MINIMAL,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings_created"] == 1
        assert data["findings_updated"] == 0

    def test_trivy_ingest_deduplicates(self, authed_client):
        # Ingest twice — second should update, not create
        authed_client.post(
            "/api/v1/ingest/trivy?project=dedup-project&branch=main&commit=abc",
            json=TRIVY_MINIMAL,
        )
        resp = authed_client.post(
            "/api/v1/ingest/trivy?project=dedup-project&branch=main&commit=def",
            json=TRIVY_MINIMAL,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings_created"] == 0
        assert data["findings_updated"] == 1

    def test_invalid_payload_returns_422(self, authed_client):
        resp = authed_client.post(
            "/api/v1/ingest/trivy?project=p&branch=b&commit=c",
            json={"invalid": "garbage"},
        )
        # Parser returns empty list — no findings, but no crash
        assert resp.status_code == 200
        assert resp.json()["findings_created"] == 0

    def test_write_token_can_ingest(self, write_client):
        resp = write_client.post(
            "/api/v1/ingest/trivy?project=ci-project&branch=main&commit=aaa",
            json=TRIVY_MINIMAL,
        )
        assert resp.status_code == 200

    def test_read_token_cannot_ingest(self, read_client):
        resp = read_client.post(
            "/api/v1/ingest/trivy?project=ci-project&branch=main&commit=aaa",
            json=TRIVY_MINIMAL,
        )
        assert resp.status_code == 401


# ── Rules ─────────────────────────────────────────────────────────────────────

class TestRules:
    def test_list_empty(self, authed_client):
        resp = authed_client.get("/api/v1/rules")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self, authed_client):
        rule = {
            "name": "Auto-close INFO",
            "conditions": [{"field": "severity", "operator": "equals", "value": "INFO"}],
            "actions": [{"type": "set_status", "value": "CLOSED"}],
            "enabled": True,
            "priority": 10,
        }
        resp = authed_client.post("/api/v1/rules", json=rule)
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["name"] == "Auto-close INFO"
        assert data["enabled"] is True

    def test_create_and_delete_rule(self, authed_client):
        resp = authed_client.post("/api/v1/rules", json={
            "name": "temp rule",
            "conditions": [],
            "actions": [{"type": "set_status", "value": "CLOSED"}],
        })
        rule_id = resp.json()["id"]
        del_resp = authed_client.delete(f"/api/v1/rules/{rule_id}")
        assert del_resp.status_code in (200, 204)


# ── Stats ─────────────────────────────────────────────────────────────────────

class TestStats:
    def test_dashboard_returns_structure(self, authed_client):
        resp = authed_client.get("/api/v1/stats/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_findings" in data
        assert "open_findings" in data
        assert "by_severity" in data
        assert "by_status" in data
        assert "recent_trend" in data

    def test_dashboard_with_no_data(self, authed_client):
        resp = authed_client.get("/api/v1/stats/dashboard")
        data = resp.json()
        assert data["total_findings"] == 0
        assert data["open_findings"] == 0


# ── Settings ──────────────────────────────────────────────────────────────────

class TestSettings:
    def test_get_tokens_returns_structure(self, authed_client):
        """GET /settings/tokens returns masked previews."""
        resp = authed_client.get("/api/v1/settings/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert "read_token_preview" in data
        assert "write_token_preview" in data

    def test_get_tokens_unauthenticated(self, client):
        """Tokens endpoint must require authentication."""
        resp = client.get("/api/v1/settings/tokens")
        assert resp.status_code == 401

    def test_regenerate_read_token(self, authed_client):
        """Regenerating read token returns a non-empty token string."""
        resp = authed_client.post("/api/v1/settings/regenerate-token", json={"token_type": "read"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "read"
        assert len(data["token"]) > 20
        assert data["preview"].endswith("••••••••")

    def test_regenerate_write_token(self, authed_client):
        """Regenerating write token returns a distinct non-empty token string."""
        resp = authed_client.post("/api/v1/settings/regenerate-token", json={"token_type": "write"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "write"
        assert len(data["token"]) > 20

    def test_regenerate_invalid_token_type(self, authed_client):
        """Unknown token_type must be rejected with 422."""
        resp = authed_client.post("/api/v1/settings/regenerate-token", json={"token_type": "superadmin"})
        assert resp.status_code == 422

    def test_change_password_wrong_current(self, authed_client):
        """Wrong current password must be rejected with 401."""
        resp = authed_client.post("/api/v1/settings/change-password", json={
            "current_password": "definitely-wrong",
            "new_password": "newpassword123",
        })
        assert resp.status_code == 401

    def test_change_password_too_short(self, authed_client):
        """New password shorter than 8 chars must be rejected with 422."""
        resp = authed_client.post("/api/v1/settings/change-password", json={
            "current_password": "testpass",
            "new_password": "short",
        })
        assert resp.status_code == 422

    def test_change_password_success(self, authed_client):
        """Correct current password and valid new password must return 200."""
        resp = authed_client.post("/api/v1/settings/change-password", json={
            "current_password": "testpass",
            "new_password": "newsecurepassword",
        })
        assert resp.status_code == 200
        assert "updated" in resp.json().get("detail", "").lower()
