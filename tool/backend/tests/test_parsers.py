"""Unit tests for all scanner parsers.

These tests are pure unit tests — no database, no HTTP, just parser functions.
"""
import pytest
from app.parsers import trivy, gitlab_sast, owasp_zap, nuclei


# ── Trivy ─────────────────────────────────────────────────────────────────────

TRIVY_VULN_PAYLOAD = {
    "ArtifactName": "myapp:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "myapp:latest (debian 12.0)",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-44487",
                    "PkgName": "nghttp2",
                    "InstalledVersion": "1.52.0-1",
                    "FixedVersion": "1.52.0-1+deb12u1",
                    "Severity": "HIGH",
                    "Title": "HTTP/2 rapid reset vulnerability",
                    "Description": "NGHTTP2 vulnerable to HTTP/2 Rapid Reset Attack",
                    "CVSS": {
                        "nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
                    },
                }
            ],
        }
    ],
}

TRIVY_MISCONFIG_PAYLOAD = {
    "ArtifactName": "Dockerfile",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "Dockerfile",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "Type": "Dockerfile Security Check",
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Description": "Running containers as root is a security risk.",
                    "Severity": "CRITICAL",
                    "Resolution": "Add a non-root USER statement to the Dockerfile",
                }
            ],
        }
    ],
}


class TestTrivyParser:
    def test_parses_vulnerability(self):
        results = trivy.parse(TRIVY_VULN_PAYLOAD)
        assert len(results) == 1
        f = results[0]
        assert f["title"] == "CVE-2023-44487 in nghttp2"
        assert f["severity"].value == "HIGH"
        assert f["cve"] == "CVE-2023-44487"
        assert f["cvss_score"] == "7.5"
        assert f["component"] == "nghttp2"
        assert f["fixed_version"] == "1.52.0-1+deb12u1"

    def test_parses_misconfiguration(self):
        results = trivy.parse(TRIVY_MISCONFIG_PAYLOAD)
        assert len(results) == 1
        f = results[0]
        assert "DS002" in f["title"]
        assert f["severity"].value == "CRITICAL"

    def test_empty_payload(self):
        assert trivy.parse({}) == []
        assert trivy.parse({"Results": []}) == []

    def test_unknown_severity_maps_to_unknown(self):
        payload = {
            "Results": [{
                "Target": "test",
                "Type": "os",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-X", "PkgName": "pkg", "Severity": "WHATEVER"}],
            }]
        }
        results = trivy.parse(payload)
        assert results[0]["severity"].value == "UNKNOWN"

    def test_cvss_prefers_nvd_v3(self):
        payload = {
            "Results": [{
                "Target": "t",
                "Type": "os",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-TEST",
                    "PkgName": "lib",
                    "Severity": "HIGH",
                    "CVSS": {
                        "nvd": {"V3Score": 8.1, "V2Score": 6.5},
                        "other": {"V3Score": 5.0},
                    },
                }],
            }]
        }
        results = trivy.parse(payload)
        assert results[0]["cvss_score"] == "8.1"


# ── GitLab SAST ───────────────────────────────────────────────────────────────

GITLAB_SAST_PAYLOAD = {
    "version": "15.0.4",
    "vulnerabilities": [
        {
            "id": "abc123",
            "name": "SQL Injection",
            "description": "Possible SQL injection via unsanitized input",
            "severity": "Critical",
            "location": {
                "file": "app/db.py",
                "start_line": 42,
                "end_line": 42,
            },
            "identifiers": [
                {"type": "cwe", "value": "89", "name": "CWE-89"},
                {"type": "bandit_test_id", "value": "B608", "name": "B608"},
            ],
            "scanner": {"id": "bandit", "name": "Bandit"},
        }
    ],
}


class TestGitLabSASTParser:
    def test_parses_vulnerability(self):
        results = gitlab_sast.parse(GITLAB_SAST_PAYLOAD)
        assert len(results) == 1
        f = results[0]
        assert f["title"] == "SQL Injection"
        assert f["severity"].value == "CRITICAL"
        assert f["file_path"] == "app/db.py"
        assert f["line_start"] == 42

    def test_empty_payload(self):
        assert gitlab_sast.parse({}) == []
        assert gitlab_sast.parse({"vulnerabilities": []}) == []

    def test_severity_mapping(self):
        for gitlab_sev, expected in [
            ("Critical", "CRITICAL"), ("High", "HIGH"),
            ("Medium", "MEDIUM"), ("Low", "LOW"), ("Info", "INFO"),
        ]:
            payload = {
                "vulnerabilities": [{
                    "id": "x", "name": "Test", "severity": gitlab_sev,
                    "location": {"file": "f.py"},
                }]
            }
            results = gitlab_sast.parse(payload)
            assert results[0]["severity"].value == expected


# ── OWASP ZAP ─────────────────────────────────────────────────────────────────

ZAP_PAYLOAD = {
    "site": [
        {
            "@name": "https://app.example.com",
            "alerts": [
                {
                    "pluginid": "10038",
                    "alertRef": "10038",
                    "alert": "Content Security Policy (CSP) Header Not Set",
                    "riskdesc": "Medium (Medium)",
                    "desc": "CSP not configured.",
                    "solution": "Add a CSP header.",
                    "reference": "https://owasp.org",
                    "instances": [
                        {"uri": "https://app.example.com/", "method": "GET", "evidence": ""}
                    ],
                }
            ],
        }
    ]
}


class TestOWASPZAPParser:
    def test_parses_alert(self):
        results = owasp_zap.parse(ZAP_PAYLOAD)
        assert len(results) >= 1
        f = results[0]
        assert "Content Security Policy" in f["title"]
        assert f["severity"].value == "MEDIUM"

    def test_empty_payload(self):
        assert owasp_zap.parse({}) == []
        assert owasp_zap.parse({"site": []}) == []


# ── Nuclei ────────────────────────────────────────────────────────────────────

NUCLEI_PAYLOAD = [
    {
        "template-id": "CVE-2021-44228",
        "info": {
            "name": "Apache Log4j RCE",
            "author": ["projectdiscovery"],
            "severity": "critical",
            "description": "Log4Shell vulnerability",
            "tags": ["cve", "log4j", "rce"],
        },
        "matched-at": "https://app.example.com:8080/api/login",
        "host": "https://app.example.com",
        "type": "http",
        "ip": "10.0.0.1",
    }
]


class TestNucleiParser:
    def test_parses_finding(self):
        results = nuclei.parse(NUCLEI_PAYLOAD)
        assert len(results) == 1
        f = results[0]
        assert "Log4j" in f["title"] or "CVE-2021-44228" in f["title"]
        assert f["severity"].value == "CRITICAL"

    def test_empty_payload(self):
        assert nuclei.parse([]) == []
        assert nuclei.parse({}) == []
