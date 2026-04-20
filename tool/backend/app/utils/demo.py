"""Demo mode — hourly data wipe and sample re-injection."""
import logging
from datetime import datetime, timedelta, timezone

from app.models import SourceEnum

logger = logging.getLogger(__name__)

# Each entry: project, source enum, parser key, parser hint (for gitlab), days_ago, payload
_SAMPLES = [
    {
        "project": "web-frontend",
        "source": SourceEnum.TRIVY,
        "parser": "trivy",
        "hint": None,
        "days_ago": 25,
        "payload": {
            "Results": [{
                "Target": "web-frontend:latest (debian 12.0)",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-44487",
                        "PkgName": "nghttp2",
                        "InstalledVersion": "1.52.0-1",
                        "FixedVersion": "1.52.0-1+deb12u1",
                        "Severity": "HIGH",
                        "Title": "HTTP/2 Rapid Reset Attack",
                        "Description": "Denial of service via rapid HTTP/2 stream cancellation.",
                        "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2023-4911",
                        "PkgName": "glibc",
                        "InstalledVersion": "2.36-9+deb12u1",
                        "FixedVersion": "2.36-9+deb12u3",
                        "Severity": "CRITICAL",
                        "Title": "Looney Tunables — local privilege escalation via GLIBC_TUNABLES",
                        "Description": "Buffer overflow in glibc dynamic loader ld.so via GLIBC_TUNABLES environment variable.",
                        "CVSS": {"nvd": {"V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                    },
                    {
                        "VulnerabilityID": "CVE-2023-2975",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.9-1",
                        "FixedVersion": "3.0.10-1",
                        "Severity": "MEDIUM",
                        "Title": "OpenSSL AES-SIV implementation bug",
                        "Description": "AES-SIV cipher ignores empty associated data entries which should be authenticated.",
                        "CVSS": {"nvd": {"V3Score": 5.3}},
                    },
                    {
                        "VulnerabilityID": "CVE-2022-40897",
                        "PkgName": "setuptools",
                        "InstalledVersion": "65.5.0",
                        "FixedVersion": "65.5.1",
                        "Severity": "HIGH",
                        "Title": "pypa/setuptools ReDoS via malformed package_url parameter",
                        "Description": "Regular expression denial of service via malformed package URL.",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                    },
                ],
            }],
        },
    },
    {
        "project": "backend-api",
        "source": SourceEnum.GITLAB_SAST,
        "parser": "gitlab_sast",
        "hint": "sast",
        "days_ago": 20,
        "payload": {
            "version": "15.0.4",
            "vulnerabilities": [
                {
                    "id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                    "category": "sast",
                    "name": "SQL Injection via raw query",
                    "message": "User-controlled input passed directly to a raw SQL query",
                    "description": "Detected user-supplied input used in a raw SQL query. This can lead to SQL injection.",
                    "severity": "Critical",
                    "scanner": {"id": "semgrep", "name": "Semgrep"},
                    "location": {"file": "src/db/queries.py", "start_line": 42, "end_line": 42},
                    "identifiers": [{"type": "cwe", "name": "CWE-89", "value": "89"}],
                },
                {
                    "id": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
                    "category": "sast",
                    "name": "Hardcoded AWS access key",
                    "message": "Hardcoded AWS access key found in source code",
                    "description": "A hardcoded AWS access key was detected. Rotate this credential immediately.",
                    "severity": "High",
                    "scanner": {"id": "semgrep", "name": "Semgrep"},
                    "location": {"file": "config/aws.py", "start_line": 8, "end_line": 8},
                    "identifiers": [{"type": "cwe", "name": "CWE-798", "value": "798"}],
                },
                {
                    "id": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
                    "category": "sast",
                    "name": "Use of insecure MD5 hash",
                    "message": "MD5 is cryptographically weak and should not be used for sensitive data",
                    "description": "The use of MD5 for hashing is considered insecure. Use SHA-256 or stronger.",
                    "severity": "Medium",
                    "scanner": {"id": "semgrep", "name": "Semgrep"},
                    "location": {"file": "src/auth/utils.py", "start_line": 17, "end_line": 17},
                    "identifiers": [{"type": "cwe", "name": "CWE-327", "value": "327"}],
                },
                {
                    "id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a2",
                    "category": "sast",
                    "name": "Path traversal via unsanitised user input",
                    "message": "User input used in file path without sanitisation",
                    "description": "User-controlled data reaches a file open call. An attacker may traverse the file system.",
                    "severity": "Critical",
                    "scanner": {"id": "semgrep", "name": "Semgrep"},
                    "location": {"file": "src/files/handler.py", "start_line": 93, "end_line": 93},
                    "identifiers": [{"type": "cwe", "name": "CWE-22", "value": "22"}],
                },
            ],
            "scan": {"scanner": {"id": "semgrep", "name": "Semgrep"}, "type": "sast", "status": "success"},
        },
    },
    {
        "project": "backend-api",
        "source": SourceEnum.GITLAB_SECRETS,
        "parser": "gitlab_sast",
        "hint": "secrets",
        "days_ago": 15,
        "payload": {
            "version": "15.0.4",
            "vulnerabilities": [
                {
                    "id": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
                    "category": "secret_detection",
                    "name": "GitHub Personal Access Token",
                    "message": "GitHub Personal Access Token detected in source code",
                    "description": "A GitHub Personal Access Token was found. Revoke it immediately and rotate secrets.",
                    "severity": "Critical",
                    "scanner": {"id": "gitleaks", "name": "Gitleaks"},
                    "location": {"file": "scripts/deploy.sh", "start_line": 3, "end_line": 3},
                    "identifiers": [{"type": "gitleaks_rule_id", "name": "github-pat", "value": "github-pat"}],
                },
                {
                    "id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d5",
                    "category": "secret_detection",
                    "name": "Generic API Key",
                    "message": "High-entropy string resembling an API key detected",
                    "description": "A high-entropy string resembling an API key was found in a config file.",
                    "severity": "Critical",
                    "scanner": {"id": "gitleaks", "name": "Gitleaks"},
                    "location": {"file": "config/settings.json", "start_line": 22, "end_line": 22},
                    "identifiers": [{"type": "gitleaks_rule_id", "name": "generic-api-key", "value": "generic-api-key"}],
                },
            ],
            "scan": {"scanner": {"id": "gitleaks", "name": "Gitleaks"}, "type": "secret_detection", "status": "success"},
        },
    },
    {
        "project": "infra",
        "source": SourceEnum.GITLAB_IAC,
        "parser": "gitlab_sast",
        "hint": "iac",
        "days_ago": 10,
        "payload": {
            "version": "15.0.4",
            "vulnerabilities": [
                {
                    "id": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
                    "category": "sast",
                    "name": "Docker COPY adding sensitive directory",
                    "message": "Sensitive directory is being added to Docker image",
                    "description": "COPY . . adds the entire build context, potentially including secrets and config files.",
                    "severity": "High",
                    "scanner": {"id": "kics", "name": "KICS"},
                    "location": {"file": "Dockerfile", "start_line": 5, "end_line": 5},
                    "identifiers": [{"type": "kics", "name": "Sensitive Directory Mount", "value": "b03a748a-542d-44f4-bb86-9199ab4fd2d5"}],
                },
                {
                    "id": "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "category": "sast",
                    "name": "Container running as root",
                    "message": "Container does not define a non-root user",
                    "description": "Running containers as root increases the risk of container escape attacks.",
                    "severity": "Medium",
                    "scanner": {"id": "kics", "name": "KICS"},
                    "location": {"file": "docker-compose.yml", "start_line": 12, "end_line": 12},
                    "identifiers": [{"type": "kics", "name": "Container Running As Root", "value": "9b6b2f85-92d4-4a6e-b46e-92d1c6e7e0d7"}],
                },
                {
                    "id": "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c4",
                    "category": "sast",
                    "name": "Missing memory limit in container",
                    "message": "Container resource limits not defined",
                    "description": "Containers without memory limits can exhaust host resources, causing denial of service.",
                    "severity": "Medium",
                    "scanner": {"id": "kics", "name": "KICS"},
                    "location": {"file": "docker-compose.yml", "start_line": 24, "end_line": 24},
                    "identifiers": [{"type": "kics", "name": "Missing Memory Limit", "value": "4d55f2b1-d2c3-4e5f-9876-a1b2c3d4e5f6"}],
                },
            ],
            "scan": {"scanner": {"id": "kics", "name": "KICS"}, "type": "sast", "status": "success"},
        },
    },
    {
        "project": "web-frontend",
        "source": SourceEnum.OWASP_ZAP,
        "parser": "owasp_zap",
        "hint": None,
        "days_ago": 7,
        "payload": {
            "site": [{
                "@name": "https://web-frontend.example.com",
                "@host": "web-frontend.example.com",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alertRef": "40012-1",
                        "alert": "Cross Site Scripting (Reflected)",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "2",
                        "riskdesc": "High (Medium)",
                        "desc": "XSS via reflected user input — attacker-supplied code echoed into the browser.",
                        "method": "GET",
                        "solution": "Sanitize all user inputs and implement Content-Security-Policy.",
                        "instances": [{"uri": "https://web-frontend.example.com/search", "method": "GET", "param": "q", "attack": "<script>alert(1)</script>", "evidence": "<script>alert(1)</script>"}],
                    },
                    {
                        "pluginid": "10038",
                        "alertRef": "10038-1",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "riskdesc": "Medium (High)",
                        "desc": "CSP is not configured — increases risk of XSS and data injection attacks.",
                        "method": "GET",
                        "solution": "Configure Content-Security-Policy on your web server.",
                        "instances": [{"uri": "https://web-frontend.example.com/", "method": "GET", "param": "", "attack": "", "evidence": ""}],
                    },
                    {
                        "pluginid": "10016",
                        "alertRef": "10016-1",
                        "alert": "Web Browser XSS Protection Not Enabled",
                        "name": "Web Browser XSS Protection Not Enabled",
                        "riskcode": "1",
                        "confidence": "2",
                        "riskdesc": "Low (Medium)",
                        "desc": "The X-XSS-Protection header is not set, disabling the XSS filter built into most browsers.",
                        "method": "GET",
                        "solution": "Ensure each page sets the X-XSS-Protection HTTP response header.",
                        "instances": [{"uri": "https://web-frontend.example.com/", "method": "GET", "param": "", "attack": "", "evidence": ""}],
                    },
                ],
            }],
        },
    },
    {
        "project": "infra",
        "source": SourceEnum.NUCLEI,
        "parser": "nuclei",
        "hint": None,
        "days_ago": 3,
        "payload": [
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Apache Log4j RCE (Log4Shell)",
                    "author": ["pdteam"],
                    "tags": ["cve", "cve2021", "log4j", "rce", "oast"],
                    "description": "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP endpoints.",
                    "severity": "critical",
                    "classification": {
                        "cve_id": ["CVE-2021-44228"],
                        "cwe_id": ["CWE-917"],
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "cvss_score": 10.0,
                    },
                },
                "type": "http",
                "host": "https://infra.example.com",
                "matched_at": "https://infra.example.com/api/login",
                "timestamp": "2024-01-14T10:05:00Z",
            },
            {
                "template-id": "CVE-2023-23397",
                "info": {
                    "name": "Microsoft Outlook NTLM Hash Leak",
                    "author": ["pdteam"],
                    "tags": ["cve", "cve2023", "outlook", "ntlm"],
                    "description": "Microsoft Outlook allows NTLM hash theft via specially crafted email.",
                    "severity": "high",
                    "classification": {
                        "cve_id": ["CVE-2023-23397"],
                        "cwe_id": ["CWE-294"],
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cvss_score": 9.8,
                    },
                },
                "type": "http",
                "host": "https://infra.example.com",
                "matched_at": "https://infra.example.com/api/webhook",
                "timestamp": "2024-01-14T10:05:05Z",
            },
            {
                "template-id": "exposed-panels-grafana",
                "info": {
                    "name": "Grafana Unauthenticated Panel Access",
                    "author": ["pdteam"],
                    "tags": ["panel", "grafana", "exposure"],
                    "description": "Grafana dashboard is accessible without authentication.",
                    "severity": "medium",
                    "classification": {"cvss_score": 5.3},
                },
                "type": "http",
                "host": "https://infra.example.com",
                "matched_at": "https://infra.example.com:3000",
                "timestamp": "2024-01-14T10:05:10Z",
            },
        ],
    },
    {
        "project": "backend-api",
        "source": SourceEnum.TRIVY,
        "parser": "trivy",
        "hint": None,
        "days_ago": 1,
        "payload": {
            "Results": [{
                "Target": "backend-api:latest (debian 12.0)",
                "Type": "debian",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-38408",
                        "PkgName": "openssh-client",
                        "InstalledVersion": "1:9.2p1-2",
                        "FixedVersion": "1:9.2p1-2+deb12u2",
                        "Severity": "CRITICAL",
                        "Title": "OpenSSH ssh-agent remote code execution via PKCS#11",
                        "Description": "The PKCS#11 feature in ssh-agent allows remote code execution by loading malicious shared libraries.",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    },
                    {
                        "VulnerabilityID": "CVE-2023-3446",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.9-1",
                        "FixedVersion": "3.0.10-1",
                        "Severity": "LOW",
                        "Title": "OpenSSL DH_check() excessive time with large Q parameter",
                        "Description": "Checking excessively long DH keys or parameters may be very slow, causing DoS.",
                        "CVSS": {"nvd": {"V3Score": 5.3}},
                    },
                ],
            }],
        },
    },
]


def reset_and_seed():
    """Wipe all data and reinject demo findings. Called hourly in demo mode."""
    from app.database import SessionLocal
    from app.models import Finding, Scan, Project
    from app.routers.ingest import ingest_findings
    from app.parsers import trivy, gitlab_sast, owasp_zap, nuclei

    def _parse(parser_key, hint, payload):
        if parser_key == "trivy":
            return trivy.parse(payload)
        if parser_key == "gitlab_sast":
            return gitlab_sast.parse(payload, hint or "sast")
        if parser_key == "owasp_zap":
            return owasp_zap.parse(payload)
        if parser_key == "nuclei":
            return nuclei.parse(payload)
        return []

    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(Project).delete()
        db.commit()
        logger.info("[demo] All data wiped")

        now = datetime.now(timezone.utc)
        total_created = 0

        for sample in _SAMPLES:
            try:
                parsed = _parse(sample["parser"], sample.get("hint"), sample["payload"])
                scan_date = now - timedelta(days=sample["days_ago"])
                result = ingest_findings(
                    db=db,
                    project_name=sample["project"],
                    source=sample["source"],
                    parsed_findings=parsed,
                    branch="main",
                    commit_sha="demo",
                    pipeline_id="demo",
                    scan_date=scan_date,
                )
                total_created += result.findings_created
                logger.info("[demo] %s / %s: %d findings injected", sample["project"], sample["source"].value, result.findings_created)
            except Exception as exc:
                logger.error("[demo] Failed to inject %s / %s: %s", sample["project"], sample.get("source"), exc)
                db.rollback()

        logger.info("[demo] Reset complete — %d total findings across %d projects", total_created, len({s["project"] for s in _SAMPLES}))
    except Exception as exc:
        logger.error("[demo] Reset failed: %s", exc)
        db.rollback()
    finally:
        db.close()
