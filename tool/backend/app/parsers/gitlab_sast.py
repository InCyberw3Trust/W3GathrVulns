"""
Parser for GitLab Security reports.
Handles SAST (Semgrep/Bandit/ESLint), IaC (KICS) and Secret Detection (Gitleaks).
Auto-detects report type from scan.type or scanner.id.
"""
from typing import List, Dict, Any, Optional
from app.models import SeverityEnum, SourceEnum

SEVERITY_MAP = {
    "Critical": SeverityEnum.CRITICAL,
    "High":     SeverityEnum.HIGH,
    "Medium":   SeverityEnum.MEDIUM,
    "Low":      SeverityEnum.LOW,
    "Info":     SeverityEnum.INFO,
    "Unknown":  SeverityEnum.UNKNOWN,
}


# ── Source detection ───────────────────────────────────────────────────────────

def _detect_source(payload: Dict[str, Any], hint: str = "") -> SourceEnum:
    scan_type  = payload.get("scan", {}).get("type", "").lower()
    scanner_id = payload.get("scan", {}).get("scanner", {}).get("id", "").lower()
    hint       = hint.lower()
    if "secret" in scan_type or "secret" in hint or "gitleaks" in scanner_id:
        return SourceEnum.GITLAB_SECRETS
    if "iac" in scan_type or "iac" in hint or "kics" in scanner_id:
        return SourceEnum.GITLAB_IAC
    return SourceEnum.GITLAB_SAST


# ── Scan-level metadata (same for every finding in the report) ─────────────────

def _extract_scan_meta(payload: Dict[str, Any]) -> dict:
    scan = payload.get("scan", {})
    obs  = scan.get("observability", {}).get("events", [{}])[0]
    return {
        "report_version":   payload.get("version"),
        "scan_type":        scan.get("type"),
        "scan_status":      scan.get("status"),
        "scan_start":       scan.get("start_time"),
        "scan_end":         scan.get("end_time"),
        "analyzer_id":      scan.get("analyzer", {}).get("id"),
        "analyzer_name":    scan.get("analyzer", {}).get("name"),
        "analyzer_version": scan.get("analyzer", {}).get("version"),
        "scanner_id":       scan.get("scanner", {}).get("id"),
        "scanner_name":     scan.get("scanner", {}).get("name"),
        "scanner_version":  scan.get("scanner", {}).get("version"),
        # Observability extras (file count, duration)
        "scan_file_count":  obs.get("file_count"),
        "scan_time_s":      obs.get("time_s"),
    }


# ── Identifier extraction helpers ──────────────────────────────────────────────

def _parse_identifiers(identifiers: list) -> dict:
    """
    Fully parse all identifier types present in GitLab SAST reports.

    Known types observed in real reports:
      semgrep_id        → Semgrep rule slug + advisory URL
      cwe               → CWE number + mitre URL  (can be multiple)
      owasp             → OWASP category          (can be multiple, 2017 + 2021)
      cve               → CVE ID
      eslint_rule_id    → ESLint rule name
      bandit_test_id    → Bandit test ID (B113, B501…)
      njsscan_rule_type → NJSScan description
      kics_id           → KICS UUID (IaC only)
      gitleaks_rule_id  → Gitleaks rule (secrets only)
    """
    result = {
        "semgrep_id":        None,
        "semgrep_url":       None,
        "cve":               None,
        "cwes":              [],   # list of {"id": "CWE-338", "url": "..."}
        "owasp":             [],   # list of {"value": "A02:2021", "name": "..."}
        "eslint_rule_id":    None,
        "bandit_test_id":    None,
        "njsscan_rule_type": None,
        "kics_id":           None,
        "kics_doc_url":      None,
        "gitleaks_rule_id":  None,
        "all_identifiers":   identifiers,
    }

    for ident in identifiers:
        t   = ident.get("type", "")
        val = ident.get("value", "")
        url = ident.get("url")
        name = ident.get("name", "")

        if t == "semgrep_id":
            result["semgrep_id"]  = val
            result["semgrep_url"] = url

        elif t == "cve":
            result["cve"] = val

        elif t == "cwe":
            result["cwes"].append({"id": f"CWE-{val}" if not val.startswith("CWE") else val, "url": url})

        elif t == "owasp":
            result["owasp"].append({"value": val, "name": name})

        elif t == "eslint_rule_id":
            result["eslint_rule_id"] = val

        elif t == "bandit_test_id":
            result["bandit_test_id"] = val

        elif t == "njsscan_rule_type":
            result["njsscan_rule_type"] = val   # descriptive string

        elif t == "kics_id":
            result["kics_id"]      = val
            result["kics_doc_url"] = url

        elif t == "gitleaks_rule_id":
            result["gitleaks_rule_id"] = val

    return result


# ── SAST parser (Semgrep / Bandit / ESLint) ────────────────────────────────────

def _parse_sast(vuln: dict, scan_meta: dict) -> dict:
    """
    Full extraction for GitLab SAST findings (Semgrep + all sub-analyzers).

    vuln_id priority: semgrep_id > cve > cwe[0] > gl_id
    """
    location    = vuln.get("location", {})
    identifiers = vuln.get("identifiers", [])
    ids         = _parse_identifiers(identifiers)

    # Best vuln_id: prefer the Semgrep rule slug
    vuln_id = (
        ids["semgrep_id"] or
        ids["cve"] or
        (ids["cwes"][0]["id"] if ids["cwes"] else None) or
        vuln.get("id", "")
    )

    # Primary CWE for display
    primary_cwe     = ids["cwes"][0]["id"]  if ids["cwes"] else None
    primary_cwe_url = ids["cwes"][0]["url"] if ids["cwes"] else None

    return {
        # ── Core ──────────────────────────────────────────────────
        "title":             vuln.get("name", "Unknown vulnerability"),
        "description":       vuln.get("description", ""),
        "severity":          SEVERITY_MAP.get(vuln.get("severity", "Unknown"), SeverityEnum.UNKNOWN),
        "source":            SourceEnum.GITLAB_SAST,
        "vuln_id":           vuln_id,
        "cve":               ids["cve"],
        "file_path":         location.get("file"),
        "line_start":        location.get("start_line"),
        "line_end":          location.get("end_line"),   # multi-line findings (Bandit)
        "component":         location.get("dependency", {}).get("package", {}).get("name"),
        "component_version": location.get("dependency", {}).get("version"),
        # ── Tags: scanner + CWE + OWASP categories ───────────────
        "tags": list(filter(None, [
            "sast",
            ids["semgrep_id"],
            ids["bandit_test_id"],
            primary_cwe,
            ids["cwes"][1]["id"] if len(ids["cwes"]) > 1 else None,
        ])),
        # ── Structured extra data ─────────────────────────────────
        "extra_data": {
            "gl_finding_id":    vuln.get("id"),
            "category":         vuln.get("category"),

            # Rule identifiers
            "semgrep_id":       ids["semgrep_id"],
            "semgrep_url":      ids["semgrep_url"],
            "bandit_test_id":   ids["bandit_test_id"],
            "eslint_rule_id":   ids["eslint_rule_id"],
            "njsscan_rule_type":ids["njsscan_rule_type"],

            # Weakness classification
            "cwes":             ids["cwes"],          # all CWEs with URLs
            "primary_cwe":      primary_cwe,
            "primary_cwe_url":  primary_cwe_url,

            # OWASP (both 2017 and 2021 entries when present)
            "owasp":            ids["owasp"],

            # Scanner info
            "scanner":          vuln.get("scanner", {}),
            "all_identifiers":  identifiers,

            # Scan-level metadata
            **scan_meta,
        },
        "raw_data": vuln,
    }


# ── IaC parser (KICS) ──────────────────────────────────────────────────────────

def _parse_iac(vuln: dict, scan_meta: dict) -> dict:
    location    = vuln.get("location", {})
    identifiers = vuln.get("identifiers", [])
    ids         = _parse_identifiers(identifiers)

    line = location.get("start_line")
    if not line:
        parts = vuln.get("cve", "").split(":")
        if len(parts) >= 3:
            try:
                line = int(parts[-2])
            except ValueError:
                pass

    return {
        "title":      vuln.get("name", "IaC Misconfiguration"),
        "description": vuln.get("description", ""),
        "severity":   SEVERITY_MAP.get(vuln.get("severity", "Unknown"), SeverityEnum.UNKNOWN),
        "source":     SourceEnum.GITLAB_IAC,
        "vuln_id":    ids["kics_id"] or vuln.get("id", ""),
        "file_path":  location.get("file"),
        "line_start": line,
        "tags":       list(filter(None, ["iac", "kics", vuln.get("scanner", {}).get("id")])),
        "extra_data": {
            "gl_finding_id": vuln.get("id"),
            "category":      vuln.get("category"),
            "kics_id":       ids["kics_id"],
            "doc_url":       ids["kics_doc_url"],
            "scanner":       vuln.get("scanner", {}),
            "all_identifiers": identifiers,
            **scan_meta,
        },
        "raw_data": vuln,
    }


# ── Secrets parser (Gitleaks) ──────────────────────────────────────────────────

def _parse_secret(vuln: dict, scan_meta: dict) -> dict:
    location    = vuln.get("location", {})
    identifiers = vuln.get("identifiers", [])
    ids         = _parse_identifiers(identifiers)

    commit      = location.get("commit", {}).get("sha", "")
    raw_extract = vuln.get("raw_source_code_extract", "")
    masked      = _mask_secret(raw_extract)

    desc = vuln.get("description", "")
    if masked:
        desc = f"{desc}\n\n**Leaked value (masked):** `{masked}`"
    if commit and commit != "0000000":
        desc = f"{desc}\n\n**Commit:** `{commit}`"

    return {
        "title":      vuln.get("name", "Secret detected"),
        "description": desc.strip(),
        "severity":   SEVERITY_MAP.get(vuln.get("severity", "Critical"), SeverityEnum.CRITICAL),
        "source":     SourceEnum.GITLAB_SECRETS,
        "vuln_id":    ids["gitleaks_rule_id"] or vuln.get("id", ""),
        "file_path":  location.get("file"),
        "line_start": location.get("start_line"),
        "tags":       ["secret", "gitleaks"],
        "extra_data": {
            "gl_finding_id":      vuln.get("id"),
            "rule_id":            ids["gitleaks_rule_id"],
            "confidence":         vuln.get("confidence"),
            "commit_sha":         commit,
            "raw_extract_masked": masked,
            "scanner":            vuln.get("scanner", {}),
            "all_identifiers":    identifiers,
            **scan_meta,
        },
        "raw_data": {k: v for k, v in vuln.items() if k != "raw_source_code_extract"},
    }


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "****" + value[-4:]


# ── Entry point ────────────────────────────────────────────────────────────────

PARSERS = {
    SourceEnum.GITLAB_SAST:    _parse_sast,
    SourceEnum.GITLAB_IAC:     _parse_iac,
    SourceEnum.GITLAB_SECRETS: _parse_secret,
}


def parse(payload: Dict[str, Any], source_hint: str = "") -> List[Dict[str, Any]]:
    source    = _detect_source(payload, source_hint)
    parser    = PARSERS[source]
    scan_meta = _extract_scan_meta(payload)
    findings  = []
    seen_ids  = set()

    for vuln in payload.get("vulnerabilities", []):
        gl_id = vuln.get("id", "")
        if gl_id and gl_id in seen_ids:
            continue
        if gl_id:
            seen_ids.add(gl_id)
        try:
            f = parser(vuln, scan_meta)
            f["source"] = source
            findings.append(f)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to parse vuln {gl_id}: {e}")

    return findings
