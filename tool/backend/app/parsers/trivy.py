"""Parser for Trivy JSON output (trivy image/fs --format json)"""
from typing import List, Dict, Any
from app.models import SeverityEnum, SourceEnum

SEVERITY_MAP = {
    "CRITICAL":   SeverityEnum.CRITICAL,
    "HIGH":       SeverityEnum.HIGH,
    "MEDIUM":     SeverityEnum.MEDIUM,
    "LOW":        SeverityEnum.LOW,
    "NEGLIGIBLE": SeverityEnum.INFO,
    "UNKNOWN":    SeverityEnum.UNKNOWN,
}


def _best_cvss(cvss: dict) -> tuple[str | None, str | None]:
    """Return (score, vector) preferring NVD V3 > NVD V2 > first available."""
    if not cvss:
        return None, None
    for source in ("nvd", *[k for k in cvss if k != "nvd"]):
        entry = cvss.get(source, {})
        if entry.get("V3Score"):
            return str(entry["V3Score"]), entry.get("V3Vector")
        if entry.get("V2Score"):
            return str(entry["V2Score"]), entry.get("V2Vector")
    return None, None


def parse(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    for result in payload.get("Results", []):
        target      = result.get("Target", "")
        result_type = result.get("Type", "")
        artifact    = payload.get("ArtifactName", "")
        artifact_type = payload.get("ArtifactType", "")

        # ── Vulnerabilities ───────────────────────────────────────
        for vuln in result.get("Vulnerabilities") or []:
            cvss        = vuln.get("CVSS", {})
            cvss_score, cvss_vector = _best_cvss(cvss)

            pkg_id      = vuln.get("PkgID", "")
            purl        = vuln.get("PkgIdentifier", {}).get("PURL", "")
            vuln_id     = vuln.get("VulnerabilityID", "")
            is_cve      = vuln_id.startswith("CVE-")

            # Collect all CVSS details for raw storage
            cvss_detail = {}
            for src, scores in cvss.items():
                cvss_detail[src] = {
                    k: scores[k] for k in ("V2Score","V3Score","V2Vector","V3Vector") if k in scores
                }

            findings.append({
                "title":             f"{vuln_id} in {vuln.get('PkgName','unknown')}",
                "description":       vuln.get("Description", ""),
                "severity":          SEVERITY_MAP.get(vuln.get("Severity","UNKNOWN").upper(), SeverityEnum.UNKNOWN),
                "source":            SourceEnum.TRIVY,
                "vuln_id":           vuln_id,
                "cve":               vuln_id if is_cve else None,
                "cvss_score":        cvss_score,
                "file_path":         target,
                "component":         vuln.get("PkgName"),
                "component_version": vuln.get("InstalledVersion"),
                "fixed_version":     vuln.get("FixedVersion"),
                "tags":              list(filter(None, [result_type, artifact_type, vuln.get("Status")])),
                # Extended fields stored in extra_data
                "extra_data": {
                    "pkg_id":            pkg_id,
                    "purl":              purl,
                    "pkg_status":        vuln.get("Status"),
                    "severity_source":   vuln.get("SeveritySource"),
                    "primary_url":       vuln.get("PrimaryURL"),
                    "title_short":       vuln.get("Title"),
                    "cwe_ids":           vuln.get("CweIDs", []),
                    "cvss":              cvss_detail,
                    "cvss_vector":       cvss_vector,
                    "vendor_severity":   vuln.get("VendorSeverity", {}),
                    "references":        vuln.get("References", []),
                    "published_date":    vuln.get("PublishedDate"),
                    "last_modified":     vuln.get("LastModifiedDate"),
                    "data_source":       vuln.get("DataSource", {}),
                    "layer":             vuln.get("Layer", {}),
                    "fingerprint":       vuln.get("Fingerprint"),
                    "artifact":          artifact,
                    "artifact_type":     artifact_type,
                    "result_type":       result_type,
                },
                "raw_data": vuln,
            })

        # ── Misconfigurations ─────────────────────────────────────
        for mis in result.get("Misconfigurations") or []:
            _mis_id    = mis.get("ID", "")
            _mis_title = mis.get("Title", "Misconfiguration")
            _title     = f"{_mis_id}: {_mis_title}" if _mis_id else _mis_title
            findings.append({
                "title":       _title,
                "description": f"{mis.get('Description','')}\n\nResolution: {mis.get('Resolution','')}",
                "severity":    SEVERITY_MAP.get(mis.get("Severity","UNKNOWN").upper(), SeverityEnum.UNKNOWN),
                "source":      SourceEnum.TRIVY,
                "vuln_id":     mis.get("ID"),
                "file_path":   target,
                "tags":        list(filter(None, ["misconfiguration", result_type])),
                "extra_data": {
                    "primary_url":   mis.get("PrimaryURL"),
                    "references":    mis.get("References", []),
                    "status":        mis.get("Status"),
                    "cause_message": mis.get("CauseMetadata", {}).get("Message"),
                    "result_type":   result_type,
                    "artifact":      artifact,
                },
                "raw_data": mis,
            })

        # ── Secrets ───────────────────────────────────────────────
        for secret in result.get("Secrets") or []:
            findings.append({
                "title":       f"Secret detected: {secret.get('Title','Unknown')}",
                "description": secret.get("Match", ""),
                "severity":    SEVERITY_MAP.get(secret.get("Severity","HIGH").upper(), SeverityEnum.HIGH),
                "source":      SourceEnum.TRIVY,
                "vuln_id":     secret.get("RuleID"),
                "file_path":   target,
                "line_start":  secret.get("StartLine"),
                "line_end":    secret.get("EndLine"),
                "tags":        ["secret", result_type],
                "extra_data": {
                    "rule_id":  secret.get("RuleID"),
                    "category": secret.get("Category"),
                    "artifact": artifact,
                },
                "raw_data": secret,
            })

    return findings
