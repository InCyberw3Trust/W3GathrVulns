"""
Parser for OWASP ZAP JSON report.

Supports both formats:
  - Standard ZAP JSON (zap-baseline, zap-full)
    { "site": [ { "alerts": [...] } ] }
  - ZAP 2.17+ JSON with insights block
    { "@programName": "ZAP", "insights": [...], "site": [...] }

Handles riskdesc in ANY format:
  "Medium (High)"  →  MEDIUM
  "Medium"         →  MEDIUM
  "Informational"  →  INFO
  "2"              →  (riskcode numeric fallback)
"""
import re
import html
from typing import List, Dict, Any
from app.models import SeverityEnum, SourceEnum


# ── Severity mapping ───────────────────────────────────────────────────────────

RISKCODE_MAP = {
    "3": SeverityEnum.HIGH,
    "2": SeverityEnum.MEDIUM,
    "1": SeverityEnum.LOW,
    "0": SeverityEnum.INFO,
}

RISKDESC_MAP = {
    "critical":      SeverityEnum.CRITICAL,
    "high":          SeverityEnum.HIGH,
    "medium":        SeverityEnum.MEDIUM,
    "low":           SeverityEnum.LOW,
    "informational": SeverityEnum.INFO,
    "info":          SeverityEnum.INFO,
    "false positive": SeverityEnum.INFO,
}


def _parse_severity(alert: dict) -> SeverityEnum:
    """
    Try every available severity signal, most precise first.

    riskdesc examples seen in the wild:
      "Medium (High)"        → MEDIUM (first word wins)
      "Medium"               → MEDIUM
      "Informational (Low)"  → INFO
      "Low (Medium)"         → LOW
      "High"                 → HIGH
    """
    # 1. riskdesc — first word before space or parenthesis
    riskdesc = alert.get("riskdesc", "")
    if riskdesc:
        first_word = re.split(r"[\s(]", riskdesc.strip())[0].lower()
        if first_word in RISKDESC_MAP:
            return RISKDESC_MAP[first_word]

    # 2. riskcode numeric
    riskcode = str(alert.get("riskcode", ""))
    if riskcode in RISKCODE_MAP:
        return RISKCODE_MAP[riskcode]

    # 3. risk field (some export formats)
    risk = alert.get("risk", "").lower()
    if risk in RISKDESC_MAP:
        return RISKDESC_MAP[risk]

    return SeverityEnum.UNKNOWN


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "\n", text)
    text = html.unescape(text)
    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def _parse_references(ref_html: str) -> List[str]:
    """Extract URLs from a reference HTML block like <p>https://...</p>."""
    if not ref_html:
        return []
    return re.findall(r'https?://[^\s<>"\']+', ref_html)


def _parse_confidence(alert: dict) -> str:
    """Map confidence code to label."""
    conf_map = {"3": "High", "2": "Medium", "1": "Low", "0": "False Positive"}
    code = str(alert.get("confidence", ""))
    return conf_map.get(code, code or "Unknown")


def parse(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    # ── Extract scan-level metadata ────────────────────────────────────────────
    scan_meta = {
        "zap_version":  payload.get("@version"),
        "generated_at": payload.get("@generated") or payload.get("created"),
        "program":      payload.get("@programName", "ZAP"),
        "insights":     payload.get("insights", []),   # statistics block
    }

    # ── Support both list and dict for "site" ──────────────────────────────────
    sites = payload.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_name  = site.get("@name", site.get("name", ""))
        site_host  = site.get("@host", site.get("host", ""))
        site_port  = site.get("@port", site.get("port", ""))
        site_ssl   = site.get("@ssl", site.get("ssl", "false")).lower() == "true"

        alerts = site.get("alerts", [])
        for alert in alerts:
            severity   = _parse_severity(alert)
            confidence = _parse_confidence(alert)
            references = _parse_references(alert.get("reference", ""))
            instances  = alert.get("instances", [])

            # Build description: desc + solution + otherinfo
            desc_parts = []
            if alert.get("desc"):
                desc_parts.append(_strip_html(alert["desc"]))
            if alert.get("solution"):
                desc_parts.append(f"\n**Solution:**\n{_strip_html(alert['solution'])}")
            if alert.get("otherinfo"):
                cleaned = _strip_html(alert["otherinfo"])
                if cleaned:
                    desc_parts.append(f"\n**Additional info:**\n{cleaned}")
            description = "\n".join(desc_parts).strip()

            # CWE / WASC identifiers
            cwe_id  = f"CWE-{alert['cweid']}"  if alert.get("cweid")  and str(alert["cweid"])  != "-1" else None
            wasc_id = f"WASC-{alert['wascid']}" if alert.get("wascid") and str(alert["wascid"]) != "-1" else None

            # Tags
            tags = ["dast", "web"]
            if alert.get("systemic"):
                tags.append("systemic")
            if cwe_id:
                tags.append(cwe_id)

            # Structured extra data for the detail view
            extra_data = {
                # ZAP identifiers
                "plugin_id":     alert.get("pluginid"),
                "alert_ref":     alert.get("alertRef"),
                # Risk / confidence
                "riskdesc":      alert.get("riskdesc", ""),
                "confidence":    confidence,
                "confidence_raw": alert.get("confidence"),
                # Weakness classification
                "cwe_id":        cwe_id,
                "cwe_url":       f"https://cwe.mitre.org/data/definitions/{alert['cweid']}.html" if cwe_id else None,
                "wasc_id":       wasc_id,
                "wasc_url":      f"https://www.webappsec.org/projects/threat/{alert['wascid']}" if wasc_id else None,
                # Impact data
                "instance_count": int(alert.get("count", len(instances))),
                "systemic":       bool(alert.get("systemic", False)),
                "solution":       _strip_html(alert.get("solution", "")),
                "references":     references,
                # Site context
                "site":      site_name,
                "host":      site_host,
                "port":      site_port,
                "ssl":       site_ssl,
                # All instances (for full detail)
                "instances": [
                    {
                        "id":        inst.get("id"),
                        "uri":       inst.get("uri", ""),
                        "method":    inst.get("method", "GET"),
                        "param":     inst.get("param", ""),
                        "attack":    inst.get("attack", ""),
                        "evidence":  inst.get("evidence", ""),
                        "otherinfo": inst.get("otherinfo", ""),
                    }
                    for inst in instances
                ],
                # Scan-level
                **scan_meta,
            }

            # One finding per alert (not per instance) — instances are stored in extra_data
            # Primary URL = first instance URI, or site name
            primary_url = (instances[0].get("uri") if instances else site_name) or site_name
            primary_method = instances[0].get("method", "GET") if instances else "GET"
            primary_param  = instances[0].get("param", "") if instances else ""
            primary_evidence = instances[0].get("evidence", "") if instances else ""

            findings.append({
                "title":       alert.get("name", alert.get("alert", "Unknown alert")),
                "description": description,
                "severity":    severity,
                "source":      SourceEnum.OWASP_ZAP,
                "vuln_id":     alert.get("pluginid") or alert.get("alertRef"),
                "cve":         None,   # ZAP doesn't produce CVEs directly
                "cvss_score":  None,
                "url":         primary_url,
                "method":      primary_method,
                "parameter":   primary_param if primary_param else None,
                "tags":        tags,
                "extra_data":  extra_data,
                "raw_data":    alert,
            })

    return findings
