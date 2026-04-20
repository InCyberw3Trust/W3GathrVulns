"""
Parser for Nuclei JSONL output (nuclei -jsonl / -json).

Each finding is one JSON object with fields:
  template, template-id, template-url, template-path
  info.{name, author, tags, description, reference, severity, metadata,
        classification.{cve-id, cwe-id, cvss-metrics}, remediation}
  type            → "http" | "dns" | "ssl"
  host, port, scheme, url, matched-at
  matcher-name    → which sub-matcher fired (e.g. "cloudflare", "tls-1.0")
  extractor-name  → which extractor fired (e.g. "tls_1.1", "registrantName")
  extracted-results → list of extracted values
  request, response → full traffic (trimmed before storage)
  curl-command    → reproducible curl
  ip, timestamp
"""
import re
from typing import List, Dict, Any, Optional
from app.models import SeverityEnum, SourceEnum

SEVERITY_MAP = {
    "critical": SeverityEnum.CRITICAL,
    "high":     SeverityEnum.HIGH,
    "medium":   SeverityEnum.MEDIUM,
    "low":      SeverityEnum.LOW,
    "info":     SeverityEnum.INFO,
    "unknown":  SeverityEnum.UNKNOWN,
}


def _sev(item: dict) -> SeverityEnum:
    raw = item.get("info", {}).get("severity", "info").lower().strip()
    return SEVERITY_MAP.get(raw, SeverityEnum.UNKNOWN)


def _trim(text: Optional[str], max_len: int = 2000) -> Optional[str]:
    """Keep traffic snippets reasonably sized."""
    if not text:
        return None
    return text[:max_len] + ("…" if len(text) > max_len else "")


def _extract_cves(item: dict) -> Optional[str]:
    cve_ids = item.get("info", {}).get("classification", {}).get("cve-id") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    cve_ids = [c for c in cve_ids if c]
    return cve_ids[0] if cve_ids else None


def _extract_cwes(item: dict) -> List[str]:
    cwe_ids = item.get("info", {}).get("classification", {}).get("cwe-id") or []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    return [c for c in cwe_ids if c]


def _build_title(item: dict) -> str:
    """
    Build a descriptive title.
    For templates that fire multiple times (e.g. deprecated-tls),
    include matcher-name/extractor-name so each sub-finding is distinct.
    """
    name         = item.get("info", {}).get("name", item.get("template-id", "Unknown"))
    matcher_name = item.get("matcher-name", "")
    extractor    = item.get("extractor-name", "")

    suffix = matcher_name or extractor
    if suffix:
        return f"{name} [{suffix}]"
    return name


def _build_description(item: dict) -> str:
    parts = []
    info  = item.get("info", {})

    if info.get("description"):
        parts.append(info["description"].strip())

    if info.get("remediation"):
        parts.append(f"\n**Remediation:**\n{info['remediation'].strip()}")

    extracted = item.get("extracted-results", [])
    if extracted:
        joined = ", ".join(str(v) for v in extracted if v)
        if joined:
            parts.append(f"\n**Extracted values:** `{joined}`")

    return "\n".join(parts).strip()


def _build_references(item: dict) -> List[str]:
    refs = item.get("info", {}).get("reference", []) or []
    if isinstance(refs, str):
        refs = [refs]
    return [r for r in refs if r and r.startswith("http")]


def _build_tags(item: dict) -> List[str]:
    info_tags = item.get("info", {}).get("tags", []) or []
    if isinstance(info_tags, str):
        info_tags = [t.strip() for t in info_tags.split(",")]
    scan_type = item.get("type", "")
    tags = list(set(filter(None, info_tags + ([scan_type] if scan_type else []))))
    return tags[:20]


def parse(payload: Any) -> List[Dict[str, Any]]:
    """
    Accept multiple formats:
      - Array:           jq -s '.'               → [{...}, {...}]          ✓ correct
      - Wrapped array:   jq -s '{payload: .}'    → {"payload": [{...}]}    handled
      - Single object:   direct dict             → {...}                    handled
    """
    if not payload:
        return []

    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        # Handle {"payload": [...]} wrapping (wrong jq command but common mistake)
        if "payload" in payload and isinstance(payload["payload"], list):
            items = payload["payload"]
        # Handle single finding passed as dict
        elif "template-id" in payload or "info" in payload:
            items = [payload]
        else:
            # Unknown dict structure — try values that are lists
            for v in payload.values():
                if isinstance(v, list):
                    items = v
                    break
            else:
                items = [payload]
    else:
        return []

    findings = []

    for item in items:
        if not isinstance(item, dict):
            continue

        cve       = _extract_cves(item)
        cwes      = _extract_cwes(item)
        cvss_raw  = item.get("info", {}).get("classification", {}).get("cvss-metrics", "")
        cvss_score = None
        if cvss_raw:
            m = re.search(r"CVSS:\d+\.\d+/.*?/(\d+\.\d+)$", cvss_raw)
            if not m:
                # Try /score format: some templates put plain float
                try:
                    cvss_score = str(float(cvss_raw))
                except ValueError:
                    pass
            else:
                cvss_score = m.group(1)

        template_id  = item.get("template-id", "")
        template_url = item.get("template-url", "")
        matched_at   = item.get("matched-at", item.get("url", item.get("host", "")))
        scan_type    = item.get("type", "")          # http | dns | ssl
        matcher_name = item.get("matcher-name", "")
        extractor    = item.get("extractor-name", "")
        extracted    = item.get("extracted-results", []) or []
        ip           = item.get("ip", "")

        # Primary URL / host
        primary_url = (
            item.get("url") or
            item.get("matched-at") or
            (f"{item.get('host')}:{item.get('port')}" if item.get("port") else item.get("host", ""))
        )

        findings.append({
            "title":       _build_title(item),
            "description": _build_description(item),
            "severity":    _sev(item),
            "source":      SourceEnum.NUCLEI,
            "vuln_id":     template_id,
            "cve":         cve,
            "cvss_score":  cvss_score,
            "url":         primary_url or None,
            "tags":        _build_tags(item),
            "extra_data": {
                # Template identity
                "template_id":   template_id,
                "template_url":  template_url,
                "template_path": item.get("template-path", ""),

                # Match details
                "matcher_name":      matcher_name,
                "extractor_name":    extractor,
                "extracted_results": [str(v) for v in extracted if v],
                "matched_at":        matched_at,
                "scan_type":         scan_type,    # http / dns / ssl

                # Network context
                "host":   item.get("host", ""),
                "port":   item.get("port", ""),
                "scheme": item.get("scheme", ""),
                "ip":     ip,
                "timestamp": item.get("timestamp", ""),

                # Weakness classification
                "cve":        cve,
                "cwes":       cwes,
                "cvss_metrics": cvss_raw,

                # Template metadata
                "authors":  item.get("info", {}).get("author", []),
                "tags":     item.get("info", {}).get("tags", []),
                "references": _build_references(item),
                "max_requests": item.get("info", {}).get("metadata", {}).get("max-request"),
                "verified":     item.get("info", {}).get("metadata", {}).get("verified", False),
                "shodan_query": item.get("info", {}).get("metadata", {}).get("shodan-query"),

                # Reproducibility
                "curl_command": _trim(item.get("curl-command"), 500),

                # Traffic (trimmed — full data in raw_data)
                "request_snippet":  _trim(item.get("request"), 800),
                "response_snippet": _trim(item.get("response"), 800),
            },
            # Store full item but strip potentially huge request/response
            "raw_data": {
                k: v for k, v in item.items()
                if k not in ("request", "response")
            },
        })

    return findings
