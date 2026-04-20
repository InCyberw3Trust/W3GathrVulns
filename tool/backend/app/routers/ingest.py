"""Webhook endpoints to receive scan results from CI/CD pipelines"""
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from sqlalchemy import and_
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from app.database import get_db
from app.models import Project, Scan, Finding, SourceEnum, StatusEnum
from app.schemas import IngestResponse
from app.parsers import trivy, gitlab_sast, owasp_zap, nuclei
from app.utils.rules_engine import apply_rules_to_finding
import uuid
import logging

router = APIRouter(prefix="/ingest", tags=["ingest"])
logger = logging.getLogger(__name__)


def get_or_create_project(db: Session, project_name: str, repo_url: str = None) -> Project:
    project = db.query(Project).filter(Project.name == project_name).first()
    if not project:
        project = Project(id=str(uuid.uuid4()), name=project_name, repository_url=repo_url)
        db.add(project)
        db.flush()
    return project


def ingest_findings(
    db: Session,
    project_name: str,
    source: SourceEnum,
    parsed_findings: list,
    branch: str = None,
    commit_sha: str = None,
    pipeline_id: str = None,
    repo_url: str = None,
    raw_payload: dict = None,
    scan_date: Optional[datetime] = None,
) -> IngestResponse:
    project = get_or_create_project(db, project_name, repo_url)

    scan = Scan(
        id=str(uuid.uuid4()),
        project_id=project.id,
        source=source,
        branch=branch,
        commit_sha=commit_sha,
        pipeline_id=pipeline_id,
        findings_count=len(parsed_findings),
        raw_payload=raw_payload,
        **({"scan_date": scan_date} if scan_date else {}),
    )
    db.add(scan)
    db.flush()

    created = 0
    updated = 0

    for f in parsed_findings:
        title     = f.get("title", "")
        file_path = f.get("file_path")
        line      = f.get("line_start")

        # ── Deduplication strategy ────────────────────────────────────────────
        # For IaC (KICS): same rule fires at N different lines in the same file.
        # Each line is a distinct instance → always include line_start in the key.
        #
        # For other sources (Trivy, SAST, Secrets): line may not always be
        # present or meaningful as a dedup key, but we still use it when set.
        # This avoids collapsing e.g. "Security Opt Not Set" at line 3, 32, 53…
        # into a single finding.
        #
        # Dedup key: project + title + source + file_path [+ line_start]
        # ─────────────────────────────────────────────────────────────────────
        q = db.query(Finding).filter(
            and_(
                Finding.project_id == project.id,
                Finding.title      == title,
                Finding.source     == source,
                Finding.status     != StatusEnum.FALSE_POSITIVE,
            )
        )
        if file_path is not None:
            q = q.filter(Finding.file_path == file_path)

        if line is not None:
            # Line is available → include it in the key (critical for IaC)
            q = q.filter(Finding.line_start == line)

        existing = q.first()

        if existing:
            existing.last_seen = scan.scan_date
            existing.scan_id   = scan.id
            if f.get("cvss_score")    and not existing.cvss_score:
                existing.cvss_score    = f["cvss_score"]
            if f.get("fixed_version") and not existing.fixed_version:
                existing.fixed_version = f["fixed_version"]
            if f.get("cve")           and not existing.cve:
                existing.cve           = f["cve"]
            # Merge tags without duplicates
            existing_tags = set(existing.tags or [])
            existing.tags = list(existing_tags | set(f.get("tags") or []))
            # Always refresh extra_data with latest scan data
            existing.extra_data = f.get("extra_data")
            updated += 1
        else:
            valid_cols = set(Finding.__table__.columns.keys())
            finding = Finding(
                id=str(uuid.uuid4()),
                project_id=project.id,
                scan_id=scan.id,
                **{k: v for k, v in f.items() if k in valid_cols},
            )
            if scan_date:
                finding.first_seen = scan_date
                finding.last_seen  = scan_date
            db.add(finding)
            created += 1

    # Flush to get short_ids assigned, then apply rules
    db.flush()
    rules_applied = 0
    all_findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    for finding in all_findings:
        rules_applied += apply_rules_to_finding(db, finding)

    db.commit()
    logger.info(f"[{project_name}] {source.value}: {created} created, {updated} updated, {rules_applied} rules applied")
    return IngestResponse(
        scan_id=scan.id,
        project_id=project.id,
        findings_created=created,
        findings_updated=updated,
        rules_applied=rules_applied,
        message=f"Scan ingested: {created} new findings, {updated} updated, {rules_applied} rules applied",
    )


# ── Ingest endpoints ──────────────────────────────────────────────────────────

def _parse_scan_date(scan_date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO date string to timezone-aware datetime, or return None."""
    if not scan_date_str:
        return None
    try:
        dt = datetime.fromisoformat(scan_date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


@router.post("/trivy", response_model=IngestResponse)
async def ingest_trivy(
    payload: Dict[str, Any],
    project: str = Query(...), branch: Optional[str] = Query(None),
    commit: Optional[str] = Query(None), pipeline: Optional[str] = Query(None),
    repo_url: Optional[str] = Query(None), scan_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        parsed = trivy.parse(payload)
        return ingest_findings(db, project, SourceEnum.TRIVY, parsed, branch, commit, pipeline, repo_url, payload, _parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("Trivy ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")


@router.post("/gitlab-sast", response_model=IngestResponse)
async def ingest_gitlab_sast(
    payload: Dict[str, Any],
    project: str = Query(...), branch: Optional[str] = Query(None),
    commit: Optional[str] = Query(None), pipeline: Optional[str] = Query(None),
    repo_url: Optional[str] = Query(None), scan_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        parsed = gitlab_sast.parse(payload, "sast")
        return ingest_findings(db, project, SourceEnum.GITLAB_SAST, parsed, branch, commit, pipeline, repo_url, payload, _parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("GitLab SAST ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")


@router.post("/gitlab-iac", response_model=IngestResponse)
async def ingest_gitlab_iac(
    payload: Dict[str, Any],
    project: str = Query(...), branch: Optional[str] = Query(None),
    commit: Optional[str] = Query(None), pipeline: Optional[str] = Query(None),
    scan_date: Optional[str] = Query(None), db: Session = Depends(get_db),
):
    try:
        parsed = gitlab_sast.parse(payload, "iac")
        return ingest_findings(db, project, SourceEnum.GITLAB_IAC, parsed, branch, commit, pipeline, scan_date=_parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("GitLab IaC ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")


@router.post("/gitlab-secrets", response_model=IngestResponse)
async def ingest_gitlab_secrets(
    payload: Dict[str, Any],
    project: str = Query(...), branch: Optional[str] = Query(None),
    commit: Optional[str] = Query(None), pipeline: Optional[str] = Query(None),
    scan_date: Optional[str] = Query(None), db: Session = Depends(get_db),
):
    try:
        parsed = gitlab_sast.parse(payload, "secrets")
        return ingest_findings(db, project, SourceEnum.GITLAB_SECRETS, parsed, branch, commit, pipeline, scan_date=_parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("GitLab Secrets ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")


@router.post("/owasp-zap", response_model=IngestResponse)
async def ingest_owasp_zap(
    payload: Dict[str, Any],
    project: str = Query(...), branch: Optional[str] = Query(None),
    pipeline: Optional[str] = Query(None), scan_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        parsed = owasp_zap.parse(payload)
        return ingest_findings(db, project, SourceEnum.OWASP_ZAP, parsed, branch, None, pipeline, scan_date=_parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("OWASP ZAP ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")


@router.post("/nuclei", response_model=IngestResponse)
async def ingest_nuclei(
    payload: Any = Body(...),
    project: str = Query(...), branch: Optional[str] = Query(None),
    pipeline: Optional[str] = Query(None), scan_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    try:
        parsed = nuclei.parse(payload)
        raw = payload if isinstance(payload, dict) else {"results": payload}
        return ingest_findings(db, project, SourceEnum.NUCLEI, parsed, branch, None, pipeline, raw_payload=raw, scan_date=_parse_scan_date(scan_date))
    except Exception as e:
        logger.exception("Nuclei ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")




@router.delete("/reset", tags=["admin"])
def reset_all_data(
    confirm: str = Query(..., description="Must be 'YES_DELETE_EVERYTHING'"),
    db: Session = Depends(get_db),
):
    """⚠️  Wipe all findings, scans and projects. Irreversible."""
    if confirm != "YES_DELETE_EVERYTHING":
        raise HTTPException(status_code=400, detail="Pass ?confirm=YES_DELETE_EVERYTHING to confirm")
    from app.models import Finding, Scan, Project
    deleted_findings = db.query(Finding).delete()
    deleted_scans    = db.query(Scan).delete()
    deleted_projects = db.query(Project).delete()
    db.commit()
    return {"message": "All data wiped", "deleted": {"findings": deleted_findings, "scans": deleted_scans, "projects": deleted_projects}}
