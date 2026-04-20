from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, func, asc, desc
from typing import Optional, List
from app.database import get_db
from app.models import Finding, Project, SeverityEnum, StatusEnum, SourceEnum
from app.schemas import FindingResponse, FindingListResponse, FindingUpdate, FindingBatchUpdate
from app.utils.git_links import build_git_file_url

router = APIRouter(prefix="/findings", tags=["findings"])

SORTABLE = {
    "first_seen":  Finding.first_seen,
    "last_seen":   Finding.last_seen,
    "severity":    Finding.severity,
    "status":      Finding.status,
    "source":      Finding.source,
    "title":       Finding.title,
    "short_id":    Finding.short_id,
}


def _build_git_url(finding: Finding) -> Optional[str]:
    """Build git file URL using project settings and scan branch/commit."""
    p = finding.project
    s = finding.scan
    if not p or not p.repository_url or not finding.file_path:
        return None
    # Sources that have meaningful file paths
    if finding.source.value not in ("gitlab_sast", "gitlab_iac", "gitlab_secrets", "trivy"):
        return None
    branch = (s.branch if s else None) or p.default_branch or "main"
    commit = s.commit_sha if s else None
    return build_git_file_url(
        repo_url=p.repository_url,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        branch=branch,
        commit_sha=commit,
        provider=p.git_provider,
    )


def _to_response(finding: Finding) -> FindingResponse:
    d = FindingResponse.model_validate(finding)
    if finding.project:
        d.project_name = finding.project.name
    d.git_file_url = _build_git_url(finding)
    return d


@router.get("", response_model=FindingListResponse)
def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    # Text search
    search: Optional[str] = Query(None),
    # Simple multi-value filters (legacy, still supported)
    project_id: Optional[str] = Query(None),
    severity: Optional[List[SeverityEnum]] = Query(None),
    status: Optional[List[StatusEnum]] = Query(None),
    source: Optional[List[SourceEnum]] = Query(None),
    # Advanced filter builder: JSON array of conditions
    # e.g. [{"field":"title","op":"contains","value":"CVE"},{"field":"source","op":"equals","value":"trivy"}]
    filters: Optional[str] = Query(None, description='JSON filter array'),
    # Sorting
    sort_by: str = Query("first_seen"),
    sort_dir: str = Query("desc"),
    db: Session = Depends(get_db),
):
    import json

    q = (
        db.query(Finding)
        .options(joinedload(Finding.project), joinedload(Finding.scan))
        .join(Project, Finding.project_id == Project.id)
    )

    if search:
        q = q.filter(or_(
            Finding.title.ilike(f"%{search}%"),
            Finding.description.ilike(f"%{search}%"),
            Finding.cve.ilike(f"%{search}%"),
            Finding.vuln_id.ilike(f"%{search}%"),
            Finding.component.ilike(f"%{search}%"),
            Finding.file_path.ilike(f"%{search}%"),
        ))

    if project_id:  q = q.filter(Finding.project_id == project_id)
    if severity:    q = q.filter(Finding.severity.in_(severity))
    if status:      q = q.filter(Finding.status.in_(status))
    if source:      q = q.filter(Finding.source.in_(source))

    # Advanced filter builder
    if filters:
        try:
            from sqlalchemy import cast, Text as SAText, and_ as sa_and, or_ as sa_or
            parsed = json.loads(filters)

            # Enum columns must be cast to text before ILIKE/lower operations
            ENUM_COLS = {"source", "severity", "status"}
            TEXT_COLS = {
                "title":       Finding.title,
                "file_path":   Finding.file_path,
                "component":   Finding.component,
                "vuln_id":     Finding.vuln_id,
                "cve":         Finding.cve,
                "description": Finding.description,
                "project":     Project.name,
            }
            ENUM_RAW = {
                "source":   Finding.source,
                "severity": Finding.severity,
                "status":   Finding.status,
            }

            def build_condition(flt):
                """Convert a single filter dict to a SQLAlchemy expression (or None)."""
                field = flt.get("field")
                op    = flt.get("op")
                val   = flt.get("value", "")

                if field in ENUM_COLS:
                    raw_col  = ENUM_RAW[field]
                    text_col = cast(raw_col, SAText)
                    if op == "equals":       return raw_col == val.upper()
                    if op == "not_equals":   return raw_col != val.upper()
                    if op == "in":
                        return raw_col.in_([v.strip().upper() for v in val.split(",")])
                    if op == "not_in":
                        return ~raw_col.in_([v.strip().upper() for v in val.split(",")])
                    if op == "contains":     return text_col.ilike(f"%{val}%")
                    if op == "not_contains": return ~text_col.ilike(f"%{val}%")
                    if op == "starts_with":  return text_col.ilike(f"{val}%")
                    if op == "ends_with":    return text_col.ilike(f"%{val}")
                elif field in TEXT_COLS:
                    col = TEXT_COLS[field]
                    if op == "equals":       return func.lower(col) == val.lower()
                    if op == "not_equals":   return func.lower(col) != val.lower()
                    if op == "contains":     return col.ilike(f"%{val}%")
                    if op == "not_contains": return ~col.ilike(f"%{val}%")
                    if op == "starts_with":  return col.ilike(f"{val}%")
                    if op == "ends_with":    return col.ilike(f"%{val}")
                    if op == "in":
                        return col.in_([v.strip() for v in val.split(",")])
                    if op == "not_in":
                        return ~col.in_([v.strip() for v in val.split(",")])
                return None

            # Support two formats:
            #   - Grouped: {"groups": [{"conditions": [...], "mode": "or"}, ...]}
            #     Groups are ANDed; conditions within a group use the group's mode (default OR).
            #   - Flat (legacy): [...conditions...]
            #     All conditions are ANDed (same as before).
            if isinstance(parsed, dict) and "groups" in parsed:
                group_clauses = []
                for group in parsed["groups"]:
                    conditions = group.get("conditions", [])
                    mode = group.get("mode", "or")  # default: OR within a group
                    cond_exprs = [c for c in (build_condition(f) for f in conditions) if c is not None]
                    if cond_exprs:
                        if mode == "or":
                            group_clauses.append(sa_or(*cond_exprs))
                        else:
                            group_clauses.append(sa_and(*cond_exprs))
                if group_clauses:
                    q = q.filter(sa_and(*group_clauses))
            else:
                # Flat list — all ANDed (backward-compatible)
                for flt in parsed:
                    expr = build_condition(flt)
                    if expr is not None:
                        q = q.filter(expr)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Filter parse error: {e}")

    # Sorting
    sort_col = SORTABLE.get(sort_by, Finding.first_seen)
    q = q.order_by(desc(sort_col) if sort_dir == "desc" else asc(sort_col))

    total = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()

    return FindingListResponse(
        items=[_to_response(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )


@router.get("/{finding_ref}", response_model=FindingResponse)
def get_finding(finding_ref: str, db: Session = Depends(get_db)):
    """Accept either short_id (integer) or UUID."""
    q = db.query(Finding).options(joinedload(Finding.project), joinedload(Finding.scan))
    if finding_ref.isdigit():
        f = q.filter(Finding.short_id == int(finding_ref)).first()
    else:
        f = q.filter(Finding.id == finding_ref).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_response(f)


@router.patch("/batch", response_model=dict)
def batch_update_findings(update: FindingBatchUpdate, db: Session = Depends(get_db)):
    """Update status/severity for multiple findings at once."""
    if not update.ids:
        raise HTTPException(status_code=400, detail="No IDs provided")
    findings = db.query(Finding).filter(Finding.id.in_(update.ids)).all()
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found")
    updated = 0
    for f in findings:
        changed = False
        if update.status is not None and f.status != update.status:
            f.status = update.status
            changed = True
        if update.severity is not None and f.severity != update.severity:
            f.severity = update.severity
            changed = True
        if changed:
            updated += 1
    db.commit()
    return {"updated": updated, "total": len(findings)}


@router.patch("/{finding_ref}", response_model=FindingResponse)
def update_finding(finding_ref: str, update: FindingUpdate, db: Session = Depends(get_db)):
    q = db.query(Finding).options(joinedload(Finding.project), joinedload(Finding.scan))
    f = q.filter(Finding.short_id == int(finding_ref)).first() if finding_ref.isdigit() else q.filter(Finding.id == finding_ref).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    for field, value in update.model_dump(exclude_none=True).items():
        setattr(f, field, value)
    db.commit()
    db.refresh(f)
    return _to_response(f)


@router.delete("/{finding_ref}", status_code=204)
def delete_finding(finding_ref: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.short_id == int(finding_ref)).first() if finding_ref.isdigit() else db.query(Finding).filter(Finding.id == finding_ref).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(f)
    db.commit()
