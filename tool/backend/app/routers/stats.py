from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date, case
from typing import Optional, List
from datetime import datetime, timedelta, timezone
from app.database import get_db
from app.models import Finding, Project, Scan, SeverityEnum, StatusEnum, SourceEnum
from app.schemas import DashboardStats

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard_stats(
    project_id: Optional[List[str]]     = Query(None),
    severity:   Optional[List[SeverityEnum]] = Query(None),
    status:     Optional[List[StatusEnum]]   = Query(None),
    source:     Optional[List[SourceEnum]]   = Query(None),
    db: Session = Depends(get_db),
):
    # ── Base filtered query ───────────────────────────────────────────────────
    def base():
        q = db.query(Finding)
        if project_id: q = q.filter(Finding.project_id.in_(project_id))
        if severity:   q = q.filter(Finding.severity.in_(severity))
        if status:     q = q.filter(Finding.status.in_(status))
        if source:     q = q.filter(Finding.source.in_(source))
        return q

    # ── KPI counts ────────────────────────────────────────────────────────────
    total     = base().with_entities(func.count(Finding.id)).scalar() or 0
    open_f    = base().filter(Finding.status == StatusEnum.OPEN).with_entities(func.count(Finding.id)).scalar() or 0
    closed_c  = base().filter(Finding.status == StatusEnum.CLOSED).with_entities(func.count(Finding.id)).scalar() or 0
    in_prog   = base().filter(Finding.status == StatusEnum.IN_PROGRESS).with_entities(func.count(Finding.id)).scalar() or 0
    acc_risk  = base().filter(Finding.status == StatusEnum.ACCEPTED_RISK).with_entities(func.count(Finding.id)).scalar() or 0
    fp        = base().filter(Finding.status == StatusEnum.FALSE_POSITIVE).with_entities(func.count(Finding.id)).scalar() or 0

    # Open by severity
    def open_sev(sev):
        return base().filter(
            Finding.severity == sev,
            Finding.status == StatusEnum.OPEN
        ).with_entities(func.count(Finding.id)).scalar() or 0

    # New this week
    week_ago     = datetime.now(timezone.utc) - timedelta(days=7)
    new_this_week = base().filter(Finding.first_seen >= week_ago).with_entities(func.count(Finding.id)).scalar() or 0

    # Infra counts (unfiltered)
    total_projects = db.query(func.count(Project.id)).scalar() or 0
    total_scans    = db.query(func.count(Scan.id)).scalar() or 0

    # ── By severity ───────────────────────────────────────────────────────────
    by_sev = []
    for sev in SeverityEnum:
        c = base().filter(Finding.severity == sev).with_entities(func.count(Finding.id)).scalar() or 0
        if c:
            by_sev.append({"severity": sev.value, "count": c})

    # ── By source ─────────────────────────────────────────────────────────────
    by_src = []
    for src in SourceEnum:
        c = base().filter(Finding.source == src).with_entities(func.count(Finding.id)).scalar() or 0
        if c:
            by_src.append({"source": src.value, "count": c})

    # ── By status ─────────────────────────────────────────────────────────────
    by_status_list = []
    for st in StatusEnum:
        c = base().filter(Finding.status == st).with_entities(func.count(Finding.id)).scalar() or 0
        if c:
            by_status_list.append({"status": st.value, "count": c})

    # ── 30-day trend ──────────────────────────────────────────────────────────
    trend_q = (
        base()
        .with_entities(cast(Finding.first_seen, Date).label("date"), func.count(Finding.id).label("count"))
        .group_by(cast(Finding.first_seen, Date))
        .order_by(cast(Finding.first_seen, Date).desc())
        .limit(30)
    )
    trend = [{"date": str(r.date), "count": r.count} for r in reversed(trend_q.all())]

    # ── Top projects by open findings ─────────────────────────────────────────
    top_q = (
        db.query(Project.id, Project.name, func.count(Finding.id).label("count"))
        .join(Finding, Finding.project_id == Project.id)
    )
    if severity:   top_q = top_q.filter(Finding.severity.in_(severity))
    if source:     top_q = top_q.filter(Finding.source.in_(source))
    if project_id: top_q = top_q.filter(Project.id.in_(project_id))
    top_q = (
        top_q.filter(Finding.status == StatusEnum.OPEN)
        .group_by(Project.id, Project.name)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
    )
    top_projects = [{"id": r.id, "name": r.name, "open_findings": r.count} for r in top_q.all()]

    # ── Severity by project (stacked bar — open findings) ────────────────────
    sev_proj_q = (
        db.query(
            Project.name,
            func.sum(case((Finding.severity == SeverityEnum.CRITICAL, 1), else_=0)).label("CRITICAL"),
            func.sum(case((Finding.severity == SeverityEnum.HIGH,     1), else_=0)).label("HIGH"),
            func.sum(case((Finding.severity == SeverityEnum.MEDIUM,   1), else_=0)).label("MEDIUM"),
            func.sum(case((Finding.severity == SeverityEnum.LOW,      1), else_=0)).label("LOW"),
        )
        .join(Finding, Finding.project_id == Project.id)
        .filter(Finding.status == StatusEnum.OPEN)
    )
    if project_id: sev_proj_q = sev_proj_q.filter(Project.id.in_(project_id))
    if severity:   sev_proj_q = sev_proj_q.filter(Finding.severity.in_(severity))
    if source:     sev_proj_q = sev_proj_q.filter(Finding.source.in_(source))
    sev_proj_q = (
        sev_proj_q
        .group_by(Project.name)
        .order_by(func.sum(case((Finding.severity == SeverityEnum.CRITICAL, 1), else_=0)).desc())
        .limit(8)
    )
    by_severity_project = [
        {"project": r.name, "CRITICAL": r.CRITICAL, "HIGH": r.HIGH, "MEDIUM": r.MEDIUM, "LOW": r.LOW}
        for r in sev_proj_q.all()
    ]

    return DashboardStats(
        total_findings=total,
        open_findings=open_f,
        closed_count=closed_c,
        in_progress_count=in_prog,
        accepted_risk_count=acc_risk,
        critical_count=open_sev(SeverityEnum.CRITICAL),
        high_count=open_sev(SeverityEnum.HIGH),
        medium_count=open_sev(SeverityEnum.MEDIUM),
        low_count=open_sev(SeverityEnum.LOW),
        false_positives=fp,
        new_this_week=new_this_week,
        total_projects=total_projects,
        total_scans=total_scans,
        by_severity=by_sev,
        by_source=by_src,
        by_status=by_status_list,
        recent_trend=trend,
        top_projects=top_projects,
        by_severity_project=by_severity_project,
    )
