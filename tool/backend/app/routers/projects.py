from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
import uuid
from app.database import get_db
from app.models import Project, Finding, Scan, StatusEnum, SeverityEnum
from app.schemas import ProjectCreate, ProjectUpdate, ProjectResponse, ScanResponse

router = APIRouter(prefix="/projects", tags=["projects"])


# ── Static routes FIRST (before /{project_id}) ───────────────────────────────

@router.get("/export")
def export_projects(db: Session = Depends(get_db)):
    """Export all projects as JSON."""
    projects = db.query(Project).all()
    return [
        {
            "name": p.name,
            "description": p.description,
            "repository_url": p.repository_url,
            "git_provider": p.git_provider.value if p.git_provider else None,
            "default_branch": p.default_branch,
        }
        for p in projects
    ]


@router.post("/import")
def import_projects(data: List[dict], db: Session = Depends(get_db)):
    """Import projects from JSON. Skips existing names."""
    created = 0
    skipped = 0
    for item in data:
        if not item.get("name"):
            skipped += 1
            continue
        if db.query(Project).filter(Project.name == item["name"]).first():
            skipped += 1
            continue
        p = Project(id=str(uuid.uuid4()), **{
            k: v for k, v in item.items()
            if k in ("name", "description", "repository_url", "git_provider", "default_branch") and v is not None
        })
        db.add(p)
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


# ── Collection routes ─────────────────────────────────────────────────────────

@router.get("", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).all()
    result = []
    for p in projects:
        total  = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id).scalar()
        open_c = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.status == StatusEnum.OPEN).scalar()
        crit   = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.severity == SeverityEnum.CRITICAL, Finding.status == StatusEnum.OPEN).scalar()
        r = ProjectResponse.model_validate(p)
        r.findings_count = total
        r.open_findings  = open_c
        r.critical_count = crit
        result.append(r)
    return result


@router.post("", response_model=ProjectResponse, status_code=201)
def create_project(data: ProjectCreate, db: Session = Depends(get_db)):
    existing = db.query(Project).filter(Project.name == data.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Project already exists")
    p = Project(id=str(uuid.uuid4()), **data.model_dump())
    db.add(p)
    db.commit()
    db.refresh(p)
    r = ProjectResponse.model_validate(p)
    r.findings_count = 0
    r.open_findings  = 0
    r.critical_count = 0
    return r


# ── Item routes ───────────────────────────────────────────────────────────────

@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    total  = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id).scalar()
    open_c = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.status == StatusEnum.OPEN).scalar()
    crit   = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.severity == SeverityEnum.CRITICAL, Finding.status == StatusEnum.OPEN).scalar()
    r = ProjectResponse.model_validate(p)
    r.findings_count = total
    r.open_findings  = open_c
    r.critical_count = crit
    return r


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, update: ProjectUpdate, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    for k, v in update.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    db.commit()
    db.refresh(p)
    r = ProjectResponse.model_validate(p)
    r.findings_count = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id).scalar()
    r.open_findings  = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.status == StatusEnum.OPEN).scalar()
    r.critical_count = db.query(func.count(Finding.id)).filter(Finding.project_id == p.id, Finding.severity == SeverityEnum.CRITICAL, Finding.status == StatusEnum.OPEN).scalar()
    return r


@router.get("/{project_id}/scans", response_model=List[ScanResponse])
def get_project_scans(project_id: str, db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.scan_date.desc()).all()
    result = []
    for s in scans:
        r = ScanResponse.model_validate(s)
        r.project_name = s.project.name if s.project else None
        result.append(r)
    return result


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(p)
    db.commit()
