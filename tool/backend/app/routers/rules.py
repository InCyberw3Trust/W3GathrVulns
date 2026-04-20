from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from typing import List
import uuid
from app.database import get_db
from app.models import Rule, Finding
from app.schemas import RuleCreate, RuleUpdate, RuleResponse, RuleTestResult, FindingResponse
from app.utils.rules_engine import matches_rule, apply_rules_to_all, apply_actions
from app.utils import scheduler

router = APIRouter(prefix="/rules", tags=["rules"])


# ── Static routes FIRST (before /{rule_id}) ───────────────────────────────────

@router.get("/export")
def export_rules(db: Session = Depends(get_db)):
    """Export all rules as portable JSON."""
    rules = db.query(Rule).order_by(Rule.priority.asc()).all()
    return [
        {
            "name":            r.name,
            "description":     r.description,
            "enabled":         r.enabled,
            "priority":        r.priority,
            "conditions":      r.conditions,
            "conditions_mode": r.conditions_mode,
            "actions":         r.actions,
            "cron_schedule":   r.cron_schedule,
        }
        for r in rules
    ]


@router.post("/import")
def import_rules(data: List[dict], db: Session = Depends(get_db)):
    """Import rules from JSON. Skips exact name duplicates."""
    created = 0
    skipped = 0
    for item in data:
        if not item.get("name"):
            skipped += 1
            continue
        if db.query(Rule).filter(Rule.name == item["name"]).first():
            skipped += 1
            continue
        rule = Rule(
            id=str(uuid.uuid4()),
            name=item.get("name", "Imported rule"),
            description=item.get("description"),
            enabled=item.get("enabled", True),
            priority=item.get("priority", 100),
            conditions=item.get("conditions", []),
            conditions_mode=item.get("conditions_mode", "all"),
            actions=item.get("actions", []),
            cron_schedule=item.get("cron_schedule"),
        )
        db.add(rule)
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


@router.post("/apply-all", response_model=dict)
def apply_all_rules(db: Session = Depends(get_db)):
    """Re-apply all enabled rules to all findings."""
    return apply_rules_to_all(db)


@router.post("/run-scheduled", tags=["admin"])
def run_scheduled(db: Session = Depends(get_db)):
    """
    Trigger for cron-scheduled rule application.
    Example cron: 0 * * * * curl -X POST http://backend:8000/api/v1/rules/run-scheduled
    """
    return apply_rules_to_all(db)


# ── Collection routes ─────────────────────────────────────────────────────────

@router.get("", response_model=List[RuleResponse])
def list_rules(db: Session = Depends(get_db)):
    return db.query(Rule).order_by(Rule.priority.asc(), Rule.created_at.desc()).all()


@router.post("", response_model=RuleResponse, status_code=201)
def create_rule(data: RuleCreate, db: Session = Depends(get_db)):
    rule = Rule(
        id=str(uuid.uuid4()),
        name=data.name,
        description=data.description,
        enabled=data.enabled,
        priority=data.priority,
        conditions=[c.model_dump() for c in data.conditions],
        conditions_mode=data.conditions_mode,
        actions=[a.model_dump() for a in data.actions],
        cron_schedule=data.cron_schedule,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    scheduler.sync_rule(rule.id, rule.cron_schedule, rule.enabled)
    return rule


# ── Item routes ───────────────────────────────────────────────────────────────

@router.get("/{rule_id}", response_model=RuleResponse)
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    r = db.query(Rule).filter(Rule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    return r


@router.patch("/{rule_id}", response_model=RuleResponse)
def update_rule(rule_id: str, update: RuleUpdate, db: Session = Depends(get_db)):
    r = db.query(Rule).filter(Rule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    data = update.model_dump(exclude_none=True)
    if "conditions" in data:
        data["conditions"] = [c.model_dump() if hasattr(c, 'model_dump') else c for c in (update.conditions or [])]
    if "actions" in data:
        data["actions"] = [a.model_dump() if hasattr(a, 'model_dump') else a for a in (update.actions or [])]
    for k, v in data.items():
        setattr(r, k, v)
    db.commit()
    db.refresh(r)
    scheduler.sync_rule(r.id, r.cron_schedule, r.enabled)
    return r


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    r = db.query(Rule).filter(Rule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    scheduler.remove_rule(rule_id)
    db.delete(r)
    db.commit()


@router.post("/{rule_id}/simulate", response_model=RuleTestResult)
def simulate_rule(rule_id: str, limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    """
    Preview which findings this rule would affect — READ ONLY, no changes applied.
    Returns matched findings with what their new status/severity WOULD become.
    """
    r = db.query(Rule).filter(Rule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    findings = db.query(Finding).options(joinedload(Finding.project), joinedload(Finding.scan)).all()
    matched = [f for f in findings if matches_rule(f, r)]
    result_items = []
    for f in matched[:limit]:
        fr = FindingResponse.model_validate(f)
        if f.project:
            fr.project_name = f.project.name
        # Annotate what would change (without saving)
        fr.notes = _simulate_actions(f, r)
        result_items.append(fr)
    return RuleTestResult(matched_count=len(matched), matched_findings=result_items)


@router.post("/{rule_id}/apply", response_model=dict)
def apply_single_rule(rule_id: str, db: Session = Depends(get_db)):
    """
    Apply this specific rule to ALL findings immediately.
    Returns count of findings changed.
    """
    r = db.query(Rule).filter(Rule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    findings = db.query(Finding).options(joinedload(Finding.project)).all()
    changed = 0
    for f in findings:
        if matches_rule(f, r):
            if apply_actions(f, r):
                changed += 1
    if changed > 0:
        r.applied_count = (r.applied_count or 0) + changed
        from sqlalchemy.sql import func as sqlfunc
        r.last_applied_at = sqlfunc.now()
    db.commit()
    return {"rule_id": rule_id, "rule_name": r.name, "findings_changed": changed}


@router.post("/{rule_id}/test", response_model=RuleTestResult)
def test_rule(rule_id: str, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    """Alias for /simulate — kept for backwards compat."""
    return simulate_rule(rule_id, limit, db)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _simulate_actions(finding: Finding, rule: Rule) -> str:
    """Return a human-readable string of what would change."""
    changes = []
    for action in (rule.actions or []):
        atype = action.get("type")
        value = action.get("value", "")
        if atype == "set_status" and str(finding.status.value) != value:
            changes.append(f"status: {finding.status.value} → {value}")
        elif atype == "set_severity" and str(finding.severity.value) != value:
            changes.append(f"severity: {finding.severity.value} → {value}")
    return " | ".join(changes) if changes else "no change (already matches)"
