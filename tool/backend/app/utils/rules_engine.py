"""
Rules engine: evaluate Rule conditions against a Finding,
then apply actions (set_status, set_severity).
"""
import re
import logging
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.models import Rule, Finding, StatusEnum, SeverityEnum

logger = logging.getLogger(__name__)

FIELD_MAP = {
    "title":       lambda f: f.title or "",
    "source":      lambda f: f.source.value if f.source else "",
    "vuln_id":     lambda f: f.vuln_id or "",
    "cve":         lambda f: f.cve or "",
    "severity":    lambda f: f.severity.value if f.severity else "",
    "status":      lambda f: f.status.value if f.status else "",
    "file_path":   lambda f: f.file_path or "",
    "component":   lambda f: f.component or "",
    "tags":        lambda f: " ".join(f.tags or []),
    "description": lambda f: (f.description or "")[:500],
}


def _get_field(finding: Finding, field: str) -> str:
    getter = FIELD_MAP.get(field)
    return getter(finding).lower() if getter else ""


def _eval_condition(finding: Finding, cond: dict) -> bool:
    field    = cond.get("field", "")
    operator = cond.get("operator", "equals")
    value    = (cond.get("value", "") or "").lower()
    actual   = _get_field(finding, field)

    if operator == "equals":       return actual == value
    if operator == "not_equals":   return actual != value
    if operator == "contains":     return value in actual
    if operator == "not_contains": return value not in actual
    if operator == "starts_with":  return actual.startswith(value)
    if operator == "ends_with":    return actual.endswith(value)
    if operator == "in":           return actual in [v.strip().lower() for v in value.split(",")]
    if operator == "regex":
        try:
            return bool(re.search(value, actual))
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{value}': {e}")
            return False
    return False


def matches_rule(finding: Finding, rule: Rule) -> bool:
    conditions = rule.conditions or []
    if not conditions:
        return False
    results = [_eval_condition(finding, c) for c in conditions]
    return all(results) if (rule.conditions_mode or "all") == "all" else any(results)


def apply_actions(finding: Finding, rule: Rule) -> bool:
    changed = False
    for action in (rule.actions or []):
        atype = action.get("type")
        value = action.get("value", "")
        if atype == "set_status":
            try:
                new_val = StatusEnum(value)
                if finding.status != new_val:
                    finding.status = new_val
                    changed = True
            except ValueError:
                logger.warning(f"Rule {rule.id}: invalid status '{value}'")
        elif atype == "set_severity":
            try:
                new_val = SeverityEnum(value)
                if finding.severity != new_val:
                    finding.severity = new_val
                    changed = True
            except ValueError:
                logger.warning(f"Rule {rule.id}: invalid severity '{value}'")
    return changed


def apply_rules_to_finding(db: Session, finding: Finding) -> int:
    rules = (db.query(Rule).filter(Rule.enabled == True).order_by(Rule.priority.asc()).all())
    applied = 0
    for rule in rules:
        if matches_rule(finding, rule):
            if apply_actions(finding, rule):
                rule.applied_count = (rule.applied_count or 0) + 1
                applied += 1
    return applied


def apply_rules_to_all(db: Session) -> dict:
    rules    = db.query(Rule).filter(Rule.enabled == True).order_by(Rule.priority.asc()).all()
    findings = db.query(Finding).all()
    total    = 0
    for finding in findings:
        for rule in rules:
            if matches_rule(finding, rule):
                if apply_actions(finding, rule):
                    rule.applied_count = (rule.applied_count or 0) + 1
                    total += 1
    db.commit()
    return {"findings_processed": len(findings), "rules_applied": total}
