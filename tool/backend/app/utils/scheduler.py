"""
Background cron scheduler for rule auto-execution.

Each Rule with a non-null cron_schedule gets an APScheduler job.
The scheduler is synced on startup and whenever a rule is created/updated/deleted.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler(timezone="UTC", daemon=True)


# ── Job function ─────────────────────────────────────────────────────────────

def _run_rule_job(rule_id: str):
    """Execute a rule against all findings. Runs in a background thread."""
    from app.database import SessionLocal
    from app.models import Rule, Finding
    from app.utils.rules_engine import matches_rule, apply_actions
    from sqlalchemy.orm import joinedload
    from sqlalchemy.sql import func as sqlfunc

    db = SessionLocal()
    try:
        rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not rule or not rule.enabled:
            return

        findings = db.query(Finding).options(joinedload(Finding.project)).all()
        changed = 0
        for f in findings:
            if matches_rule(f, rule):
                if apply_actions(f, rule):
                    changed += 1

        if changed > 0:
            rule.applied_count = (rule.applied_count or 0) + changed
            rule.last_applied_at = sqlfunc.now()
        db.commit()
        logger.info("Cron rule '%s' applied: %d findings changed", rule.name, changed)
    except Exception as exc:
        logger.error("Cron rule %s failed: %s", rule_id, exc)
        db.rollback()
    finally:
        db.close()


# ── Public API ────────────────────────────────────────────────────────────────

def start():
    """Start the background scheduler (called once at app startup)."""
    if not _scheduler.running:
        _scheduler.start()
        logger.info("APScheduler started")


def stop():
    """Gracefully shut down the scheduler."""
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")


def sync_rule(rule_id: str, cron_schedule: str | None, enabled: bool):
    """
    Register or update a rule's cron job.
    Passing cron_schedule=None or enabled=False removes the job.
    """
    job_id = f"rule_{rule_id}"

    # Always remove the old job first
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    if cron_schedule and enabled:
        try:
            trigger = CronTrigger.from_crontab(cron_schedule, timezone="UTC")
            _scheduler.add_job(
                _run_rule_job,
                trigger,
                id=job_id,
                args=[rule_id],
                replace_existing=True,
                misfire_grace_time=300,
            )
            logger.info("Scheduled rule %s with cron '%s'", rule_id, cron_schedule)
        except Exception as exc:
            logger.warning("Invalid cron_schedule for rule %s ('%s'): %s", rule_id, cron_schedule, exc)


def remove_rule(rule_id: str):
    """Remove a rule's cron job (called on rule deletion)."""
    job_id = f"rule_{rule_id}"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)
        logger.info("Removed cron job for rule %s", rule_id)


def schedule_demo_reset():
    """Register the hourly demo data reset job (call only when DEMO_MODE=true)."""
    from app.utils.demo import reset_and_seed

    job_id = "demo_reset"
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    _scheduler.add_job(
        reset_and_seed,
        CronTrigger.from_crontab("0 * * * *", timezone="UTC"),
        id=job_id,
        replace_existing=True,
        misfire_grace_time=300,
    )
    logger.info("Demo reset job scheduled: every hour at :00")


def sync_all_rules():
    """Load all rules from DB and register their cron jobs."""
    from app.database import SessionLocal
    from app.models import Rule

    db = SessionLocal()
    try:
        rules = db.query(Rule).all()
        for rule in rules:
            sync_rule(rule.id, rule.cron_schedule, rule.enabled)
        logger.info("Scheduler synced: %d rules loaded", len(rules))
    except Exception as exc:
        logger.error("Failed to sync scheduler on startup: %s", exc)
    finally:
        db.close()
