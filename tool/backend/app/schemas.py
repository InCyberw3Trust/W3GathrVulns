import re
from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Any, Dict
from datetime import datetime
from app.models import SeverityEnum, StatusEnum, SourceEnum, RuleConditionOperator, RuleActionType, GitProviderEnum


# ── Projects ──────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    repository_url: Optional[str] = None
    git_provider: Optional[GitProviderEnum] = GitProviderEnum.GITLAB
    default_branch: Optional[str] = "main"


class ProjectUpdate(BaseModel):
    description: Optional[str] = None
    repository_url: Optional[str] = None
    git_provider: Optional[GitProviderEnum] = None
    default_branch: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    git_provider: Optional[GitProviderEnum]
    default_branch: Optional[str]
    created_at: datetime
    findings_count: Optional[int] = 0
    open_findings: Optional[int] = 0
    critical_count: Optional[int] = 0

    model_config = {"from_attributes": True}


# ── Findings ──────────────────────────────────────────────────────────────────

class FindingUpdate(BaseModel):
    status: Optional[StatusEnum] = None
    false_positive_reason: Optional[str] = None
    notes: Optional[str] = None
    severity: Optional[SeverityEnum] = None


class FindingBatchUpdate(BaseModel):
    ids: List[str]   # list of finding UUIDs
    status: Optional[StatusEnum] = None
    severity: Optional[SeverityEnum] = None


class FindingResponse(BaseModel):
    id: str
    short_id: Optional[int] = None
    project_id: str
    scan_id: str
    title: str
    description: Optional[str]
    severity: SeverityEnum
    status: StatusEnum
    source: SourceEnum
    vuln_id: Optional[str]
    cve: Optional[str]
    cvss_score: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    component: Optional[str]
    component_version: Optional[str]
    fixed_version: Optional[str]
    url: Optional[str]
    method: Optional[str]
    parameter: Optional[str]
    tags: Optional[List[str]]
    extra_data: Optional[dict] = None
    false_positive_reason: Optional[str]
    notes: Optional[str]
    first_seen: datetime
    last_seen: datetime
    project_name: Optional[str] = None
    # Git link context (computed)
    git_file_url: Optional[str] = None

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ── Scans ─────────────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    id: str
    project_id: str
    source: SourceEnum
    branch: Optional[str]
    commit_sha: Optional[str]
    pipeline_id: Optional[str]
    scan_date: datetime
    findings_count: int
    project_name: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Stats ─────────────────────────────────────────────────────────────────────

class SeverityCount(BaseModel):
    severity: str
    count: int


class SourceCount(BaseModel):
    source: str
    count: int


class StatusCount(BaseModel):
    status: str
    count: int


class TrendPoint(BaseModel):
    date: str
    count: int


class DashboardStats(BaseModel):
    total_findings: int
    open_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    false_positives: int
    closed_count: int
    in_progress_count: int
    accepted_risk_count: int
    new_this_week: int
    total_projects: int
    total_scans: int
    by_severity: List[SeverityCount]
    by_source: List[SourceCount]
    by_status: List[StatusCount]
    recent_trend: List[TrendPoint]
    top_projects: List[dict]
    by_severity_project: List[dict]


# ── Rules ─────────────────────────────────────────────────────────────────────

class RuleCondition(BaseModel):
    field: str   # title, source, vuln_id, severity, file_path, tags, component, cve
    operator: RuleConditionOperator
    value: str

    @model_validator(mode="after")
    def validate_regex(self):
        if self.operator == RuleConditionOperator.REGEX:
            try:
                re.compile(self.value)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return self


class RuleAction(BaseModel):
    type: RuleActionType
    value: str


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    priority: int = 100
    conditions: List[RuleCondition]
    conditions_mode: str = "all"   # "all" or "any"
    actions: List[RuleAction]
    cron_schedule: Optional[str] = None


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    conditions: Optional[List[RuleCondition]] = None
    conditions_mode: Optional[str] = None
    actions: Optional[List[RuleAction]] = None
    cron_schedule: Optional[str] = None


class RuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    enabled: bool
    priority: int
    conditions: List[dict]
    conditions_mode: str
    actions: List[dict]
    created_at: datetime
    updated_at: Optional[datetime]
    applied_count: int
    last_applied_at: Optional[datetime]
    cron_schedule: Optional[str] = None

    model_config = {"from_attributes": True}


class RuleTestResult(BaseModel):
    matched_count: int
    matched_findings: List[FindingResponse]


# ── Ingest ────────────────────────────────────────────────────────────────────

class IngestResponse(BaseModel):
    scan_id: str
    project_id: str
    findings_created: int
    findings_updated: int
    rules_applied: int = 0
    message: str
