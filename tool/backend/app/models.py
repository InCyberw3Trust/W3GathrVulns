from sqlalchemy import Column, String, Integer, BigInteger, DateTime, Text, JSON, Boolean, Enum, ForeignKey, Index
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func
import enum
import uuid


class Base(DeclarativeBase):
    pass


class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class StatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    IN_PROGRESS = "IN_PROGRESS"


class SourceEnum(str, enum.Enum):
    TRIVY = "trivy"
    GITLAB_SAST = "gitlab_sast"
    GITLAB_IAC = "gitlab_iac"
    GITLAB_SECRETS = "gitlab_secrets"
    OWASP_ZAP = "owasp_zap"
    NUCLEI = "nuclei"
    UNKNOWN = "unknown"


class RuleConditionOperator(str, enum.Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    IN = "in"


class RuleActionType(str, enum.Enum):
    SET_STATUS = "set_status"
    SET_SEVERITY = "set_severity"


class GitProviderEnum(str, enum.Enum):
    GITLAB = "gitlab"
    GITHUB = "github"
    BITBUCKET = "bitbucket"
    AZURE = "azure"
    GITEA = "gitea"
    OTHER = "other"


class AppSetting(Base):
    """Key-value store for runtime-configurable settings (tokens, credentials)."""
    __tablename__ = "app_settings"

    key        = Column(String(100), primary_key=True)
    value      = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    repository_url = Column(String(500), nullable=True)
    # Git integration for file links
    git_provider = Column(Enum(GitProviderEnum, native_enum=False), nullable=True, default=GitProviderEnum.GITLAB)
    default_branch = Column(String(255), nullable=True, default="main")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    source = Column(Enum(SourceEnum, native_enum=False), nullable=False)
    branch = Column(String(255), nullable=True)
    commit_sha = Column(String(255), nullable=True)
    pipeline_id = Column(String(255), nullable=True)
    scan_date = Column(DateTime(timezone=True), server_default=func.now())
    findings_count = Column(Integer, default=0)
    raw_payload = Column(JSON, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_scans_project_source", "project_id", "source"),)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    # Human-readable sequential ID — assigned by PostgreSQL sequence via _migrate() DEFAULT
    short_id = Column(BigInteger, unique=True, nullable=True, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)

    title = Column(String(1000), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(SeverityEnum, native_enum=False), nullable=False, default=SeverityEnum.UNKNOWN)
    status = Column(Enum(StatusEnum, native_enum=False), nullable=False, default=StatusEnum.OPEN)
    source = Column(Enum(SourceEnum, native_enum=False), nullable=False)

    vuln_id = Column(String(255), nullable=True, index=True)
    cve = Column(String(100), nullable=True, index=True)
    cvss_score = Column(String(10), nullable=True)

    file_path = Column(String(1000), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    component = Column(String(500), nullable=True)
    component_version = Column(String(100), nullable=True)
    fixed_version = Column(String(100), nullable=True)

    url = Column(String(2000), nullable=True)
    method = Column(String(20), nullable=True)
    parameter = Column(String(500), nullable=True)

    tags = Column(JSON, nullable=True, default=list)
    false_positive_reason = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now())
    extra_data = Column(JSON, nullable=True)
    raw_data = Column(JSON, nullable=True)

    project = relationship("Project", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_source", "source"),
    )


class Rule(Base):
    """Auto-triage rules: match findings on ingest and apply actions."""
    __tablename__ = "rules"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)  # lower = higher priority

    # JSON array of condition objects:
    # [{"field": "source", "operator": "equals", "value": "trivy"},
    #  {"field": "vuln_id", "operator": "contains", "value": "CVE-2021"}]
    conditions = Column(JSON, nullable=False, default=list)
    # "all" or "any"
    conditions_mode = Column(String(10), nullable=False, default="all")

    # JSON array of action objects:
    # [{"type": "set_status", "value": "FALSE_POSITIVE"},
    #  {"type": "set_severity", "value": "LOW"}]
    actions = Column(JSON, nullable=False, default=list)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    applied_count = Column(Integer, default=0, nullable=False)
    last_applied_at = Column(DateTime(timezone=True), nullable=True)
    # Cron expression for scheduled execution (e.g. "0 * * * *")
    # NULL = no schedule (only runs on ingest + manual trigger)
    cron_schedule = Column(String(100), nullable=True)
