# W3GathrVulns — Code Training Guide

> Version v0.1.0-beta  
> This document explains the project code from A to Z: where to find each piece, what happens during an API call, how the database is structured, and how each layer communicates with the others.

---

## Table of Contents

1. [Application Overview](#1-application-overview)
2. [Docker Infrastructure](#2-docker-infrastructure)
3. [Application Startup](#3-application-startup)
4. [Complete End-to-End Data Flow](#4-complete-end-to-end-data-flow)
5. [Request Lifecycle — By Route](#5-request-lifecycle--by-route)
   - 5.1 [POST /ingest/{tool} — scan ingestion](#51-post-ingesttool--scan-ingestion)
   - 5.2 [GET /findings — findings list](#52-get-findings--findings-list)
   - 5.3 [PATCH /findings/{id} — update](#53-patch-findingsid--update)
   - 5.4 [GET /stats/dashboard — statistics](#54-get-statsdashboard--statistics)
   - 5.5 [GET /export/csv and /export/pdf](#55-get-exportcsv-and-exportpdf)
   - 5.6 [POST /rules and POST /rules/{id}/apply](#56-post-rules-and-post-rulesidapply)
6. [Code Reference](#code-reference)
   - [Backend](#backend)
     - [Configuration (config.py)](#configuration-configpy)
     - [Database In Detail](#database-in-detail)
     - [ORM Models (models.py)](#orm-models-modelspy)
     - [Pydantic Schemas (schemas.py)](#pydantic-schemas-schemaspy)
     - [Parsers — Each Scanner In Detail](#parsers--each-scanner-in-detail)
     - [Rules Engine (rules_engine.py)](#rules-engine-rules_enginepy)
     - [Git Link Generation (git_links.py)](#git-link-generation-git_linkspy)
     - [Cron Scheduler (scheduler.py)](#cron-scheduler-schedulerpy)
     - [Test Suite](#test-suite)
   - [Frontend](#frontend)
     - [File Structure](#file-structure)
     - [Theme (index.css)](#theme-indexcss)
     - [Findings Filters](#findings-filters)
     - [State Management (client.js + React Query)](#state-management-clientjs--react-query)
     - [Debug Page — Sample Data Injection](#debug-page--sample-data-injection)
   - [Adding a Feature — Practical Guide](#adding-a-feature--practical-guide)
7. [Navigation Guide — Where to Find What](#7-navigation-guide--where-to-find-what)

---

## 1. Application Overview

W3GathrVulns is a **centralised security findings management platform**. It receives results from security scanners (Trivy, GitLab SAST, OWASP ZAP, etc.) from CI/CD pipelines, normalises them, deduplicates them, and presents them in a dashboard.

```
CI/CD Scanners
  Trivy / Semgrep / KICS / ZAP / Nuclei / Gitleaks
       │
       │  POST /api/v1/ingest/{tool}   ← raw JSON payload from the scanner
       ▼
┌──────────────────────────────────────────────────────┐
│                  Nginx (HTTPS :443)                   │
│  • Redirects HTTP → HTTPS                             │
│  • /api/* → proxy to backend:8000                     │
│  • /* → serves React build (SPA)                      │
└────────────────────┬─────────────────────────────────┘
                     │
           ┌─────────▼──────────┐
           │  FastAPI (uvicorn)  │
           │  • 8 routers        │
           │  • 4 parsers        │
           │  • Rules engine     │
           └─────────┬──────────┘
                     │  SQLAlchemy ORM
           ┌─────────▼──────────┐
           │   PostgreSQL 16    │
           │  • projects        │
           │  • scans           │
           │  • findings        │
           │  • rules           │
           │  • app_settings    │
           └────────────────────┘
```

**Key technologies:**

| Layer | Main File / Folder | Role |
|---|---|---|
| API Entrypoint | `tool/backend/app/main.py` | Creates the FastAPI app, registers routers |
| Configuration | `tool/backend/app/config.py` | Reads environment variables |
| Database | `tool/backend/app/database.py` | Connection, migrations, session |
| Models | `tool/backend/app/models.py` | PostgreSQL tables via SQLAlchemy ORM |
| Schemas | `tool/backend/app/schemas.py` | I/O validation via Pydantic |
| API Routers | `tool/backend/app/routers/` | HTTP endpoints (8 files) |
| Parsers | `tool/backend/app/parsers/` | Scanner JSON → normalised Finding |
| Rules | `tool/backend/app/utils/rules_engine.py` | Auto-triage of findings |
| Scheduler | `tool/backend/app/utils/scheduler.py` | APScheduler — executes rules on cron schedule + demo reset |
| Demo | `tool/backend/app/utils/demo.py` | Demo mode: sample payloads + hourly wipe-and-reseed |
| Auth | `tool/backend/app/utils/auth.py` | JWT creation/verification + in-memory token cache |
| Git links | `tool/backend/app/utils/git_links.py` | URLs pointing to source files |
| Frontend | `tool/frontend/src/` | React SPA (dashboard, findings, rules…) |
| Infrastructure | `tool/docker-compose.yml` | Orchestration of the 4 services |

---

## 2. Docker Infrastructure

### docker-compose.yml — services

The stack has 4 services starting in dependency order:

```
certs (init) → db (healthy) → backend (healthy) → frontend
```

```yaml
services:
  certs:         # Init container — run once
    image: alpine/openssl
    volumes: [certs_data:/certs]
    entrypoint: ["/bin/sh", "/generate.sh"]
    restart: "no"           # ← does NOT restart

  db:
    image: postgres:16-alpine
    volumes: [postgres_data:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s
      timeout: 5s
      retries: 10    # ← waits up to 50s

  backend:
    build: ./backend/Dockerfile    # Python 3.12-slim
    env_file: .env
    depends_on:
      db:
        condition: service_healthy  # ← waits for pg_isready to pass
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 10s
      retries: 5

  frontend:
    build: ./frontend/Dockerfile   # Node 20 build → nginx alpine serve
    ports: ["${HTTP_PORT:-80}:80", "${HTTPS_PORT:-443}:443"]
    volumes: [certs_data:/etc/nginx/certs:ro]
    depends_on:
      certs:   {condition: service_completed_successfully}
      backend: {condition: service_healthy}
```

### Backend Dockerfile (Python 3.12)

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# System dependencies for psycopg2 (compiled PostgreSQL driver)
RUN apt-get install -y gcc libpq-dev

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ ./app/

# 2 workers for concurrency
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
```

### Frontend Dockerfile (multi-stage)

```dockerfile
# Stage 1: Build React with Node
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build      # → generates /app/dist/

# Stage 2: Serve with Nginx
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod -R 755 /usr/share/nginx/html   # ← ensure nginx worker can read files
COPY nginx.conf /etc/nginx/conf.d/default.conf
```

The final image does **not** contain Node.js — only the compiled static files and Nginx.

### Nginx (nginx.conf)

```nginx
# Redirect HTTP → HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    ssl_certificate     /etc/nginx/certs/w3gathrvulns.crt;
    ssl_certificate_key /etc/nginx/certs/w3gathrvulns.key;

    # PROXY: everything starting with /api/ goes to the backend
    location /api/ {
        proxy_pass http://backend:8000;
        proxy_read_timeout 120s;    # ← for large ingest payloads
        client_max_body_size 50M;   # ← maximum payload size
    }

    # SPA: everything else serves index.html (React Router handles client-side routing)
    location / {
        root  /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }
}
```

**`try_files $uri $uri/ /index.html`**: if the requested URL does not match a static file, returns `index.html`. This is what allows React Router to handle URLs like `/findings/42` directly.

---

## 3. Application Startup

### Startup order

```
1. certs (alpine/openssl)
   └─ Runs tool/certs/generate.sh
   └─ Generates /certs/w3gathrvulns.crt and /certs/w3gathrvulns.key
   └─ Condition: service_completed_successfully

2. db (postgres:16-alpine)
   └─ Initialises the DB with POSTGRES_USER / POSTGRES_DB
   └─ Health check: pg_isready every 5s (max 50s)
   └─ Condition: service_healthy

3. backend (FastAPI)
   └─ Launches uvicorn app.main:app --workers 2
   └─ On import, config.py reads .env → Settings()
   └─ startup() function:
      ├─ init_db()                  → creates tables + idempotent migrations
      ├─ reload_token_cache()       → loads API tokens from DB into memory
      ├─ scheduler.start()          → starts APScheduler background thread
      └─ scheduler.sync_all_rules() → registers cron jobs for all enabled rules
   └─ Health check: GET /api/health every 10s (max 50s)
   └─ Condition: service_healthy

4. frontend (Nginx + React build)
   └─ Serves Vite build from /usr/share/nginx/html
   └─ Proxies /api/* → http://backend:8000
```

### Backend startup in detail (`main.py`)

```python
# 1. FastAPI application creation with OpenAPI metadata
app = FastAPI(
    title="W3GathrVulns API",
    version="0.1.0-beta",
    openapi_url="/api/openapi.json",   # must be under /api/ for Nginx proxy
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# 2. CORS middleware — reads cors_origins from .env
app.add_middleware(CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Auth middleware — checks every request except public paths
app.add_middleware(AuthMiddleware)   # ← validates JWT or API token

# 4. Startup event — runs once before accepting requests
@app.on_event("startup")
def startup():
    init_db()                   # ← database.py — runs migrations
    reload_token_cache()        # ← loads API tokens from DB into in-memory dict
    scheduler.start()           # ← start APScheduler background thread
    scheduler.sync_all_rules()  # ← register all enabled cron rules as jobs

# 5. Mount the 8 routers under /api/v1
app.include_router(auth.router,     prefix="/api/v1")
app.include_router(settings.router, prefix="/api/v1")
app.include_router(ingest.router,   prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
# ... (projects, stats, export, rules)
```

### Startup migrations (`database.py`)

The `_migrate()` function executes a list of **idempotent** SQL statements (using `IF NOT EXISTS`, `IF NULL`, `DO $$ BEGIN ... EXCEPTION` blocks). It is safe to re-run on every startup.

Current migrations (execution order):

| SQL | Purpose |
|---|---|
| `ALTER TABLE findings ADD COLUMN IF NOT EXISTS extra_data JSONB` | Extended metadata storage per scanner |
| `ALTER TABLE rules ADD COLUMN IF NOT EXISTS cron_schedule VARCHAR(100)` | Scheduled rule execution |
| `ALTER TABLE findings ADD COLUMN IF NOT EXISTS short_id BIGINT` | Human-readable ID (#42) |
| `ALTER TABLE projects ADD COLUMN IF NOT EXISTS git_provider VARCHAR(50)` | Git provider for file links |
| `ALTER TABLE projects ADD COLUMN IF NOT EXISTS default_branch VARCHAR(255)` | Default branch for links |
| `CREATE SEQUENCE finding_short_id_seq` | Auto-increment sequence for short_id |
| `UPDATE findings SET short_id = nextval(...)` | Backfill existing findings |
| `CREATE UNIQUE INDEX ix_findings_short_id` | Uniqueness index on short_id |
| `CREATE TABLE IF NOT EXISTS app_settings (key VARCHAR PRIMARY KEY, value TEXT)` | Token cache + password hash storage |

---

## 4. Complete End-to-End Data Flow

Here is the complete journey of a vulnerability from detection to display in the dashboard.

```
1. DETECTION (CI/CD)
   ──────────────────
   GitLab Pipeline → trivy-scan job
   trivy image --format json --output trivy.json myapp:latest
   └─ Generates: {"Results": [{"Target": "myapp", "Vulnerabilities": [...]}]}

2. SENDING
   ────────
   curl -X POST "https://w3gathrvulns.internal/api/v1/ingest/trivy?project=myapp&branch=main&commit=abc123" \
     -H "Content-Type: application/json" -d @trivy.json

3. RECEPTION (Nginx)
   ──────────────────
   /api/ → proxy_pass http://backend:8000

4. PARSING (backend)
   ──────────────────
   trivy.parse(payload)
   └─ CVE-2023-44487 in nghttp2 → {
        title: "CVE-2023-44487 in nghttp2",
        severity: HIGH,
        cve: "CVE-2023-44487",
        cvss_score: "7.5",
        component: "nghttp2",
        component_version: "1.52.0-1",
        fixed_version: "1.52.0-1+deb12u1",
        file_path: "myapp:latest (debian 12.0)",
        extra_data: {cvss: {nvd: {V3Score: 7.5, ...}}, ...}
      }

5. DEDUPLICATION
   ──────────────
   SELECT * FROM findings
   WHERE project_id = 'proj-uuid'
     AND title = 'CVE-2023-44487 in nghttp2'
     AND source = 'trivy'
     AND file_path = 'myapp:latest (debian 12.0)'
     AND status != 'FALSE_POSITIVE'
   └─ Not found → INSERT INTO findings (...)
      short_id = nextval('finding_short_id_seq') = 42

6. RULES
   ──────
   SELECT * FROM rules WHERE enabled = true ORDER BY priority ASC
   └─ Rule "Auto-close INFO": conditions=[{source=trivy, severity=INFO}]
      → severity=HIGH → no match → no action

7. COMMIT
   ───────
   db.commit() → everything persists

8. RESPONSE
   ─────────
   {"scan_id":"...", "findings_created":1, "findings_updated":0, "rules_applied":0}

9. DISPLAY (Frontend)
   ───────────────────
   Dashboard auto-refresh (60s) → GET /api/v1/stats/dashboard
   → open_findings: 143 → re-render KPI card

   Findings page → GET /api/v1/findings?severity=HIGH
   → finding #42 appears in the list
   → click → GET /api/v1/findings/42
   → detail page with git_file_url if repo_url is configured
```

---

## 5. Request Lifecycle — By Route

### 5.1 POST /ingest/{tool} — scan ingestion

This is the most important flow. Here is what happens in detail for `POST /api/v1/ingest/trivy?project=my-app&branch=main&commit=abc123`.

```
Client (CI/CD)
  │
  │  POST /api/v1/ingest/trivy?project=my-app&branch=main&commit=abc123
  │  Body: { "Results": [...] }  ← raw JSON from Trivy
  │
  ▼
Nginx
  │  location /api/ → proxy_pass http://backend:8000
  │
  ▼
FastAPI (uvicorn worker)
  │
  │  1. Routing: matches @router.post("/trivy") in routers/ingest.py
  │
  │  2. Dependencies resolved:
  │     └─ db: Session = Depends(get_db) → opens a PostgreSQL session
  │
  │  3. Query params validated by FastAPI:
  │     project: str = Query(...)   ← REQUIRED, 422 if missing
  │     branch, commit, pipeline    ← Optional
  │     scan_date: str = Query(None)← Optional ISO 8601 datetime (overrides first_seen/last_seen)
  │
  │  4. Body deserialisation:
  │     payload: Dict[str, Any]     ← FastAPI parses JSON automatically
  │
  │  5. try/except block:
  │     └─ parsed = trivy.parse(payload)   ← PARSER
  │
  ▼
parsers/trivy.py  →  parse(payload)
  │
  │  Iterates payload["Results"]
  │  For each result:
  │    └─ Iterates Vulnerabilities, Misconfigurations, Secrets
  │       For each item:
  │         • Maps severity via SEVERITY_MAP
  │         • Extracts CVSS (prefers NVD V3 > NVD V2)
  │         • Builds the finding dict with all normalised fields
  │         • Stores raw object in extra_data and raw_data
  │  Returns: list[dict]  (one dict per finding)
  │
  ▼
routers/ingest.py  →  ingest_findings(db, "my-app", SourceEnum.TRIVY, parsed, ...)
  │
  │  6. get_or_create_project("my-app")
  │     └─ SELECT * FROM projects WHERE name = "my-app"
  │     └─ If absent → INSERT INTO projects (id, name) → db.flush()
  │
  │  7. Scan creation:
  │     INSERT INTO scans (id, project_id, source, branch, commit_sha, findings_count, raw_payload)
  │     db.flush()   ← flush without commit to have scan.id available
  │
  │  8. For each parsed finding:
  │
  │     a) DEDUPLICATION:
  │        SELECT * FROM findings
  │        WHERE project_id = 'xxx'
  │          AND title = 'CVE-2023-44487 in nghttp2'
  │          AND source = 'trivy'
  │          AND file_path = 'myapp:latest (debian 12.0)'
  │          AND status != 'FALSE_POSITIVE'
  │          [AND line_start = 5]   ← if line_start is present
  │
  │     b) If found (existing):
  │        • existing.last_seen = now (or scan_date if provided)
  │        • existing.scan_id  = new scan
  │        • Fills missing fields: cvss_score, fixed_version, cve
  │        • Merges tags without duplicates
  │        • Refreshes extra_data with latest scan data
  │        • updated += 1
  │
  │     c) If not found (new):
  │        • Finding(id=uuid4(), project_id, scan_id, **{k:v for valid k})
  │        • If scan_date provided: first_seen = last_seen = scan_date
  │        • db.add(finding)
  │        • created += 1
  │
  │  9. db.flush()  ← assigns short_ids (PostgreSQL sequence)
  │
  │  10. RULES APPLICATION:
  │      all_findings = SELECT * FROM findings WHERE scan_id = new_scan.id
  │      For each finding:
  │        apply_rules_to_finding(db, finding)   ← rules_engine.py
  │
  │  11. db.commit()  ← EVERYTHING is persisted in a single transaction
  │
  │  12. Returns IngestResponse:
  │      {"scan_id":"...", "findings_created":3, "findings_updated":0, "rules_applied":1}
  │
  ▼
FastAPI serialises IngestResponse → JSON → HTTP 200
```

**Why `db.flush()` and not `db.commit()` during the loop?**  
`flush()` sends INSERTs/UPDATEs to PostgreSQL without committing them. This allows the sequence to assign `short_id` values and keeps FKs consistent, but everything can be rolled back if an error occurs. The final `commit()` validates everything in an atomic transaction.

---

### 5.2 GET /findings — findings list

```
GET /api/v1/findings?page=1&page_size=25&severity=CRITICAL&severity=HIGH&search=openssl&sort_by=severity&sort_dir=desc
```

```
FastAPI
  │
  │  1. Parameters parsed (FastAPI handles lists automatically):
  │     severity: List[SeverityEnum] = [CRITICAL, HIGH]
  │     search: str = "openssl"
  │
  │  2. SQLAlchemy query construction:
  │
  │     q = db.query(Finding)
  │           .options(
  │             joinedload(Finding.project),  ← loads project in 1 query (no N+1)
  │             joinedload(Finding.scan)       ← same
  │           )
  │           .join(Project, Finding.project_id == Project.id)
  │
  │  3. Filters applied:
  │     • search → OR on title, description, cve, vuln_id, component, file_path (ILIKE)
  │     • severity → Finding.severity IN [CRITICAL, HIGH]
  │     • status → Finding.status IN [...]
  │     • source → Finding.source IN [...]
  │     • project_id → Finding.project_id = '...'
  │     • filters (advanced JSON) → dynamic field/operator/value conditions
  │
  │  4. Sorting:
  │     SORTABLE = {"severity": Finding.severity, "first_seen": Finding.first_seen, ...}
  │     ORDER BY severity DESC
  │
  │  5. Pagination:
  │     total = q.count()
  │     items = q.offset(0).limit(25).all()
  │
  │  6. For each finding → _to_response(finding):
  │     a) FindingResponse.model_validate(finding)  ← serialises ORM to Pydantic
  │     b) d.project_name = finding.project.name    ← relationship access (already loaded)
  │     c) d.git_file_url = _build_git_url(finding) ← builds Git URL if applicable
  │
  │  7. Returns FindingListResponse:
  │     { items:[...], total:142, page:1, page_size:25, total_pages:6 }
```

**`joinedload` vs lazy loading:**  
Without `joinedload`, accessing `finding.project` in the loop would trigger one SQL query per finding (N+1 problem). With `joinedload`, SQLAlchemy performs a single JOIN query and caches the results.

---

### 5.3 PATCH /findings/{id} — update

```
PATCH /api/v1/findings/42        ← short_id
Body: {"status": "FALSE_POSITIVE", "false_positive_reason": "Test environment"}
```

```python
# In findings.py — get_finding accepts short_id OR UUID
if finding_ref.isdigit():
    f = q.filter(Finding.short_id == int(finding_ref)).first()
else:
    f = q.filter(Finding.id == finding_ref).first()

# Apply updated fields (only those provided)
if update.status is not None:
    f.status = update.status
if update.false_positive_reason is not None:
    f.false_positive_reason = update.false_positive_reason

db.commit()
return _to_response(f)
```

---

### 5.4 GET /stats/dashboard — statistics

```
GET /api/v1/stats/dashboard
GET /api/v1/stats/dashboard?severity=CRITICAL&severity=HIGH&status=OPEN&source=trivy&project_id=<uuid>
```

All four filter params (`project_id`, `severity`, `status`, `source`) are optional lists. When provided, a shared `base()` helper applies them to every aggregation query so all KPIs, charts, and the trend reflect the same filtered scope.

The endpoint computes:

```python
# KPIs
total, open, closed, in_progress, accepted_risk, false_positives
new_this_week  # findings with first_seen >= now - 7 days

# Open counts by severity (CRITICAL / HIGH / MEDIUM / LOW)
critical_count = base().filter(status=OPEN, severity=CRITICAL).count()

# Breakdowns (for charts)
by_severity    # group by severity
by_status      # group by status → status donut chart
by_source      # group by source → bar chart

# Trend
recent_trend   # last 30 days, group by date

# Top projects
top_projects   # top 5 by open findings count

# Stacked bar: severity × project
by_severity_project   # top 8 projects, columns: CRITICAL/HIGH/MEDIUM/LOW (open only)
# Uses SQLAlchemy conditional sum:
# func.sum(case((Finding.severity == SeverityEnum.CRITICAL, 1), else_=0))
```

---

### 5.5 GET /export/csv and /export/pdf

These endpoints return **streaming files** rather than JSON.

**CSV:**
```python
def export_csv(...):
    findings = get_filtered_findings(db, ...)  # same filter logic as /findings

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Title", "Severity", ...])  # header
    for f in findings:
        writer.writerow([f.short_id, f.title, f.severity.value, ...])

    filename = f"w3gathrvulns-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
```

**PDF:** uses the `reportlab` library. Rows are coloured by severity:
- CRITICAL → red
- HIGH → orange
- MEDIUM → yellow
- LOW → light green
- INFO → white

---

### 5.6 POST /rules and POST /rules/{id}/apply

**Creating a rule:**

```
POST /api/v1/rules
Body: {
  "name": "Auto-close ZAP INFO",
  "conditions": [
    {"field": "source", "operator": "equals", "value": "owasp_zap"},
    {"field": "severity", "operator": "equals", "value": "INFO"}
  ],
  "conditions_mode": "all",
  "actions": [{"type": "set_status", "value": "CLOSED"}],
  "priority": 10
}
```

Pydantic validates each `RuleCondition` (including regex compilation), then the rule is inserted into the database with its conditions/actions serialised as JSON.

**Applying a rule (`POST /rules/{id}/apply`):**

```python
# Load all findings
findings = db.query(Finding).all()

for finding in findings:
    if matches_rule(finding, rule):        # rules_engine.py
        if apply_actions(finding, rule):   # modifies finding.status or finding.severity
            rule.applied_count += 1
            changes += 1

db.commit()
return {"changes": changes, "total_checked": len(findings)}
```

---

## Code Reference

---

### Backend

---

#### Configuration (config.py)

```python
class Settings(BaseSettings):
    database_url: str          # REQUIRED — crashes on startup if missing
    secret_key: str            # REQUIRED — min 32 chars, rejected if known insecure value
    api_prefix: str = "/api/v1"
    cors_origins: List[str] = ["http://localhost"]
    debug: bool = False

    class Config:
        env_file = ".env"       # automatically reads tool/.env
```

**Intentional behaviour:** if `database_url` or `secret_key` are missing, the application **refuses to start**. This is deliberate to prevent launching a misconfigured instance.

The `secret_key_must_not_be_default` validator compares the key against a list of common values (`changeme`, `secret`, etc.) **and** enforces a minimum length of 32 characters. If either check fails, the application crashes with an explicit message.

The `settings` object is imported as a singleton in all modules that need it:
```python
from app.config import settings
# then: settings.database_url, settings.cors_origins, etc.
```

---

#### Database In Detail

##### Connection (`database.py`)

```python
_is_sqlite = settings.database_url.startswith("sqlite")
engine = create_engine(
    settings.database_url,
    pool_pre_ping=not _is_sqlite,   # tests connection before reuse (PostgreSQL only)
    **({} if _is_sqlite else {
        "pool_size": 10,    # connections kept open permanently
        "max_overflow": 20, # extra connections under load (max 30 total)
    }),
)
# Note: pool_size / max_overflow are not valid for SQLite — the conditional
# ensures the same codebase works for both production (PostgreSQL) and tests (SQLite).
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

**pool_pre_ping=True**: before taking a connection from the pool, SQLAlchemy sends a `SELECT 1` to ensure it is still active. Essential for avoiding errors after a database restart.

**Session injection into routes** via `Depends(get_db)`:

```python
def get_db():
    db = SessionLocal()
    try:
        yield db            # ← session is passed to the router
    finally:
        db.close()          # ← closed even on exception
```

FastAPI calls `get_db` as a dependency (`Depends`) for each request. The session is created, passed to the handler function, then automatically closed at the end of the request.

##### Complete Database Schema

###### Table `projects`

```sql
CREATE TABLE projects (
    id              VARCHAR    PRIMARY KEY,              -- UUID v4
    name            VARCHAR(255) NOT NULL UNIQUE,        -- Project name (e.g. "my-app")
    description     TEXT,
    repository_url  VARCHAR(500),                        -- Git repository URL
    git_provider    VARCHAR(50),                         -- Enum: gitlab/github/bitbucket/azure/gitea/other
    default_branch  VARCHAR(255) DEFAULT 'main',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at      TIMESTAMP WITH TIME ZONE            -- updated on every PATCH
);

INDEX ix_projects_name ON projects(name);
```

**Role:** logical container for scans and findings. Auto-created on first ingest if it does not exist.

###### Table `scans`

```sql
CREATE TABLE scans (
    id             VARCHAR    PRIMARY KEY,   -- UUID v4
    project_id     VARCHAR    NOT NULL REFERENCES projects(id),
    source         VARCHAR    NOT NULL,      -- Enum: trivy/gitlab_sast/gitlab_iac/...
    branch         VARCHAR(255),             -- Git branch from the pipeline
    commit_sha     VARCHAR(255),             -- Commit SHA
    pipeline_id    VARCHAR(255),             -- CI/CD pipeline ID
    scan_date      TIMESTAMP WITH TIME ZONE DEFAULT now(),
    findings_count INTEGER DEFAULT 0,       -- Number of parsed findings (before dedup)
    raw_payload    JSON                      -- Raw JSON payload from the scanner (stored as-is)
);

INDEX ix_scans_project_source ON scans(project_id, source);
```

**Role:** records each scanner execution. The `raw_payload` allows replaying parsing if the parser is improved.

###### Table `findings`

This is the central table. It contains all normalised vulnerabilities.

```sql
CREATE TABLE findings (
    -- Identifiers
    id         VARCHAR    PRIMARY KEY,                   -- UUID v4
    short_id   BIGINT UNIQUE,                            -- Human-readable ID: #1, #2, #42...
    project_id VARCHAR    NOT NULL REFERENCES projects(id),
    scan_id    VARCHAR    NOT NULL REFERENCES scans(id),

    -- Core data
    title       VARCHAR(1000) NOT NULL,
    description TEXT,
    severity    VARCHAR NOT NULL DEFAULT 'UNKNOWN',      -- Enum: CRITICAL/HIGH/MEDIUM/LOW/INFO/UNKNOWN
    status      VARCHAR NOT NULL DEFAULT 'OPEN',         -- Enum: OPEN/CLOSED/FALSE_POSITIVE/ACCEPTED_RISK/IN_PROGRESS
    source      VARCHAR NOT NULL,                        -- Enum: trivy/gitlab_sast/etc.

    -- Vulnerability identifiers
    vuln_id    VARCHAR(255),  -- Rule ID (CVE, semgrep_id, kics_id...)
    cve        VARCHAR(100),  -- Specific CVE if applicable (e.g. CVE-2023-44487)
    cvss_score VARCHAR(10),   -- CVSS score (e.g. "9.8")

    -- Code location
    file_path  VARCHAR(1000),
    line_start INTEGER,
    line_end   INTEGER,

    -- Affected component
    component         VARCHAR(500),
    component_version VARCHAR(100),
    fixed_version     VARCHAR(100),

    -- Web context (ZAP, Nuclei)
    url       VARCHAR(2000),
    method    VARCHAR(20),
    parameter VARCHAR(500),

    -- Management and tracking
    tags                  JSON,
    false_positive_reason TEXT,
    notes                 TEXT,
    first_seen   TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_seen    TIMESTAMP WITH TIME ZONE DEFAULT now(),

    -- Raw data
    extra_data  JSONB,  -- Extended scanner metadata (detailed CVSS, CWEs, etc.)
    raw_data    JSON    -- Raw scanner object as parsed
);

INDEX ix_findings_project_severity ON findings(project_id, severity);
INDEX ix_findings_status            ON findings(status);
INDEX ix_findings_source            ON findings(source);
INDEX ix_findings_short_id          ON findings(short_id);    -- UNIQUE
INDEX ix_findings_vuln_id           ON findings(vuln_id);
INDEX ix_findings_cve               ON findings(cve);
```

**Key points:**

- `short_id` has no ORM-level default. The PostgreSQL sequence (`finding_short_id_seq`) is wired directly to the column via a migration, so PostgreSQL assigns the value on INSERT.
- `first_seen` never changes after creation. `last_seen` is updated on each scan that detects the same finding.
- `extra_data` is of type JSONB (indexable). `raw_data` is plain JSON.
- `status = FALSE_POSITIVE` excludes the finding from deduplication — it will never be updated by a subsequent scan.

###### Table `rules`

```sql
CREATE TABLE rules (
    id          VARCHAR    PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    priority    INTEGER NOT NULL DEFAULT 100,

    -- Conditions (JSON array)
    -- e.g. [{"field":"source","operator":"equals","value":"trivy"}]
    conditions      JSON NOT NULL DEFAULT '[]',
    conditions_mode VARCHAR(10) NOT NULL DEFAULT 'all',  -- "all" (AND) or "any" (OR)

    -- Actions (JSON array)
    -- e.g. [{"type":"set_status","value":"FALSE_POSITIVE"}]
    actions JSON NOT NULL DEFAULT '[]',

    cron_schedule VARCHAR(100),

    applied_count  INTEGER NOT NULL DEFAULT 0,
    last_applied_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE
);
```

###### Table `app_settings`

```sql
CREATE TABLE app_settings (
    key   VARCHAR PRIMARY KEY,  -- "api_token_read", "api_token_write", "ui_password_hash"
    value TEXT NOT NULL
);
```

Stores the three mutable secrets: read token, write token, and the bcrypt password hash. On first startup `_seed_settings()` imports values from `.env` into this table — after that the DB is authoritative and **`.env` values are never used for runtime authentication**. Changes made via the Settings page (token regeneration, password change) update this table without requiring a restart. The auth middleware loads these values into an in-memory `token_cache` dict at startup and after each change, so there is no DB hit per request.

##### Table Relationships

```
projects (1) ──── (N) scans
projects (1) ──── (N) findings
scans    (1) ──── (N) findings

findings ──── project (via project_id)
findings ──── scan    (via scan_id)
```

Relationships are defined with `cascade="all, delete-orphan"`: deleting a project automatically deletes its scans and findings.

##### Enums

Enums are defined in Python in `models.py` and mapped to `VARCHAR` columns in PostgreSQL (no native ENUM type, to simplify migrations).

```python
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

class GitProviderEnum(str, enum.Enum):
    GITLAB = "gitlab"
    GITHUB = "github"
    BITBUCKET = "bitbucket"
    AZURE = "azure"
    GITEA = "gitea"
    OTHER = "other"
```

---

#### ORM Models (models.py)

SQLAlchemy uses a declarative pattern: each Python class inherits from `Base` and corresponds to a table.

```python
class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    short_id = Column(BigInteger, unique=True, nullable=True, index=True)
    ...
    project = relationship("Project", back_populates="findings")
    scan    = relationship("Scan",    back_populates="findings")

class AppSetting(Base):
    __tablename__ = "app_settings"

    key   = Column(String, primary_key=True)
    value = Column(Text, nullable=False)
```

**Key points:**

- `default=lambda: str(uuid.uuid4())`: the UUID is generated on the Python side, not by PostgreSQL.
- `short_id` has no ORM-level default. The PostgreSQL sequence (`finding_short_id_seq`) is wired directly to the column via a migration (`ALTER TABLE findings ALTER COLUMN short_id SET DEFAULT nextval('finding_short_id_seq')`), so PostgreSQL assigns the value on INSERT without SQLAlchemy needing to know about it.
- `relationship(...)` with `back_populates`: allows accessing `finding.project` or `finding.scan` directly from Python (lazy loading by default).
- `cascade="all, delete-orphan"` on `Project → Scan` and `Project → Finding` relationships: cascade deletion is managed by SQLAlchemy, not a PostgreSQL FK constraint.
- `AppSetting` is used only by `_seed_settings()` (on first startup) and by the Settings router (token regeneration, password change). It is never queried per request — values are cached in the `token_cache` dict in `utils/auth.py`.

---

#### Pydantic Schemas (schemas.py)

Pydantic validates incoming and outgoing data. Each endpoint declares its types via these schemas.

##### Input schemas (Create / Update)

```python
class ProjectCreate(BaseModel):
    name: str                          # REQUIRED
    repository_url: Optional[str]      # Optional
    git_provider: Optional[GitProviderEnum] = GitProviderEnum.GITLAB
    default_branch: Optional[str] = "main"

class FindingUpdate(BaseModel):
    status: Optional[StatusEnum] = None
    false_positive_reason: Optional[str] = None
    notes: Optional[str] = None
    severity: Optional[SeverityEnum] = None
```

##### Response schema

```python
class FindingResponse(BaseModel):
    id: str
    short_id: Optional[int]
    ...
    project_name: Optional[str] = None    # ← computed field, not in DB
    git_file_url: Optional[str] = None    # ← computed field, not in DB

    model_config = {"from_attributes": True}  # ← enables conversion from SQLAlchemy model
```

`model_config = {"from_attributes": True}` allows calling `FindingResponse.model_validate(finding_orm)` directly from a SQLAlchemy object.

##### Rule validation

```python
class RuleCondition(BaseModel):
    field: str
    operator: RuleConditionOperator
    value: str

    @model_validator(mode="after")
    def validate_regex(self):
        if self.operator == RuleConditionOperator.REGEX:
            try:
                re.compile(self.value)   # ← compiles the regex at creation time
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")
        return self

class RuleAction(BaseModel):
    type: str   # "set_status" or "set_severity"
    value: str  # e.g. "CLOSED", "HIGH"
```

This validator is executed automatically by Pydantic when deserialising a `RuleCondition`. If the regex pattern is invalid, FastAPI returns a 422 with a clear message before the rule is even created in the database.

---

#### Parsers — Each Scanner In Detail

All parsers follow the same contract:

```python
def parse(payload: dict) -> list[dict]:
    """
    Input:  raw JSON payload from the scanner (as received in the HTTP body)
    Output: list of normalised dicts, each dict may contain any key
            corresponding to a Finding column
    """
```

##### trivy.py

Trivy can produce 3 types of findings in a single report:

| Type | Source JSON key | Main extracted fields |
|---|---|---|
| Vulnerability | `Results[].Vulnerabilities[]` | CVE, CVSS (NVD V3 preferred), package, version, fixed_version |
| Misconfiguration | `Results[].Misconfigurations[]` | Rule ID prepended to title (e.g. `DS002: Image should not be run as root`), description, resolution |
| Secret | `Results[].Secrets[]` | RuleID, start/end line, match |

**CVSS extraction:**
```python
def _best_cvss(cvss: dict) -> tuple[str, str]:
    # Priority: NVD V3 > NVD V2 > first available source
    for source in ("nvd", *[k for k in cvss if k != "nvd"]):
        entry = cvss.get(source, {})
        if entry.get("V3Score"):
            return str(entry["V3Score"]), entry.get("V3Vector")
        if entry.get("V2Score"):
            return str(entry["V2Score"]), entry.get("V2Vector")
    return None, None
```

**Misconfiguration title format:**
```python
_mis_id    = mis.get("ID", "")
_mis_title = mis.get("Title", "Misconfiguration")
_title     = f"{_mis_id}: {_mis_title}" if _mis_id else _mis_title
# → "DS002: Image should not be run as root"
```

##### gitlab_sast.py

This parser handles **3 types** of GitLab reports with a single entry point `parse(payload, hint)`:

**Automatic type detection:**
```python
def _detect_source(payload, hint):
    scan_type  = payload["scan"]["type"].lower()     # "sast", "iac", "secret_detection"
    scanner_id = payload["scan"]["scanner"]["id"].lower()  # "semgrep", "kics", "gitleaks"
    if "secret" in scan_type or "gitleaks" in scanner_id: return GITLAB_SECRETS
    if "iac" in scan_type or "kics" in scanner_id:        return GITLAB_IAC
    return GITLAB_SAST
```

**Identifier extraction (`_parse_identifiers`):**  
Each GitLab vulnerability contains an `identifiers` array with `{type, value, url}` objects. The parser extracts: `semgrep_id`, CVEs, CWEs (list), OWASP (list), `kics_id`, `gitleaks_rule_id`, etc. All are stored in `extra_data`.

**Secret masking:**  
For Gitleaks reports, the extracted value (`raw_source_code_extract`) is masked before storage:
```python
def _mask_secret(value):
    # "ghp_AbCdEfGhIjKlMn" → "ghp_****lMn"
    return value[:4] + "****" + value[-4:]
```

##### owasp_zap.py

ZAP reports alerts with instances (one alert can match on N URLs). The parser creates one finding per instance to preserve the full HTTP context (URL, method, parameter, evidence).

##### nuclei.py

Nuclei produces JSONL (one line = one JSON object). The received payload must be a JSON array (wrapped with `jq -s '.'`). Empty payloads return `[]` immediately. The parser handles both dict and list formats.

Each Nuclei result can have multiple `matcher-name` values — the parser creates one finding per matcher to differentiate match cases.

---

#### Rules Engine (rules_engine.py)

##### General Operation

```
For each finding (during ingest or manual application):
  Load all enabled rules, sorted by priority ASC
  For each rule:
    matches_rule(finding, rule)?
      ├─ NO  → move to next rule
      └─ YES → apply_actions(finding, rule)
                 If change → rule.applied_count += 1
```

**All enabled rules are evaluated** (no short-circuit on first match). A priority-10 rule may change the status, then a priority-20 rule may still change the severity of the same finding.

##### `matches_rule(finding, rule)`

```python
FIELD_MAP = {
    "title":       lambda f: f.title or "",
    "source":      lambda f: f.source.value if f.source else "",
    "severity":    lambda f: f.severity.value if f.severity else "",
    "status":      lambda f: f.status.value if f.status else "",
    "file_path":   lambda f: f.file_path or "",
    "component":   lambda f: f.component or "",
    "tags":        lambda f: " ".join(f.tags or []),
    "description": lambda f: (f.description or "")[:500],  # truncated to 500 chars
    "vuln_id":     lambda f: f.vuln_id or "",
    "cve":         lambda f: f.cve or "",
}
```

All fields are converted to **lowercase** for comparison (case-insensitive matching).

##### `_eval_condition(finding, cond)`

```python
if operator == "equals":       return actual == value
if operator == "not_equals":   return actual != value
if operator == "contains":     return value in actual
if operator == "not_contains": return value not in actual
if operator == "starts_with":  return actual.startswith(value)
if operator == "ends_with":    return actual.endswith(value)
if operator == "in":           return actual in [v.strip().lower() for v in value.split(",")]
if operator == "regex":
    try:    return bool(re.search(value, actual))
    except re.error as e:
        logger.warning(f"Invalid regex '{value}': {e}")
        return False
```

##### `apply_actions(finding, rule)`

```python
for action in rule.actions:
    if action["type"] == "set_status":
        new_val = StatusEnum(action["value"])
        if finding.status != new_val:
            finding.status = new_val
            changed = True
    elif action["type"] == "set_severity":
        new_val = SeverityEnum(action["value"])
        if finding.severity != new_val:
            finding.severity = new_val
            changed = True
```

Invalid enum values are logged and ignored (no exception raised).

---

#### Git Link Generation (git_links.py)

When a finding has a `file_path` and its project has a `repository_url`, the backend builds a clickable link to the source file at the correct line.

```python
# Parameters used:
ref = commit_sha or branch or "main"   # prefers exact SHA to pin the version
fp  = "/".join(quote(seg) for seg in file_path.lstrip("/").split("/"))  # URL-encode each segment

# By provider:
# GitLab    : https://gitlab.com/group/repo/-/blob/{ref}/{fp}#L{line}
# GitHub    : https://github.com/org/repo/blob/{ref}/{fp}#L{line}-L{lineEnd}
# Bitbucket : https://bitbucket.org/org/repo/src/{ref}/{fp}#lines-{line}
# Azure     : https://dev.azure.com/org/project/_git/repo?path=/{fp}&version=GB{ref}&line={line}
# Gitea     : https://gitea.example.com/user/repo/src/branch/{ref}/{fp}#L{line}
```

This link is computed on the fly in `_to_response()` and is never stored in the database.

---

#### Cron Scheduler (scheduler.py)

`tool/backend/app/utils/scheduler.py` wraps APScheduler's `BackgroundScheduler` to execute rules on a schedule without any external cron daemon.

##### How it works

```
app startup
  └─ scheduler.start()          — starts the BackgroundScheduler thread
  └─ scheduler.sync_all_rules() — reads all Rules from DB
       └─ for each rule with cron_schedule + enabled=True:
            CronTrigger.from_crontab(cron_schedule)
            → _scheduler.add_job(_run_rule_job, trigger, id="rule_{id}")

rule create / PATCH / delete (routers/rules.py)
  └─ scheduler.sync_rule(rule.id, rule.cron_schedule, rule.enabled)
      — removes old job (if any) and registers a new one if applicable
  └─ scheduler.remove_rule(rule.id)  ← only on delete

cron fires
  └─ _run_rule_job(rule_id)
       └─ opens a fresh DB session (SessionLocal())
       └─ re-fetches the rule (checks still enabled)
       └─ iterates all findings — matches_rule() → apply_actions()
       └─ commits, logs count, closes session
```

##### Example cron values

| Schedule | Meaning |
|---|---|
| `0 * * * *` | Every hour |
| `0 6 * * *` | Every day at 06:00 UTC |
| `*/15 * * * *` | Every 15 minutes |
| `0 0 * * 1` | Every Monday at midnight |

The cron is always interpreted in UTC.

---

#### Demo Mode (demo.py)

`tool/backend/app/utils/demo.py` implements the demo mode behaviour: a one-shot and hourly data reset that wipes all findings, scans, and projects and reseeds them with realistic sample data.

##### Activation

`DEMO_MODE=true` in `.env`. On startup, `main.py` calls `reset_and_seed()` directly and registers an hourly APScheduler job via `scheduler.schedule_demo_reset()`.

##### Data flow

```
startup (or cron fires at :00 UTC)
  └─ reset_and_seed()
       ├─ DELETE findings / scans / projects   ← wipes all data
       └─ for each sample in _SAMPLES:
            _parse(parser_key, hint, payload)  ← calls the actual parser
            ingest_findings(db, project, source, parsed, scan_date=now-N_days)
                                               ← same path as real CI/CD ingest
```

##### Sample data

`_SAMPLES` contains 7 scanner payloads across 3 projects, with `days_ago` values ranging from 1 to 25 so the 30-day trend chart is populated:

| Project | Scanner | `days_ago` |
|---|---|---|
| `web-frontend` | Trivy | 25 |
| `backend-api` | GitLab SAST | 20 |
| `backend-api` | GitLab Secrets | 15 |
| `infra` | GitLab IaC | 10 |
| `web-frontend` | OWASP ZAP | 7 |
| `infra` | Nuclei | 3 |
| `backend-api` | Trivy | 1 |

##### API protection

`POST /settings/regenerate-token` and `POST /settings/change-password` check `settings.demo_mode` first and raise `HTTP 403` if true. The check is server-side — the frontend banner is informational only.

---

#### Test Suite

The test suite lives in `tool/backend/tests/` and uses **pytest** with **FastAPI TestClient**. All tests run against an **in-memory SQLite database** — no PostgreSQL, no Docker required.

##### Running tests

```bash
cd tool/backend
pip install -r requirements-test.txt
pytest            # run all tests
pytest -v         # verbose (shows each test name)
pytest tests/test_parsers.py -v    # single file
```

##### Architecture

```
tool/backend/
├── pytest.ini          ← testpaths = tests
└── tests/
    ├── conftest.py         ← fixtures + SQLite DB + pre-authed clients
    ├── test_parsers.py     ← unit tests — parsers
    ├── test_rules_engine.py← unit tests — rules engine operators
    ├── test_auth.py        ← unit + integration — JWT, tokens, login, route protection
    └── test_api.py         ← integration — projects, findings, ingest, rules, stats, settings
```

##### `conftest.py` — shared fixtures

The conftest overrides the production DB dependency with an in-memory SQLite session and seeds the `app_settings` table + `token_cache` directly (the startup event does not run in TestClient):

```python
app.dependency_overrides[get_db] = override_get_db   # SQLite instead of PostgreSQL

# In fresh_db fixture:
db.add(AppSetting(key=SETTING_TOKEN_READ,  value="read-token-for-tests"))
db.add(AppSetting(key=SETTING_TOKEN_WRITE, value="write-token-for-tests"))
db.add(AppSetting(key=SETTING_PASSWORD,    value=pwd_context.hash("testpass")))
token_cache["read"]  = "read-token-for-tests"
token_cache["write"] = "write-token-for-tests"
```

Four client fixtures are available to any test:

| Fixture | Auth method | Use case |
|---|---|---|
| `client` | None | Test unauthenticated requests (expect 401) |
| `authed_client` | JWT (via POST /auth/login) | Standard authenticated tests |
| `read_client` | API read token | Verify GET works, POST blocked |
| `write_client` | API write token | Verify CI/CD ingest flows |

##### `test_parsers.py` — unit tests

Pure functions, no I/O. Tests each parser's `parse(payload) -> list[dict]` function with realistic payloads:

```python
def test_parses_vulnerability(self):
    results = trivy.parse(TRIVY_VULN_PAYLOAD)
    assert results[0]["severity"].value == "HIGH"
    assert results[0]["cve"] == "CVE-2023-44487"
    assert results[0]["cvss_score"] == "7.5"

def test_misconfig_title_includes_id(self):
    results = trivy.parse(TRIVY_MISCONFIG_PAYLOAD)
    assert "DS002" in results[0]["title"]
```

Key cases covered per parser:
- Happy path with realistic payload
- Empty / malformed payload → returns `[]` without raising
- Severity mapping (all levels)
- Parser-specific logic (e.g. Trivy CVSS source priority: NVD V3 > NVD V2 > fallback)

##### `test_rules_engine.py` — unit tests

Uses `MagicMock` objects to simulate `Finding` and `Rule` without any database. Every operator is tested:

```python
def test_regex_match(self):
    f = make_finding(title="CVE-2023-44487 in nghttp2")
    assert _eval_condition(f, {"field": "title", "operator": "regex", "value": r"CVE-\d{4}-\d+"})

def test_invalid_regex_returns_false(self):
    # Must not raise — just return False
    result = _eval_condition(f, {"field": "title", "operator": "regex", "value": "[invalid"})
    assert result is False
```

##### `test_auth.py` — JWT + token + endpoint tests

Covers both the utility functions and the HTTP layer:

```python
# Unit
def test_write_token_allows_all_methods(self):
    for method in ("GET", "POST", "PATCH", "DELETE"):
        assert check_api_token("write-token-for-tests", method)

def test_read_token_allows_get_only(self):
    assert check_api_token("read-token-for-tests", "GET")
    assert not check_api_token("read-token-for-tests", "POST")

# Integration
def test_read_token_blocks_post(self, read_client):
    resp = read_client.post("/api/v1/projects", json={"name": "test"})
    assert resp.status_code == 401
```

##### `test_api.py` — endpoint integration tests

Uses `authed_client` (JWT) to run full request/response cycles against the SQLite DB. Covers: Projects, Findings, Ingest, Rules, Stats, and Settings (tokens + password change).

```python
def test_trivy_ingest_deduplicates(self, authed_client):
    # Ingest same payload twice
    authed_client.post("/api/v1/ingest/trivy?project=p&branch=main&commit=a", json=TRIVY_MINIMAL)
    resp = authed_client.post("/api/v1/ingest/trivy?project=p&branch=main&commit=b", json=TRIVY_MINIMAL)
    assert resp.json()["findings_created"] == 0
    assert resp.json()["findings_updated"] == 1   # ← deduplication confirmed

def test_change_password_success(self, authed_client):
    resp = authed_client.post("/api/v1/settings/change-password", json={
        "current_password": "testpass",
        "new_password": "newsecurepassword",
    })
    assert resp.status_code == 200
```

---

### Frontend

#### File Structure

```
tool/frontend/src/
├── index.jsx              ← Entry point: renders <App /> into the DOM
├── App.jsx                ← BrowserRouter + Routes (URL → Page mapping)
├── index.css              ← Global CSS variables (dark theme, severity colours)
├── api/
│   └── client.js          ← Axios instance + all API call functions
├── context/
│   └── AuthContext.jsx    ← React context: auth state (token, user, login/logout helpers)
├── components/
│   └── Layout.jsx         ← Sidebar + header (shared by all pages)
└── pages/
    ├── Login.jsx          ← Login page (username/password form)
    ├── Dashboard.jsx      ← Main dashboard (3-row KPIs, charts, project dropdown + chips, refresh button)
    ├── Findings.jsx       ← Findings list with filters + CSV/PDF export + refresh button
    ├── FindingDetail.jsx  ← Single finding detail
    ├── Projects.jsx       ← Project management
    ├── ProjectDetail.jsx  ← Project detail + scan history
    ├── Rules.jsx          ← Rules management interface
    ├── Settings.jsx       ← API token management + admin password change
    ├── Docs.jsx           ← Scanner integration guide
    └── Debug.jsx          ← Route health checks + sample data injection (spread over 30 days)
```

#### Theme (index.css)

All colours are CSS variables, defined once. The default theme is inspired by the [Purity UI Dashboard](https://demos.creative-tim.com/purity-ui-dashboard/#/admin/dashboard) created by [Creative Tim](https://creative-tim.com) — a dark navy palette. A **light mode** is available and toggled from the sidebar — it overrides all variables under `[data-theme="light"]` on `document.documentElement`. The preference is persisted in `localStorage` and restored on next load.

```css
:root {
    --bg-base:      #0b1437;   /* deepest background */
    --bg-surface:   #111c44;   /* sidebar, cards */
    --bg-elevated:  rgba(255,255,255,0.05);
    --bg-glass:     linear-gradient(127.09deg, rgba(6,11,40,0.94) 19.41%, rgba(10,14,35,0.49) 76.65%);
    --accent:       #4299e1;   /* primary blue */
    --critical:     #fc8181;
    --high:         #f6ad55;
    --medium:       #f6e05e;
    --low:          #68d391;
    --info:         #63b3ed;
}
```

To change the theme, modify only these variables — all components use them.

#### Findings Filters

The Findings page (`tool/frontend/src/pages/Findings.jsx`) has two complementary filter layers that combine with AND:

**1. Quick-filter chips** — toggle-style pill buttons for common values:
- Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO / UNKNOWN
- Status: OPEN / IN_PROGRESS / CLOSED / ACCEPTED_RISK / FALSE_POSITIVE
- Source: trivy / gitlab_sast / gitlab_iac / gitlab_secrets / owasp_zap / nuclei

Multiple chips within the same category are ORed (e.g. CRITICAL OR HIGH).

**2. Advanced filter groups** — grouped conditions:
- Each group contains one or more `field / operator / value` rows → ORed within the group
- Groups are ANDed together
- The `+ AND group` button adds a new group; `+ OR condition` adds a row to an existing group

The resulting filter is serialised as:
```json
{"groups": [
  {"mode": "or", "conditions": [{"field": "severity", "op": "equals", "value": "CRITICAL"}]},
  {"mode": "or", "conditions": [{"field": "source", "op": "equals", "value": "trivy"}]}
]}
```

This format is parsed by `routers/findings.py` using SQLAlchemy `or_()` within each group and `and_()` between groups.

#### State Management (client.js + React Query)

**`tool/frontend/src/api/client.js`** is the API access layer. It is the **single source of truth** for URLs and parameters.

```javascript
const api = axios.create({
    baseURL: '/api/v1',
    paramsSerializer: {
        // Handles arrays: severity=[CRITICAL, HIGH] → severity=CRITICAL&severity=HIGH
        serialize: (params) => { ... }
    },
})

export const fetchFindings = (params) => api.get('/findings', { params }).then(r => r.data)
export const ingestSample  = (tool, payload, params) => api.post(`/ingest/${tool}`, payload, { params }).then(r => r.data)
```

**TanStack React Query** manages caching and automatic refetches:

```javascript
// In Dashboard.jsx:
const { data: stats, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['dashboard', filterParams],
    queryFn: () => fetchDashboard(filterParams),
    refetchInterval: 60_000,   // auto-refreshes every 60 seconds
})
// Manual refresh button calls refetch()
```

When a mutation succeeds (e.g. updating a finding status), React Query invalidates the relevant queries to force a reload:

```javascript
const mutation = useMutation({
    mutationFn: (data) => updateFinding(id, data),
    onSuccess: () => {
        queryClient.invalidateQueries(['finding', id])    // reload detail
        queryClient.invalidateQueries(['findings'])        // reload list
        queryClient.invalidateQueries(['dashboard'])       // reload stats
    }
})
```

The frontend uses **relative paths** (`/api/v1/...`). In development, Vite proxies `/api` to `http://backend:8000` via `vite.config.js`. In production, Nginx handles the proxy.

#### Debug Page — Sample Data Injection

`Debug.jsx` allows injecting test findings for all 6 scanner types. The `injectAll()` function spreads injections across 7 different dates over the past 30 days (`SPREAD_DAYS = [28, 24, 20, 16, 12, 7, 3]`) by passing a `scan_date` query parameter to the ingest endpoints. This makes the 30-day trend chart on the dashboard representative and non-flat.

---

### Adding a Feature — Practical Guide

#### Adding a New Scanner

1. **Create the parser**: `tool/backend/app/parsers/mytool.py`

```python
def parse(payload: dict) -> list[dict]:
    if not payload:
        return []
    findings = []
    for item in payload.get("results", []):
        findings.append({
            "title": item["name"],
            "severity": SEVERITY_MAP.get(item.get("severity","").upper(), "UNKNOWN"),
            "file_path": item.get("file"),
            "line_start": item.get("line"),
            "component": item.get("package"),
            "tags": ["mytool"],
            "extra_data": item,
        })
    return findings
```

2. **Add the SourceEnum** in `models.py`:
```python
MYTOOL = "mytool"
```

3. **Add the endpoint** in `routers/ingest.py`:
```python
@router.post("/mytool", response_model=IngestResponse)
async def ingest_mytool(payload: Dict[str, Any], project: str = Query(...), ...):
    try:
        parsed = mytool.parse(payload)
        return ingest_findings(db, project, SourceEnum.MYTOOL, parsed, ...)
    except Exception as e:
        logger.exception("MyTool ingest error")
        raise HTTPException(status_code=422, detail="Invalid payload format")
```

4. **Add a sample** in `tool/frontend/src/pages/Debug.jsx` (`SAMPLES` array)

5. **Document** in `OPERATIONS.md` and `tool/frontend/src/pages/Docs.jsx`

#### Adding a New Field to Finding

1. Add the column in `models.py` (`Finding` class)
2. Add a migration in `database.py` → `_migrate()`:
```python
"ALTER TABLE findings ADD COLUMN IF NOT EXISTS my_field VARCHAR(255)"
```
3. Add the field in `schemas.py` (classes `FindingResponse`, and optionally `FindingUpdate`)
4. Update the relevant parser(s) to populate the new field

#### Adding a New Filter to /findings

In `routers/findings.py`, add in two places:
- Parameter in the `list_findings` function
- Condition in the `q` query construction
- And in the `TEXT_COLS` or `ENUM_COLS` section of the advanced filters

#### Modifying a Frontend Page

Each page is self-contained. Typical page structure:

```javascript
export default function MyPage() {
    // 1. Fetch data via React Query
    const { data, isLoading, error, refetch, isFetching } = useQuery({
        queryKey: ['my-resource'],
        queryFn: fetchMyResource,
    })

    // 2. Local UI state (filters, modals, etc.)
    const [filter, setFilter] = useState('')

    // 3. Mutations
    const mutation = useMutation({
        mutationFn: updateResource,
        onSuccess: () => queryClient.invalidateQueries(['my-resource'])
    })

    // 4. Render
    if (isLoading) return <div>Loading...</div>
    return <div>...</div>
}
```

To add an API call: add the function in `tool/frontend/src/api/client.js`.

---

## 7. Navigation Guide — Where to Find What

### "I want to understand how scanner X is parsed"
→ `tool/backend/app/parsers/{scanner}.py`

Each parser is an independent file with a single public function `parse(payload) -> list[dict]`.

| Scanner | File |
|---|---|
| Trivy (image, fs, misconfig, secrets) | `parsers/trivy.py` |
| GitLab SAST / IaC / Secrets | `parsers/gitlab_sast.py` |
| OWASP ZAP | `parsers/owasp_zap.py` |
| Nuclei | `parsers/nuclei.py` |

### "I want to understand an API endpoint"
→ `tool/backend/app/routers/{domain}.py`

| Endpoint | File |
|---|---|
| POST /auth/login, GET /auth/me | `routers/auth.py` |
| GET /settings/tokens, POST /settings/regenerate-token, POST /settings/change-password | `routers/settings.py` |
| POST /ingest/* | `routers/ingest.py` |
| GET/PATCH/DELETE /findings | `routers/findings.py` |
| GET/POST/PATCH/DELETE /projects | `routers/projects.py` |
| GET /stats/dashboard | `routers/stats.py` |
| GET /export/csv, /export/pdf | `routers/export.py` |
| GET/POST/PATCH/DELETE /rules | `routers/rules.py` |

### "I want to see the database structure"
→ `tool/backend/app/models.py` — all tables, columns, enums, relationships  
→ `tool/backend/app/database.py` — automatic migrations on startup

### "I want to see what an endpoint receives / returns"
→ `tool/backend/app/schemas.py` — all Pydantic objects for validation (input) and response (output)

### "I want to modify the auto-triage rules behaviour"
→ `tool/backend/app/utils/rules_engine.py`

### "I want to modify page X of the frontend"
→ `tool/frontend/src/pages/{Page}.jsx`  
→ `tool/frontend/src/api/client.js` for the corresponding API calls

### "I want to change the infrastructure configuration"
→ `tool/docker-compose.yml` — services, volumes, variables  
→ `tool/frontend/nginx.conf` — proxy, TLS, headers  
→ `tool/certs/generate.sh` — TLS certificate generation  
→ `tool/setup.sh` — interactive installation script

### "I'm looking for an environment variable"
→ `tool/.env.example` — full list with default values  
→ `tool/backend/app/config.py` — parsing and validation of variables

---

*W3GathrVulns Training Guide — v0.1.0-beta*
