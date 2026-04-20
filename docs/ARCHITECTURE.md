# Architecture — W3GathrVulns

W3GathrVulns is a self-hosted security findings management platform. It aggregates vulnerability reports from multiple security scanners into a single dashboard, with deduplication, auto-triage rules, and export capabilities.

---

## Table of Contents

1. [Overview](#overview)
2. [Infrastructure](#infrastructure)
3. [Technology Stack](#technology-stack)
4. [Directory Structure](#directory-structure)
5. [Backend](#backend)
6. [Frontend](#frontend)
7. [Database Schema](#database-schema)
8. [Data Flow](#data-flow)
9. [Security Model](#security-model)

---

## Overview

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │  CI/CD Pipelines                                                                 │
 │                                                                                  │
 │  Trivy   GitLab SAST   GitLab IaC   GitLab Secrets   OWASP ZAP   Nuclei         │
 └────────────────────────────┬────────────────────────────────────────────────────┘
                              │  POST /api/v1/ingest/{tool}
                              │  ?project=&branch=&commit=&pipeline=
                              │
 ┌────────────────────────────▼────────────────────────────────────────────────────┐
 │  Docker Compose                                                                  │
 │                                                                                  │
 │  ┌───────────────────────────────────────────────────────────────────────────┐   │
 │  │  frontend  (Nginx alpine — ports 80/443)                                  │   │
 │  │                                                                           │   │
 │  │   :80  ──► redirect 301 ──► :443                                          │   │
 │  │                                                                           │   │
 │  │   :443  /api/*  ──► proxy_pass http://backend:8000  (timeout 120s, 50MB) │   │
 │  │         /*      ──► React SPA (try_files → index.html)                   │   │
 │  │                                                                           │   │
 │  │   React 19 + Vite  │  TanStack Query  │  Recharts  │  Axios              │   │
 │  │   pages: Dashboard · Findings · Projects · Rules · Settings · Docs · Debug│   │
 │  └───────────────────────────────────┬───────────────────────────────────────┘  │
 │                                      │  http://backend:8000                      │
 │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │
 │  │  backend  (Python 3.12-slim — internal port 8000)                         │  │
 │  │                                                                            │  │
 │  │  FastAPI 0.111  ·  Uvicorn (2 workers)  ·  SQLAlchemy 2.0  ·  Pydantic v2│  │
 │  │                                                                            │  │
 │  │  Routers (8)                   Parsers (4)           Utils                │  │
 │  │  ├─ /auth (login · me)         ├─ trivy.py           ├─ rules_engine.py   │  │
 │  │  ├─ /settings (tokens · pw)    ├─ gitlab_sast.py     ├─ git_links.py      │  │
 │  │  ├─ /ingest/{tool}             ├─ owasp_zap.py       ├─ scheduler.py      │  │
 │  │  ├─ /findings                  └─ nuclei.py           └─ demo.py          │  │
 │  │  ├─ /projects                                                             │  │
 │  │  ├─ /stats/dashboard                                                      │  │
 │  │  ├─ /export (csv · pdf)                                                   │  │
 │  │  └─ /rules                                                                │  │
 │  └───────────────────────────────────┬───────────────────────────────────────┘  │
 │                                      │  SQLAlchemy ORM (pool_size=10)            │
 │  ┌───────────────────────────────────▼───────────────────────────────────────┐  │
 │  │  db  (postgres:16-alpine — internal port 5432)                            │  │
 │  │                                                                            │  │
 │  │  tables:  projects · scans · findings · rules · app_settings              │  │
 │  │  volume:  postgres_data (persistent)                                      │  │
 │  └───────────────────────────────────────────────────────────────────────────┘  │
 │                                                                                  │
 │  ┌─────────────────────────────────┐                                            │
 │  │  certs  (alpine/openssl)        │  ← init container, runs once then exits   │
 │  │  generates w3gathrvulns.crt/key │  ← mounted read-only into frontend        │
 │  └─────────────────────────────────┘                                            │
 │                                                                                  │
 │  Startup order:  certs ──► db (healthy) ──► backend (healthy) ──► frontend      │
 └─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Infrastructure

### Docker Compose Services

Services start in dependency order:

```
certs (init) → db (healthy) → backend (healthy) → frontend
```

| Service | Image | Ports | Notes |
|---|---|---|---|
| `certs` | alpine/openssl | — | Generates self-signed cert once, then exits |
| `db` | postgres:16-alpine | 5432 (internal) | Persistent volume `postgres_data` |
| `backend` | custom (Python 3.12) | 8000 (internal) | 2 Uvicorn workers |
| `frontend` | custom (Nginx alpine) | 80, 443 | Serves React + proxies `/api/*` |

### Nginx

- HTTP (80) → permanent redirect to HTTPS (443)
- `location /api/` → `proxy_pass http://backend:8000` (timeout 120s, max body 50MB)
- `location /` → React SPA with `try_files` fallback to `index.html`

### TLS

Self-signed certificate generated by `tool/certs/generate.sh` using `SERVER_IP` for the Subject Alternative Name. Valid for 10 years. For production, replace with a certificate from a trusted CA.

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Backend | FastAPI + Uvicorn | 0.111 / 0.29 |
| ORM | SQLAlchemy | 2.0 |
| Database | PostgreSQL | 16 |
| Scheduler | APScheduler (BackgroundScheduler) | 3.10 |
| Frontend | React + Vite | 19 / 8+ |
| State management | TanStack React Query | 5 |
| Charts | Recharts | 3 |
| Styling | Plain CSS variables (Purity UI, dark + light theme toggle) | — |
| Reverse proxy | Nginx | alpine |
| Containerization | Docker Compose | v2 |

---

## Directory Structure

```
w3gathrvulns/
├── README.md
├── .gitlab-ci.yml                  # CI/CD pipeline (scan + upload to self)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── OPERATIONS.md
│   ├── CONTRIBUTING.md
│   └── FORMATION.md
└── tool/
    ├── docker-compose.yml
    ├── .env.example
    ├── .gitignore
    ├── setup.sh                    # Interactive setup (generates .env with secrets)
    ├── certs/
    │   └── generate.sh             # Self-signed TLS certificate (alpine/openssl)
    ├── backend/
    │   ├── Dockerfile              # Python 3.12-slim
    │   ├── requirements.txt        # Production dependencies
    │   ├── requirements-test.txt   # Test dependencies (SQLite-compatible, no psycopg2)
    │   ├── pytest.ini
    │   ├── tests/
    │   │   ├── conftest.py         # SQLite DB + pre-authed test clients
    │   │   ├── test_parsers.py     # Unit tests — all 4 parsers
    │   │   ├── test_rules_engine.py# Unit tests — rules engine operators
    │   │   ├── test_auth.py        # Unit + integration — JWT, tokens, login, route protection
    │   │   └── test_api.py         # Integration — projects, findings, ingest, rules, stats, settings
    │   └── app/
    │       ├── main.py             # FastAPI entry point, CORS, router registration, scheduler
    │       ├── config.py           # Settings via Pydantic BaseSettings (.env)
    │       ├── database.py         # SQLAlchemy engine, session, idempotent migrations
    │       ├── models.py           # ORM models: Project, Scan, Finding, Rule, AppSetting + enums
    │       ├── schemas.py          # Pydantic request/response schemas
    │       ├── routers/
    │       │   ├── auth.py         # POST /auth/login, GET /auth/me
    │       │   ├── settings.py     # GET /settings/tokens, POST /settings/regenerate-token + change-password
    │       │   ├── ingest.py       # POST /ingest/{trivy,gitlab-sast,gitlab-iac,...}
    │       │   ├── findings.py     # GET/PATCH/DELETE /findings (grouped AND/OR filters)
    │       │   ├── projects.py     # GET/POST/PATCH/DELETE /projects
    │       │   ├── stats.py        # GET /stats/dashboard
    │       │   ├── export.py       # GET /export/csv, /export/pdf
    │       │   └── rules.py        # GET/POST/PATCH/DELETE /rules + /apply + /run-scheduled
    │       ├── parsers/
    │       │   ├── trivy.py        # Trivy (image, fs, misconfig, secrets)
    │       │   ├── gitlab_sast.py  # GitLab SAST / IaC (KICS) / Secrets (Gitleaks)
    │       │   ├── owasp_zap.py    # OWASP ZAP
    │       │   └── nuclei.py       # Nuclei (JSONL wrapped as array)
    │       └── utils/
    │           ├── auth.py         # JWT creation/verification + in-memory token cache
    │           ├── rules_engine.py # Condition matching + action application
    │           ├── scheduler.py    # APScheduler — executes rule cron jobs + demo reset in background
    │           ├── git_links.py    # Provider-specific file URL builder
    │           └── demo.py         # Demo mode: sample payloads + hourly wipe-and-reseed
    └── frontend/
        ├── Dockerfile              # Multi-stage: Node 20 build → Nginx alpine serve
        ├── nginx.conf              # HTTP→HTTPS redirect, /api proxy, SPA fallback
        ├── index.html
        ├── vite.config.js
        ├── package.json
        └── src/
            ├── index.jsx           # React entry point
            ├── index.css           # CSS variables — dark (default) + light theme overrides
            ├── App.jsx             # BrowserRouter + route definitions
            ├── api/
            │   └── client.js       # Axios instance + all API call helpers (auth interceptor, exportFile)
            ├── context/
            │   └── AuthContext.jsx # React context for auth state (token, user)
            ├── components/
            │   └── Layout.jsx      # Sidebar (logo, nav, theme toggle, logout) + shared shell
            └── pages/
                ├── Login.jsx          # Login page (username/password)
                ├── Settings.jsx       # API token management + password change
                ├── Dashboard.jsx      # 3-row KPIs, charts, project dropdown + severity/status/source chips
                ├── Findings.jsx       # Chips + grouped AND/OR filters + paginated table
                ├── FindingDetail.jsx  # Single finding detail + edit status/severity/notes
                ├── Projects.jsx       # Project list + create/delete
                ├── ProjectDetail.jsx  # Project detail + scan history
                ├── Rules.jsx          # Rule builder + simulate + apply interface
                ├── Docs.jsx           # Scanner integration guide + integration examples
                └── Debug.jsx          # Route health checks + sample data injection
```

---

## Backend

### Entry Point

`tool/backend/app/main.py` creates the FastAPI application, registers CORS and `AuthMiddleware`, runs `init_db()` and `reload_token_cache()` on startup, starts the APScheduler, and mounts 8 routers under `/api/v1`.

### Authentication Middleware

`AuthMiddleware` intercepts every request before it reaches any router. Public paths (`/api/health`, `/api/docs`, `/api/v1/auth/login`) are exempt. All other requests must carry `Authorization: Bearer <token>` where the token is either:
- A valid JWT (issued by `POST /api/v1/auth/login`, used by the web UI)
- The write API token (full access to all methods)
- The read API token (GET requests only)

Tokens are validated exclusively against the in-memory `token_cache` (loaded from the `app_settings` DB table at startup). The `.env` values are consumed once at first startup to seed the DB — they are never used for runtime authentication.

### Routers

| Router | Prefix | Purpose |
|---|---|---|
| `auth` | `/api/v1/auth` | Login (`POST /login`) and session validation (`GET /me`) |
| `settings` | `/api/v1/settings` | Token management + password change |
| `ingest` | `/api/v1/ingest` | Receive scan payloads from CI/CD |
| `findings` | `/api/v1/findings` | CRUD, filters, batch updates |
| `projects` | `/api/v1/projects` | Project management + scan history |
| `stats` | `/api/v1/stats` | Dashboard aggregations (filterable by project, severity, status, source) |
| `export` | `/api/v1/export` | CSV and PDF report generation |
| `rules` | `/api/v1/rules` | Auto-triage rule management |

### Parsers

Each parser in `tool/backend/app/parsers/` converts a scanner's JSON output into a normalized list of finding dictionaries that the ingest router stores.

| Parser | Scanner | Notes |
|---|---|---|
| `trivy.py` | Trivy | Image, filesystem, misconfig, secrets; prefers NVD V3 CVSS; misconfig titles prefixed with rule ID |
| `gitlab_sast.py` | GitLab SAST / IaC / Secrets | Auto-detects report type from payload |
| `owasp_zap.py` | OWASP ZAP | Extracts HTTP method, URL, parameter |
| `nuclei.py` | Nuclei | JSONL wrapped as array; one finding per matcher |

**Adding a new scanner**: create `tool/backend/app/parsers/mytool.py` with a `parse(payload) -> list[dict]` function, add a router endpoint in `routers/ingest.py`, and add the source to `SourceEnum` in `models.py`.

### Deduplication

On every ingest, before creating a finding, the backend checks for an existing finding with the same project, title, source, and file path (plus line number when present).

- `line_start` is always included when present. This is critical for IaC (KICS), where the same rule can fire at multiple lines in the same file — each line is a distinct instance.
- Findings with `status = FALSE_POSITIVE` are excluded from the dedup match (they stay untouched).
- On match: updates `last_seen`, merges tags, fills missing CVE/CVSS/fixed_version.
- No match: creates a new Finding.

### Rules Engine

`tool/backend/app/utils/rules_engine.py`

Rules are evaluated against each finding after ingest (and on manual trigger). A rule matches when its conditions are satisfied, then its actions are applied.

**Condition fields**: `title`, `source`, `vuln_id`, `cve`, `severity`, `status`, `file_path`, `component`, `tags`, `description`

**Operators**: `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `in`, `regex`

**Conditions mode**: `all` (AND) or `any` (OR)

**Actions**: `set_status`, `set_severity`

Rules are applied in ascending priority order. All enabled rules are evaluated (not first-match-only). Regex patterns are validated at rule creation time.

### Cron Scheduler

`tool/backend/app/utils/scheduler.py`

An APScheduler `BackgroundScheduler` runs inside the FastAPI process. Each `Rule` with a non-null `cron_schedule` (standard 5-field cron, e.g. `0 * * * *`) gets a dedicated background job. The scheduler:

- Starts on app startup and loads all rules from DB (`sync_all_rules()`)
- Re-syncs automatically when a rule is created, updated, or deleted via the API
- Runs each job in a background thread with its own database session
- Logs the number of findings changed per execution

The `/api/v1/rules/run-scheduled` endpoint still exists for external triggers (e.g. a Kubernetes CronJob calling the endpoint instead of relying on the in-process scheduler).

---

## Frontend

A single-page application built with React 19 and Vite. Styled with plain CSS variables — a theme inspired by the [Purity UI Dashboard](https://demos.creative-tim.com/purity-ui-dashboard/#/admin/dashboard) by [Creative Tim](https://creative-tim.com), with dark (default) and light modes toggled from the sidebar and persisted to `localStorage` (no CSS framework).

### Routing (`tool/frontend/src/App.jsx`)

| Route | Page | Description |
|---|---|---|
| `/login` | `Login.jsx` | Login page — redirects to dashboard after successful auth |
| `/settings` | `Settings.jsx` | View/regenerate API tokens, change admin password |
| `/dashboard` | `Dashboard.jsx` | 3-row KPIs (summary · status detail · open by severity), trend, donuts, severity×project stacked bar, project dropdown + chips |
| `/findings` | `Findings.jsx` | Quick-filter chips + grouped AND/OR filters + paginated table + batch actions |
| `/findings/:id` | `FindingDetail.jsx` | Full finding detail, edit status/severity/notes |
| `/projects` | `Projects.jsx` | Project list with stats, create/delete |
| `/projects/:id` | `ProjectDetail.jsx` | Scan history, severity distribution |
| `/rules` | `Rules.jsx` | Rule builder with condition/action UI, simulate and apply |
| `/docs` | `Docs.jsx` | Integration guide with CI/CD code examples |
| `/debug` | `Debug.jsx` | Route health checks + sample data injection (spread over 30 days) |

### State Management

Server state is managed by **TanStack React Query** (caching, background refetch). Local UI state (filters, form inputs, modals) uses React `useState`. Filter state persists to `sessionStorage` so it survives navigation.

### Token Storage

API tokens and the admin password hash are stored in the `app_settings` DB table (key/value pairs) rather than in `.env`. On first startup, `_seed_settings()` imports values from `.env` into the DB if no DB values exist yet. After that, the DB is authoritative — changes made via the Settings page persist across restarts without touching `.env`.

The auth middleware loads tokens into an in-memory dict (`token_cache`) at startup and after any regeneration, so there is no DB hit per request.

### API Client

`tool/frontend/src/api/client.js` is the single Axios instance for all API calls. It handles array parameter serialization for multi-value filters.

---

## Database Schema

### Tables

| Table | Key Columns | Notes |
|---|---|---|
| `projects` | `id` (UUID PK), `name` (unique), `repository_url`, `git_provider`, `default_branch` | Auto-created on first ingest |
| `scans` | `id` (UUID PK), `project_id` (FK), `source`, `branch`, `commit_sha`, `pipeline_id`, `scan_date`, `findings_count`, `raw_payload` (JSON) | One record per scanner execution |
| `findings` | `id` (UUID PK), `short_id` (auto-increment), `project_id` (FK), `scan_id` (FK), `title`, `severity`, `status`, `source`, `vuln_id`, `cve`, `cvss_score`, `file_path`, `line_start`, `component`, `fixed_version`, `url`, `method`, `tags`, `notes`, `first_seen`, `last_seen`, `extra_data` (JSONB), `raw_data` (JSON) | Central table — all normalised findings |
| `rules` | `id` (UUID PK), `name`, `enabled`, `priority`, `conditions` (JSON), `conditions_mode`, `actions` (JSON), `cron_schedule`, `applied_count`, `last_applied_at` | Auto-triage rules |
| `app_settings` | `key` (PK), `value` | Stores read/write tokens and bcrypt password hash; authoritative after first startup |

### Indexes

`findings(project_id, severity)`, `findings(status)`, `findings(source)`, `findings(short_id)` (unique), `scans(project_id, source)`

### Migrations

Applied idempotently at startup via `init_db()` in `database.py` — safe to run on every restart. No manual migration steps required.

---

## Data Flow

### Ingest (CI/CD → Dashboard)

1. Scanner runs in CI and outputs a JSON report
2. CI pipeline sends a `POST /api/v1/ingest/{tool}` with the JSON body and query params (`project`, `branch`, `commit`, `pipeline`, optionally `scan_date` for backfill)
3. The matching parser extracts normalised finding dicts from the payload
4. The project is looked up or created (`get_or_create_project`)
5. A `Scan` record is created (with `scan_date` override if provided)
6. For each finding: deduplication query runs; existing findings are updated (`last_seen`, merged fields), new ones are inserted. If `scan_date` is set, `first_seen` / `last_seen` are overridden
7. All enabled rules are applied in priority order
8. Everything is committed in a single transaction
9. Returns `IngestResponse` with counts: `findings_created`, `findings_updated`, `rules_applied`

### Dashboard Stats Query

The `GET /api/v1/stats/dashboard` endpoint accepts optional filter params (`severity`, `status`, `source`, `project_id`). A shared base query applies all filters, and every aggregation — KPIs, breakdowns, 30-day trend, top projects, severity × project stacked bar — runs against the same filtered scope. The response is a single `DashboardStats` object.

### Finding Query (UI → API)

`GET /api/v1/findings` supports pagination, text search, quick-filter params (`severity`, `status`, `source`, `project_id`), and an advanced `filters` JSON param with grouped AND/OR conditions. A `git_file_url` is computed per finding at serialisation time (never stored). Returns a paginated `FindingListResponse`.

---

## Security Model

W3GathrVulns is designed as an **internal network tool** with authentication baked in.

**Authentication model**:
- All endpoints (except `/api/health`, `/api/docs`, and `/api/v1/auth/login`) require `Authorization: Bearer <token>`
- Web UI sessions use short-lived JWTs (default 24h) issued by `POST /api/v1/auth/login`
- CI/CD pipelines use static bearer tokens: `API_TOKEN_WRITE` (full access) or `API_TOKEN_READ` (GET only)
- Tokens and the password hash are stored in the `app_settings` DB table and managed via the Settings page without restart
- `AuthMiddleware` intercepts every request before routing; tokens are cached in memory after load

**Implemented protections**:
- TLS for all traffic (HTTPS only, HTTP redirects to HTTPS)
- `SECRET_KEY` minimum length and common-value validation at startup
- CORS origins explicitly configured (no wildcard with credentials)
- Input validation on all API inputs via Pydantic schemas
- Regex patterns validated at rule creation time (prevents ReDoS)
- Passwords stored as bcrypt hashes; `verify_password` never raises on invalid stored values
- Login and API token checks use DB values only — no `.env` fallback at runtime
- Error responses return generic messages (internal details logged server-side only)

**Known limitations**:
- Single admin account — no multi-user or RBAC
- No rate limiting on API endpoints
- The `DELETE /api/v1/ingest/reset` endpoint wipes all data with only a query parameter confirmation
- No audit logging of mutations
