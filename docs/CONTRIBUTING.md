# Contributing to W3GathrVulns

W3GathrVulns is a community tool. All contributions are welcome — whether it's a bug fix, a new scanner parser, a UI improvement, or documentation.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Ways to Contribute](#ways-to-contribute)
3. [Development Setup](#development-setup)
4. [Project Structure](#project-structure)
5. [Running Tests](#running-tests)
6. [Adding a New Scanner Parser](#adding-a-new-scanner-parser)
7. [Submitting a Pull Request](#submitting-a-pull-request)
8. [Reporting Bugs](#reporting-bugs)
9. [Security Vulnerabilities](#security-vulnerabilities)

---

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/w3gathrvulns.git`
3. Create a branch: `git checkout -b feature/my-feature`
4. Make your changes, test them, open a pull request

---

## Ways to Contribute

- **Bug fixes** — anything in the issue tracker labelled `bug`
- **New scanner parsers** — add support for a tool not yet supported (Grype, Burp Suite…)
- **Roadmap features** — pick an item from the roadmap in [README.md](../README.md)
- **Documentation** — improve OPERATIONS.md, ARCHITECTURE.md, or inline comments
- **Tests** — add unit tests for parsers or the rules engine
- **UI improvements** — React components, accessibility, performance
- **Bug reports and feature requests** — open an issue

---

## Development Setup

### Requirements

- Docker & Docker Compose v2
- Python 3.12+ (for local backend dev)
- Node.js 20+ (for local frontend dev)

### Full stack (Docker)

```bash
cd tool/
bash setup.sh        # generates .env
docker compose up -d --build
```

### Backend only (hot reload)

See [OPERATIONS.md — Development](OPERATIONS.md) for the full setup commands (virtual environment, local PostgreSQL, environment variables, uvicorn with `--reload`).

### Frontend only (Vite dev server)

```bash
cd tool/frontend
npm install
npm run dev        # starts on http://localhost:3000
```

Vite proxies `/api` to `http://backend:8000` — you need the backend running.

---

## Running Tests

Tests use an **in-memory SQLite database** — no PostgreSQL or Docker required.

```bash
cd tool/backend
pip install -r requirements-test.txt
pytest
```

See [FORMATION.md](FORMATION.md) for a description of each test file, available fixtures, and guidance on writing new tests for parsers, the rules engine, and API endpoints.

Every PR that adds a new parser or endpoint should include at least one test.

---

## Project Structure

```
tool/
├── backend/app/
│   ├── routers/        # API endpoints (one file per domain: auth, settings, ingest, findings, projects, stats, export, rules)
│   ├── parsers/        # Scanner-specific parsers (one file per tool)
│   ├── utils/          # Rules engine, scheduler, git link builder, auth (JWT + token cache)
│   ├── models.py       # SQLAlchemy ORM models
│   └── schemas.py      # Pydantic request/response schemas
└── frontend/src/
    ├── pages/          # One React component per route
    ├── components/     # Shared components (Layout.jsx — sidebar + shell)
    └── api/client.js   # Axios client + all API helpers (auth interceptor, exportFile)
```

---

## Adding a New Scanner Parser

This is one of the most valuable contributions. Each parser lives in `tool/backend/app/parsers/`.

### Steps

1. **Create the parser** — `tool/backend/app/parsers/mytool.py` with a single public function `parse(payload: dict) -> list[dict]`. The function iterates the scanner output and returns a list of normalised dicts, one per finding. Each dict key must match a `Finding` column name. See [FORMATION.md](FORMATION.md) — section 9 and section 15 for a detailed code walkthrough and template.

2. **Add the source enum** — in `tool/backend/app/models.py`, add `MYTOOL = "mytool"` to `SourceEnum`.

3. **Add the ingest endpoint** — in `tool/backend/app/routers/ingest.py`, add a `POST /mytool` endpoint that calls the parser and passes results to the shared `ingest_findings()` helper. See section 15 of [FORMATION.md](FORMATION.md) for the full endpoint template.

4. **Add a sample payload** — in `tool/frontend/src/pages/Debug.jsx`, add an entry to the `SAMPLES` array so the Debug page can inject test data.

5. **Document it** — add a section in `OPERATIONS.md` under "Integrating Scanners" and update `tool/frontend/src/pages/Docs.jsx`.

### Parser guidelines

- Return an empty list rather than raising on empty/invalid input
- Use `logger.warning()` to log skipped items, never silently swallow errors
- Map severity to `CRITICAL / HIGH / MEDIUM / LOW / INFO / UNKNOWN`
- Store the raw item in `extra_data` so no data is lost
- Keep the parser stateless and side-effect free (no DB access)

---

## Submitting a Pull Request

1. Make sure the project builds: `cd tool && docker compose up -d --build`
2. Verify your change with the Debug page (`/debug`) — run health checks and inject sample data
3. Keep PRs focused: one feature or fix per PR
4. Write a clear PR description: what it does, why, how to test it
5. Reference any related issue: `Closes #42`

### PR title convention

```
feat: add Grype parser
fix: deduplicate IaC findings by line number
docs: add Nuclei JSONL conversion example
refactor: extract severity mapping to shared util
```

---

## Reporting Bugs

Open an issue with:

- W3GathrVulns version (shown at `/api/health`)
- Steps to reproduce
- Expected vs actual behaviour
- Relevant logs (`docker compose logs backend`)

---

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities.

Please report them privately by email at **inimzil.pro@gmail.com** or via the repository's private vulnerability reporting feature (if enabled). Include a description of the issue, steps to reproduce, and potential impact.

I will respond as soon as I can.

---

Thank you for contributing to W3GathrVulns.
