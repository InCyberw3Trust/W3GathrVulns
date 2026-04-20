from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings
from app.database import init_db
from app.routers import ingest, findings, projects, stats, export, rules
from app.routers import auth as auth_router
from app.routers import settings as settings_router
from app.utils import scheduler
from app.utils.auth import verify_token, check_api_token, is_public, reload_token_cache
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ── Auth middleware ───────────────────────────────────────────────────────────

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if is_public(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)

        token = auth_header.removeprefix("Bearer ").strip()

        # Valid JWT (UI session) → full access
        if verify_token(token):
            return await call_next(request)

        # Valid API token → read or read+write based on HTTP method
        if check_api_token(token, request.method):
            return await call_next(request)

        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="W3GathrVulns API",
    description="Security findings management platform",
    version="0.1.0-beta",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuthMiddleware)


@app.on_event("startup")
def startup():
    init_db()                  # creates tables, runs migrations, seeds settings
    reload_token_cache()       # load API tokens from DB into memory
    scheduler.start()
    scheduler.sync_all_rules()
    if settings.demo_mode:
        from app.utils.demo import reset_and_seed
        reset_and_seed()
        scheduler.schedule_demo_reset()
        logger.info("Demo mode active — data reset on startup and scheduled hourly")


@app.on_event("shutdown")
def shutdown():
    scheduler.stop()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "w3gathrvulns-api", "version": "0.1.0-beta"}


@app.get("/api/v1/app-config")
def app_config():
    return {"demo_mode": settings.demo_mode}


prefix = settings.api_prefix
app.include_router(auth_router.router,     prefix=prefix)
app.include_router(settings_router.router, prefix=prefix)
app.include_router(ingest.router,          prefix=prefix)
app.include_router(findings.router,    prefix=prefix)
app.include_router(projects.router,    prefix=prefix)
app.include_router(stats.router,       prefix=prefix)
app.include_router(export.router,      prefix=prefix)
app.include_router(rules.router,       prefix=prefix)
