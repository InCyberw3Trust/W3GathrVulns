from sqlalchemy import create_engine, text, inspect as sa_inspect
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.models import Base, AppSetting
from passlib.context import CryptContext
import logging
import secrets

logger = logging.getLogger(__name__)

_is_sqlite = settings.database_url.startswith("sqlite")
engine = create_engine(
    settings.database_url,
    pool_pre_ping=not _is_sqlite,
    **({} if _is_sqlite else {"pool_size": 10, "max_overflow": 20}),
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)  # bind= still valid in SQLAlchemy 2.x

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Settings keys stored in DB
SETTING_TOKEN_READ  = "api_token_read"
SETTING_TOKEN_WRITE = "api_token_write"
SETTING_PASSWORD    = "ui_password_hash"


def init_db():
    _ensure_pg_enums()
    existing = set(sa_inspect(engine).get_table_names())
    new_tables = [t for t in Base.metadata.sorted_tables if t.name not in existing]
    if new_tables:
        try:
            Base.metadata.create_all(engine, tables=new_tables)
        except Exception as e:
            logger.warning(f"create_all skipped (race between workers, tables already exist): {str(e)[:80]}")
    _migrate()
    _seed_settings()


def _ensure_pg_enums():
    """No-op: all enum columns now use native_enum=False (VARCHAR storage).
    PostgreSQL native enum types are no longer created or required.
    """
    pass


def _migrate():
    """Idempotent migrations — safe to run on every startup."""
    migrations = [
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS extra_data JSONB",
        "ALTER TABLE rules ADD COLUMN IF NOT EXISTS cron_schedule VARCHAR(100)",
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS short_id BIGINT",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS git_provider VARCHAR(50)",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS default_branch VARCHAR(255) DEFAULT 'main'",
        # Convert git_provider from native enum type to VARCHAR (native_enum=False)
        "ALTER TABLE projects ALTER COLUMN git_provider TYPE VARCHAR(50) USING git_provider::TEXT",
        # Create sequence if not exists (idempotent via DO block)
        """
        DO $$ BEGIN
            CREATE SEQUENCE IF NOT EXISTS finding_short_id_seq START 1;
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """,
        # Backfill short_id for existing findings that don't have one
        """
        UPDATE findings SET short_id = nextval('finding_short_id_seq')
        WHERE short_id IS NULL
        """,
        # Set column DEFAULT so new findings get short_id automatically on INSERT
        "ALTER TABLE findings ALTER COLUMN short_id SET DEFAULT nextval('finding_short_id_seq')",
        # Add unique index if not exists
        """
        DO $$ BEGIN
            CREATE UNIQUE INDEX IF NOT EXISTS ix_findings_short_id ON findings(short_id);
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """,
        # Convert native PostgreSQL enum columns to VARCHAR (native_enum=False)
        "ALTER TABLE scans ALTER COLUMN source TYPE VARCHAR(50) USING source::TEXT",
        "ALTER TABLE findings ALTER COLUMN source TYPE VARCHAR(50) USING source::TEXT",
        "ALTER TABLE findings ALTER COLUMN severity TYPE VARCHAR(50) USING severity::TEXT",
        "ALTER TABLE findings ALTER COLUMN status TYPE VARCHAR(50) USING status::TEXT",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql.strip()))
                conn.commit()
            except Exception as e:
                logger.warning(f"Migration note: {str(e)[:80]}")


def _seed_settings():
    """
    On first startup, import token and password values from .env into the DB.
    Each setting is seeded in its own transaction to be race-safe when multiple
    uvicorn workers call init_db() simultaneously.
    Subsequent startups are no-ops for keys that already exist.
    """
    def _ensure(key: str, value: str):
        db = SessionLocal()
        try:
            if not db.query(AppSetting).filter(AppSetting.key == key).first():
                db.add(AppSetting(key=key, value=value))
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    _ensure(SETTING_TOKEN_READ,  settings.api_token_read  or _gen_token())
    _ensure(SETTING_TOKEN_WRITE, settings.api_token_write or _gen_token())
    _ensure(SETTING_PASSWORD,    pwd_context.hash(settings.ui_password))
    logger.info("App settings seeded / verified.")


def _gen_token(length: int = 48) -> str:
    return secrets.token_urlsafe(length)


def get_setting(key: str) -> str | None:
    """Read a single setting from DB (opens its own session)."""
    db = SessionLocal()
    try:
        row = db.query(AppSetting).filter(AppSetting.key == key).first()
        return row.value if row else None
    finally:
        db.close()


def set_setting(db, key: str, value: str):
    """Upsert a setting within an existing session."""
    row = db.query(AppSetting).filter(AppSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSetting(key=key, value=value))


def verify_password(plain: str) -> bool:
    """Verify a plain password against the DB-stored bcrypt hash.

    Returns False (never raises) if the stored value is missing, not a valid
    bcrypt hash (e.g. plain text from an old seed), or any other error.
    """
    pw_hash = get_setting(SETTING_PASSWORD)
    if not pw_hash:
        return False
    try:
        return pwd_context.verify(plain, pw_hash)
    except Exception:
        # Stored value is not a valid hash — re-seed it on next successful login
        return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
