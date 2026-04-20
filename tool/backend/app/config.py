from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List


class Settings(BaseSettings):
    # Obligatoires — doivent être dans .env ou variables d'environnement
    # No default value — application refuses to start if missing (intentional)
    database_url: str
    secret_key: str

    # Optional with safe defaults
    api_prefix: str = "/api/v1"
    cors_origins: List[str] = ["http://localhost"]
    debug: bool = False

    # ── Authentication ────────────────────────────────────────────────────────
    # UI credentials (web login)
    ui_username: str = "admin"
    ui_password: str = "CHANGE_ME"
    # API tokens for CI/CD integrations
    # api_token_read  : GET-only access (dashboards, exports)
    # api_token_write : full access (ingest, mutations)
    api_token_read:  str = ""
    api_token_write: str = ""
    # JWT session duration (hours)
    jwt_expire_hours: int = 24

    # ── Demo mode ─────────────────────────────────────────────────────────────
    # When true: disables token/password mutations and resets data hourly
    demo_mode: bool = False

    @field_validator("secret_key")
    @classmethod
    def secret_key_must_not_be_default(cls, v: str) -> str:
        insecure = {"change-me-in-production-very-secret-key", "change-me-in-production", "changeme", "secret"}
        if v.lower() in insecure or len(v) < 32:
            raise ValueError(
                "SECRET_KEY is insecure or too short (min 32 chars). "
                "Run ./setup.sh to generate a secure key."
            )
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
