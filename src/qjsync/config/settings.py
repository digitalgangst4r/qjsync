"""Secrets and runtime endpoints, loaded from the environment only.

Nothing in here belongs in the versionable ``rules.yml``. Values come from real
environment variables or a local ``.env`` (gitignored). See ``.env.example``.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Secrets(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Qualys ---
    qualys_username: str = Field(..., alias="QUALYS_USERNAME")
    qualys_password: str = Field(..., alias="QUALYS_PASSWORD")
    # Platform API root, e.g. https://qualysapi.qg2.apps.qualys.com (NO trailing /api).
    qualys_api_url: str = Field(..., alias="QUALYS_API_URL")

    # --- Jira (optional: not required when jira.enabled is false in rules.yml) ---
    jira_base_url: str | None = Field(None, alias="JIRA_BASE_URL")
    jira_email: str | None = Field(None, alias="JIRA_EMAIL")
    jira_api_token: str | None = Field(None, alias="JIRA_API_TOKEN")

    # --- State store ---
    database_url: str = Field(
        "postgresql+psycopg://qjsync:qjsync@localhost:5432/qjsync",
        alias="QJSYNC_DATABASE_URL",
    )
