"""Application configuration.

Settings are read from environment variables so that the deployed Lambda is
configured entirely by Terraform and no secrets live in source control.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the support API."""

    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    # --- General -----------------------------------------------------------
    environment: str = "local"
    service_name: str = "ticket-api"
    debug: bool = True

    # --- Identity ----------------------------------------------------------
    # "header"  -> read identity from request headers (used for local dev)
    # "gateway" -> read identity from the API Gateway JWT authorizer context
    identity_source: str = "header"

    # --- Storage -----------------------------------------------------------
    table_name: str = "support-platform-local"
    aws_region: str = "us-east-1"
    dynamodb_endpoint_url: str | None = None

    # --- API behaviour -----------------------------------------------------
    default_page_size: int = 25
    cors_allow_origins: str = "*"

    # --- Logging -----------------------------------------------------------
    log_level: str = "DEBUG"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings so every module sees one consistent view."""
    return Settings()
