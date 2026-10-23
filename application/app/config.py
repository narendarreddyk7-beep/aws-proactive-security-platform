"""Application configuration.

Settings come from environment variables so that the deployed Lambda is
configured entirely by Terraform and no secret or environment-specific value
lives in source control.

SECURITY POSTURE
----------------
Every default in this file is the *safe* value, so a missing environment
variable degrades towards security rather than away from it:

* ``identity_source`` defaults to ``gateway`` -- never the header adapter.
* ``debug`` defaults to ``False``.
* ``cors_allow_origins`` defaults to empty -- no cross-origin access.
* ``environment`` defaults to ``dev``, which disables the interactive docs.

The ``local_test`` identity source is a complete authentication bypass by
design, so :meth:`Settings._enforce_identity_source_guard` refuses to load a
configuration that enables it outside ``environment=local``. The Lambda then
fails to initialise rather than starting in an insecure state
(see finding F-012).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

IdentitySource = Literal["gateway", "local_test"]
Environment = Literal["local", "test", "dev", "staging", "production"]

#: Hard ceiling on a single page of results, enforced at the HTTP edge *and*
#: in the repository (defence in depth -- see finding F-009).
MAX_PAGE_SIZE = 100

#: Longest ``X-Request-Id`` accepted from a client.
MAX_REQUEST_ID_LENGTH = 64


class Settings(BaseSettings):
    """Runtime configuration for the support API."""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        extra="ignore",
        # Reject unexpected types rather than coercing them.
        validate_default=True,
    )

    # --- General -----------------------------------------------------------
    environment: Environment = "dev"
    service_name: str = "ticket-api"
    debug: bool = False

    # --- Identity ----------------------------------------------------------
    #: ``gateway``    -- read verified claims from the API Gateway JWT authorizer.
    #: ``local_test`` -- read identity from ``X-Local-*`` headers. LOCAL ONLY.
    identity_source: IdentitySource = "gateway"

    # --- Storage -----------------------------------------------------------
    table_name: str = "support-platform-dev"
    #: Membership records live in their OWN table so the execution role can
    #: hold `GetItem` on them and nothing else.
    #:
    #: Membership is the authoritative source of a caller's role, so write
    #: access to it is tenant takeover. While it shared a partition space with
    #: tickets, IAM could not express "read memberships, write only tickets":
    #: `dynamodb:LeadingKeys` constrains the *partition* key, and there is no
    #: condition key for a sort-key prefix. A second table makes the boundary
    #: expressible in IAM instead of resting on the application never writing
    #: a `USER#` key (threat T-06, accepted risk AR-04).
    membership_table_name: str = "support-platform-dev-memberships"
    aws_region: str = "us-east-1"
    #: Only set for local DynamoDB Local / moto. Must stay unset in AWS.
    dynamodb_endpoint_url: str | None = None

    # --- API behaviour -----------------------------------------------------
    default_page_size: int = Field(default=25, ge=1, le=MAX_PAGE_SIZE)
    max_page_size: int = Field(default=MAX_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
    #: Comma-separated exact origins. Empty means "no cross-origin access".
    #: ``*`` is rejected: a wildcard with credentials would let any site read
    #: a signed-in user's tickets (finding F-012).
    cors_allow_origins: str = ""

    # --- Logging -----------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # -- validators ---------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def _blank_means_unset(cls, values: object) -> object:
        """Treat an empty or whitespace-only variable as "not set".

        Terraform modules and CI runners routinely pass an empty string for a
        value they did not set. Without this, ``APP_IDENTITY_SOURCE=""`` would
        be a hard validation error at cold start. Dropping the key instead
        means the field's declared default applies -- and every default in
        this class is the secure one, so a blank variable degrades safely.
        """
        if not isinstance(values, dict):
            return values
        return {
            key: value
            for key, value in values.items()
            if not (isinstance(value, str) and not value.strip() and key != "cors_allow_origins")
        }

    @field_validator("environment", "identity_source", "log_level", mode="before")
    @classmethod
    def _normalise_case(cls, value: object) -> object:
        """Accept ``PRODUCTION`` / ``Gateway`` and friends."""
        if isinstance(value, str):
            lowered = value.strip().lower()
            return lowered.upper() if lowered in {"debug", "info", "warning", "error"} else lowered
        return value

    @field_validator("cors_allow_origins")
    @classmethod
    def _reject_wildcard_origin(cls, value: str) -> str:
        """Refuse a wildcard CORS origin outright."""
        if "*" in value:
            raise ValueError(
                "cors_allow_origins must list exact origins; '*' is not permitted "
                "because the API is credentialed (see finding F-012)."
            )
        return value

    @model_validator(mode="after")
    def _enforce_identity_source_guard(self) -> Settings:
        """Fail closed when the header identity adapter is enabled unsafely.

        This is the single guard that keeps the local-development convenience
        from becoming a production authentication bypass. It is asserted by
        ``tests/security/test_authentication.py::
        test_local_identity_adapter_is_refused_outside_local_environment``.
        """
        if self.identity_source == "local_test" and self.environment != "local":
            raise ValueError(
                "identity_source='local_test' trusts client-supplied headers and is "
                f"only permitted when environment='local' (got '{self.environment}'). "
                "Refusing to start."
            )
        if self.debug and self.environment == "production":
            raise ValueError("debug must be disabled when environment='production'.")
        return self

    # -- derived properties -------------------------------------------------

    @property
    def allowed_origins(self) -> list[str]:
        """CORS allow-list as a list of exact origins."""
        return [origin.strip() for origin in self.cors_allow_origins.split(",") if origin.strip()]

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are a local-development affordance only.

        ``/openapi.json`` publishes every field name, bound and enum value in
        the API. Useful on a laptop; an unnecessary disclosure in a deployed
        environment (finding F-012).
        """
        return self.environment == "local"

    @property
    def trusts_request_headers_for_identity(self) -> bool:
        """True when the insecure local adapter is active. Logged at startup."""
        return self.identity_source == "local_test"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings so every module sees one consistent view.

    Cached because Lambda reuses the container across invocations and
    re-reading/validating the environment on every request is wasted work.
    Tests call ``get_settings.cache_clear()`` between configurations.
    """
    return Settings()
