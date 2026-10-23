"""Configuration unit tests.

Configuration is a security control here: every default is the safe value, and
one validator is the only thing standing between a local convenience and a
production authentication bypass.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import MAX_PAGE_SIZE, Settings

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolate_from_ambient_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every ``APP_*`` variable so defaults are actually the defaults.

    The suite-wide fixture in ``conftest.py`` sets a realistic environment for
    the API tests. These tests are about what happens when *nothing* is set,
    so the ambient values have to go.
    """
    import os

    for name in [key for key in os.environ if key.startswith("APP_")]:
        monkeypatch.delenv(name, raising=False)


def _settings(**overrides: object) -> Settings:
    """Build settings from explicit values, ignoring the ambient environment."""
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Secure defaults (finding F-012)
# ---------------------------------------------------------------------------


def test_defaults_are_secure() -> None:
    """A configuration with nothing set must still be safe to deploy."""
    settings = _settings()

    assert settings.identity_source == "gateway", "Header identity must never be the default"
    assert settings.debug is False
    assert settings.allowed_origins == [], "No cross-origin access by default"
    assert settings.docs_enabled is False
    assert settings.trusts_request_headers_for_identity is False
    assert settings.log_level == "INFO"


def test_blank_environment_variables_fall_back_to_defaults() -> None:
    """An empty variable means "unset", not "invalid".

    CI runners and Terraform modules commonly pass ``""`` for a value they did
    not set. Treating that as a hard error would break cold start; treating it
    as "use the default" lands on the secure value.
    """
    settings = _settings(environment="", identity_source="", log_level="")

    assert settings.environment == "dev"
    assert settings.identity_source == "gateway"
    assert settings.log_level == "INFO"


@pytest.mark.parametrize(
    ("value", "expected"),
    [("PRODUCTION", "production"), ("Local", "local"), ("  dev  ", "dev")],
)
def test_environment_value_is_normalised(value: str, expected: str) -> None:
    """Casing and stray whitespace must not change the security posture."""
    assert _settings(environment=value).environment == expected


# ---------------------------------------------------------------------------
# Fail-closed identity guard
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize("environment", ["dev", "test", "staging", "production"])
def test_local_identity_source_rejected_outside_local(environment: str) -> None:
    """Guards finding F-012.

    ``local_test`` trusts request headers, so enabling it anywhere else must
    stop the process from starting. Raising here means the Lambda fails
    initialisation and API Gateway returns 500 -- loud, and far better than
    serving traffic with authentication disabled.
    """
    with pytest.raises(ValidationError) as exc_info:
        _settings(identity_source="local_test", environment=environment)

    assert "local" in str(exc_info.value)


@pytest.mark.security
def test_local_identity_source_permitted_in_local_environment() -> None:
    """The documented local-development path must remain usable."""
    settings = _settings(identity_source="local_test", environment="local")

    assert settings.identity_source == "local_test"
    assert settings.trusts_request_headers_for_identity is True


@pytest.mark.security
def test_debug_is_rejected_in_production() -> None:
    """Debug output in production is an information-disclosure risk."""
    with pytest.raises(ValidationError):
        _settings(debug=True, environment="production")


@pytest.mark.parametrize("value", ["header", "jwt", "none", "disabled", "cognito"])
def test_unknown_identity_source_is_rejected(value: str) -> None:
    """A typo must not silently become a permissive mode."""
    with pytest.raises(ValidationError):
        _settings(identity_source=value)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


@pytest.mark.security
@pytest.mark.regression
@pytest.mark.parametrize("value", ["*", "https://a.example,*", "*.example.com"])
def test_wildcard_cors_origin_is_rejected(value: str) -> None:
    """Guards finding F-012.

    The API is credentialed, so a wildcard origin would let any website read a
    signed-in user's tickets. Rejecting it at config load makes the mistake
    impossible to deploy rather than something to notice in review.
    """
    with pytest.raises(ValidationError):
        _settings(cors_allow_origins=value)


def test_cors_origins_are_parsed_and_trimmed() -> None:
    """A comma-separated list is parsed into exact origins."""
    settings = _settings(
        cors_allow_origins=" https://app.example.invalid , https://admin.example.invalid "
    )
    assert settings.allowed_origins == [
        "https://app.example.invalid",
        "https://admin.example.invalid",
    ]


# ---------------------------------------------------------------------------
# Page size bounds (finding F-009)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, MAX_PAGE_SIZE + 1, 10_000])
def test_page_size_outside_bounds_is_rejected(value: int) -> None:
    """The configured default page size cannot exceed the hard ceiling."""
    with pytest.raises(ValidationError):
        _settings(default_page_size=value)


def test_docs_enabled_only_locally() -> None:
    """Interactive docs publish the whole API surface."""
    assert _settings(environment="local").docs_enabled is True
    for environment in ("dev", "test", "staging", "production"):
        assert _settings(environment=environment).docs_enabled is False
