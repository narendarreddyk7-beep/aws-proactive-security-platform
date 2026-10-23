"""Health endpoint.

Intentionally unauthenticated so that API Gateway / external monitors can
probe liveness. It must therefore never disclose configuration detail.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app import __version__
from app.config import get_settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness response."""

    status: str
    service: str
    version: str
    environment: str


@router.get("/v1/health", response_model=HealthResponse, summary="Service liveness probe")
def health() -> HealthResponse:
    """Return a static liveness payload."""
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        version=__version__,
        environment=settings.environment,
    )
