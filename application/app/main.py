"""Application entry point.

Exposes:
* ``app``     -- the ASGI application (used by uvicorn locally and by tests).
* ``handler`` -- the Mangum-wrapped AWS Lambda handler.
"""

from __future__ import annotations

import traceback

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from mangum import Mangum

from app import __version__
from app.config import get_settings
from app.observability.logging import configure_logging, get_logger
from app.observability.request_context import new_request_id, set_request_id
from app.routes import health, tickets
from app.security.errors import AppError

logger = get_logger("app.main")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    configure_logging()
    settings = get_settings()

    application = FastAPI(
        title="Multi-Tenant Customer Support API",
        description="Support ticket management with organization-level data isolation.",
        version=__version__,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.middleware("http")
    async def correlate(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Attach a request id to every request."""
        set_request_id(request.headers.get("X-Request-Id") or new_request_id())
        return await call_next(request)

    @application.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        """Translate application errors into HTTP responses."""
        return JSONResponse(
            status_code=exc.http_status,
            content={"error": exc.error_code, "message": exc.message},
        )

    @application.exception_handler(Exception)
    async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
        """Return the failure detail so clients can report actionable bugs."""
        logger.exception("unhandled error")
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_error",
                "message": str(exc),
                "trace": traceback.format_exc(),
            },
        )

    application.include_router(health.router)
    application.include_router(tickets.router)
    return application


app = create_app()
handler = Mangum(app, lifespan="off")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104
