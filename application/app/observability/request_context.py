"""Per-request correlation identifier.

A ``ContextVar`` is used so the request id is available to any log call in the
call stack without threading it through every function signature. Lambda
handles one request per container at a time, so there is no cross-request
bleed; under a threaded ASGI server ``ContextVar`` is still correct because each
task gets its own copy of the context.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

_request_id: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    """Generate a fresh request identifier."""
    return uuid.uuid4().hex


def set_request_id(request_id: str) -> None:
    """Bind a request identifier to the current context."""
    _request_id.set(request_id)


def get_request_id() -> str:
    """Return the request identifier bound to the current context."""
    return _request_id.get()
