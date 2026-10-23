"""Per-request correlation identifier.

A ``ContextVar`` is used so the request id is available to any log call in the
call stack without threading it through every function signature. Lambda
handles one request at a time per container, and under an async server each
task gets its own context copy, so there is no cross-request bleed.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

#: A client-supplied correlation id is attacker-controlled input. Accepting an
#: arbitrary string would let a caller inject newlines and quotes to forge log
#: records, or deliberately collide with another request's id to muddy an
#: investigation. The allow-list below is narrow enough that neither is
#: possible (finding F-007).
_SAFE_REQUEST_ID = re.compile(r"\A[A-Za-z0-9._-]{8,64}\Z")

_request_id: ContextVar[str] = ContextVar("request_id", default="-")


def new_request_id() -> str:
    """Generate a fresh request identifier."""
    return uuid.uuid4().hex


def sanitize_request_id(candidate: str | None) -> str:
    """Return a safe request id, preferring the client's when it is acceptable.

    Honouring a well-formed client id is genuinely useful: it lets a caller
    correlate their own trace with ours when they report a problem. The
    pattern check is what makes that safe.
    """
    if candidate and _SAFE_REQUEST_ID.match(candidate):
        return candidate
    return new_request_id()


def set_request_id(request_id: str) -> None:
    """Bind a request identifier to the current context."""
    _request_id.set(request_id)


def get_request_id() -> str:
    """Return the request identifier bound to the current context."""
    return _request_id.get()
