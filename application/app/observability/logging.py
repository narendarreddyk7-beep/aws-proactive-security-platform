"""Structured JSON logging for CloudWatch Logs.

WHY AN ALLOW-LIST
-----------------
CloudWatch Logs is a second data store with its own access controls, its own
retention, and a much wider readership than the request that produced the
entry. Anything written there has a far larger blast radius than it looks.

The first implementation logged whatever was passed in ``extra``, and the
service layer passed whole ticket objects -- so customer descriptions and the
``Authorization`` header ended up in the log stream (finding F-007).

A deny-list ("strip anything called ``password``") fails the moment someone
adds a new field. This formatter uses an **allow-list** instead: a field is
invisible unless it has been explicitly reviewed and permitted. The failure
mode of forgetting is a missing field in a dashboard, not customer data in a
log.

WHAT IS SAFE TO LOG
-------------------
Identifiers and outcomes, never content:

* ``principal_id`` / ``organization_id`` -- opaque identifiers, needed to
  investigate. Not names, not email addresses.
* ``resource_id`` -- which ticket, not what it says.
* ``changed_fields`` -- which fields changed, not their values.
* ``exception`` -- stack traces. These go to the log and never to the client
  (finding F-008), which is the right way round.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, Final

from app.observability.request_context import get_request_id

#: The only keys that may appear in a rendered log line.
#:
#: Adding a key here is a security decision: it must be an identifier, a status
#: or an outcome -- never customer content, never a credential.
ALLOWED_LOG_FIELDS: Final[frozenset[str]] = frozenset(
    {
        # Envelope, always present.
        "timestamp",
        "severity",
        "component",
        "request_id",
        "message",
        # Security / audit semantics.
        "event_type",
        "outcome",
        "reason",
        "error_code",
        # Actor and target identifiers (opaque ids only).
        "principal_id",
        "organization_id",
        "resource_type",
        "resource_id",
        "changed_fields",
        "role",
        # Request shape.
        "http_method",
        "http_path",
        "http_status",
        "duration_ms",
        "result_count",
        # Diagnostics. Logged, never returned to a caller.
        "exception",
    }
)

#: Hard cap on the free-text message, so one log line cannot become a
#: data-exfiltration channel if a developer ever interpolates content into it.
MAX_MESSAGE_LENGTH: Final[int] = 256

#: Marker attribute so repeated configuration does not stack handlers and does
#: not remove handlers installed by the Lambda runtime.
_HANDLER_MARKER = "_support_api_json_handler"


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects, field-allow-listed.

    One JSON object per line is what lets CloudWatch Logs Insights query
    fields directly (``filter event_type = "authorization_denied"``), which is
    what makes the metric filters in ``monitoring.tf`` and the investigation
    steps in the runbooks possible.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as a single-line JSON object."""
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "severity": record.levelname.lower(),
            "component": record.name,
            "request_id": get_request_id(),
            "message": self._safe_message(record),
        }

        # Only allow-listed extras survive. Anything else -- including a whole
        # ticket object passed by mistake -- is dropped here.
        for key, value in record.__dict__.items():
            if key in ALLOWED_LOG_FIELDS and key not in payload:
                payload[key] = self._coerce(value)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # `default=str` guarantees serialisability; json.dumps escapes newlines,
        # so a multi-line traceback stays on one line and cannot forge a record.
        return json.dumps(payload, default=str, ensure_ascii=False)

    @staticmethod
    def _safe_message(record: logging.LogRecord) -> str:
        """Return the record message, truncated and newline-free.

        CONVENTION: log messages in this codebase are static strings. Variable
        data belongs in allow-listed fields, where it is reviewable. The
        truncation here limits the damage if that convention is ever broken.
        """
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - a broken %-format must not kill logging
            message = str(record.msg)
        message = message.replace("\n", " ").replace("\r", " ")
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[:MAX_MESSAGE_LENGTH] + "...[truncated]"
        return message

    @staticmethod
    def _coerce(value: Any) -> Any:
        """Keep JSON-native types; stringify anything else."""
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, (list, tuple)):
            return [JsonFormatter._coerce(item) for item in value]
        return str(value)


def configure_logging(level: str | None = None) -> None:
    """Install the JSON formatter on the root logger, idempotently.

    Replaces only a handler this function installed previously. The AWS Lambda
    runtime installs its own root handler; removing it would lose the runtime's
    request-id correlation, and clobbering foreign handlers also breaks test
    harnesses that attach their own.
    """
    from app.config import get_settings

    settings = get_settings()
    root = logging.getLogger()

    for existing in list(root.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            root.removeHandler(existing)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    setattr(handler, _HANDLER_MARKER, True)
    root.addHandler(handler)
    root.setLevel((level or settings.log_level).upper())

    # These are noisy and their records carry URLs and headers we do not want
    # duplicated into the structured stream.
    for noisy in ("botocore", "boto3", "urllib3", "s3transfer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given component name."""
    return logging.getLogger(name)
