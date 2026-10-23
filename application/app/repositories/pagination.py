"""Opaque pagination cursors.

DynamoDB returns a ``LastEvaluatedKey`` dict. Clients should not see raw key
structure, so it is base64-encoded into a single opaque string.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from app.security.errors import ValidationFailedError


def encode_cursor(last_evaluated_key: dict[str, Any] | None) -> str | None:
    """Encode a DynamoDB ``LastEvaluatedKey`` into an opaque cursor."""
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str | None) -> dict[str, Any] | None:
    """Decode an opaque cursor back into a DynamoDB ``ExclusiveStartKey``."""
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        decoded = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationFailedError("Malformed pagination cursor") from exc
    if not isinstance(decoded, dict):
        raise ValidationFailedError("Malformed pagination cursor")
    return decoded
