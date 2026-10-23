"""Tenant-bound pagination cursors.

A cursor is an opaque blob to a well-behaved client and a **mutable input** to
everyone else. DynamoDB's ``LastEvaluatedKey`` is a plain dict of key
attributes, so a base64-encoded one can be decoded, edited to point at another
tenant's partition, and re-sent.

The original implementation decoded the cursor and passed it straight to
``ExclusiveStartKey`` (finding F-010). Now every cursor is validated against
the caller's own partition before it is used: a cursor that does not belong to
you is rejected with 400, not forwarded.

Why not sign the cursor instead? A signature would need a key to manage and
rotate, and it would only prove the cursor was *issued by us* -- not that it
was issued to *this* tenant. Checking the partition directly is both simpler
and a stronger statement.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from app.repositories.keys import tenant_pk
from app.security.errors import ValidationFailedError

#: Generous ceiling for a legitimate DynamoDB key; anything larger is either a
#: bug or someone probing the decoder.
MAX_CURSOR_LENGTH = 1024

#: Attributes a legitimate ``LastEvaluatedKey`` may contain for this table.
_ALLOWED_CURSOR_KEYS = frozenset({"PK", "SK", "GSI1PK", "GSI1SK"})

_GENERIC_ERROR = "Invalid pagination cursor."


def encode_cursor(last_evaluated_key: dict[str, Any] | None) -> str | None:
    """Encode a DynamoDB ``LastEvaluatedKey`` into an opaque cursor."""
    if not last_evaluated_key:
        return None
    projected = {
        key: value for key, value in last_evaluated_key.items() if key in _ALLOWED_CURSOR_KEYS
    }
    raw = json.dumps(projected, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str | None, *, organization_id: str) -> dict[str, Any] | None:
    """Decode and validate a cursor against the caller's own tenant partition.

    Args:
        cursor: The opaque cursor supplied by the client.
        organization_id: The caller's organization, taken from the verified
            principal -- never from the request.

    Returns:
        A DynamoDB ``ExclusiveStartKey``, or ``None`` when no cursor was given.

    Raises:
        ValidationFailedError: The cursor is malformed, oversized, or points
            outside the caller's partition. The message is identical in every
            case so the error cannot be used to probe the key structure.
    """
    if not cursor:
        return None

    if len(cursor) > MAX_CURSOR_LENGTH:
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_too_long")

    try:
        raw = base64.urlsafe_b64decode(_pad(cursor).encode("ascii"))
        decoded = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_not_decodable") from exc

    return validate_cursor_key(decoded, organization_id=organization_id)


def validate_cursor_key(key: Any, *, organization_id: str) -> dict[str, Any]:
    """Validate a decoded ``ExclusiveStartKey`` against one tenant partition.

    Split out from :func:`decode_cursor` so the repository can apply the same
    check to a key it was handed directly. The repository is a reusable
    component; it must not assume its caller validated anything.

    Raises:
        ValidationFailedError: the key is malformed or belongs to another
            tenant.
    """
    if not isinstance(key, dict) or not key:
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_not_an_object")

    if set(key) - _ALLOWED_CURSOR_KEYS:
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_unexpected_attributes")

    if not all(isinstance(value, str) for value in key.values()):
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_value_not_a_string")

    if "PK" not in key or "SK" not in key:
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_missing_table_key")

    # The control that matters: the cursor must address the caller's partition.
    if key["PK"] != tenant_pk(organization_id):
        raise ValidationFailedError(_GENERIC_ERROR, detail="cursor_tenant_mismatch")

    return key


def _pad(value: str) -> str:
    """Restore base64 padding a client or proxy may have stripped."""
    return value + "=" * (-len(value) % 4)
