"""A DynamoDB ``Table`` wrapper that records which operations were invoked.

Used to assert *how* the repository talks to DynamoDB, not merely what it
returns. Tenant isolation that happens to work because of a post-query filter
is one refactor away from breaking, so the tests pin the mechanism: a
key-scoped ``Query``, never a ``Scan``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RecordedCall:
    """One DynamoDB API call made through the wrapper."""

    operation: str
    kwargs: dict[str, Any] = field(default_factory=dict)


class RecordingTable:
    """Delegates to a real (moto-backed) table while recording every call."""

    def __init__(self, table: Any) -> None:
        self._table = table
        self.calls: list[RecordedCall] = []

    # -- recording proxies ---------------------------------------------------

    def _record(self, operation: str, kwargs: dict[str, Any]) -> None:
        self.calls.append(RecordedCall(operation=operation, kwargs=kwargs))

    def put_item(self, **kwargs: Any) -> Any:
        """Record and delegate ``PutItem``."""
        self._record("put_item", kwargs)
        return self._table.put_item(**kwargs)

    def get_item(self, **kwargs: Any) -> Any:
        """Record and delegate ``GetItem``."""
        self._record("get_item", kwargs)
        return self._table.get_item(**kwargs)

    def update_item(self, **kwargs: Any) -> Any:
        """Record and delegate ``UpdateItem``."""
        self._record("update_item", kwargs)
        return self._table.update_item(**kwargs)

    def query(self, **kwargs: Any) -> Any:
        """Record and delegate ``Query``."""
        self._record("query", kwargs)
        return self._table.query(**kwargs)

    def scan(self, **kwargs: Any) -> Any:
        """Record and delegate ``Scan``.

        Present only so that a test can prove the repository never calls it.
        """
        self._record("scan", kwargs)
        return self._table.scan(**kwargs)

    def delete_item(self, **kwargs: Any) -> Any:
        """Record and delegate ``DeleteItem``."""
        self._record("delete_item", kwargs)
        return self._table.delete_item(**kwargs)

    def __getattr__(self, name: str) -> Any:
        """Pass through anything not explicitly wrapped (e.g. ``table_name``)."""
        return getattr(self._table, name)

    # -- assertions helpers --------------------------------------------------

    def operations(self) -> list[str]:
        """Names of the operations invoked, in order."""
        return [call.operation for call in self.calls]

    def calls_to(self, operation: str) -> list[RecordedCall]:
        """Every recorded call to one operation."""
        return [call for call in self.calls if call.operation == operation]


def condition_values(expression: Any) -> list[str]:
    """Flatten a boto3 condition expression into its literal parts.

    Returns attribute names prefixed with ``#`` and literal values as-is, so a
    test can assert that a key condition really does pin the tenant partition::

        values = condition_values(call.kwargs["KeyConditionExpression"])
        assert "TENANT#org-northwind" in values
        assert "#PK" in values
    """
    collected: list[str] = []

    if hasattr(expression, "get_expression"):
        parsed = expression.get_expression()
        for value in parsed.get("values", ()):
            collected.extend(condition_values(value))
        return collected

    name = getattr(expression, "name", None)
    if name is not None:
        collected.append(f"#{name}")
        return collected

    if isinstance(expression, str):
        collected.append(expression)
    elif isinstance(expression, (list, tuple)):
        for value in expression:
            collected.extend(condition_values(value))
    else:
        collected.append(str(expression))
    return collected
