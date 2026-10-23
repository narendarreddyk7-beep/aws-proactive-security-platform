"""Multi-tenant customer support API.

Package layout:

* ``app.config``        -- environment-driven settings (fail-closed).
* ``app.models``        -- Pydantic domain + API models.
* ``app.security``      -- identity extraction, principal, authorization policy.
* ``app.repositories``  -- tenant-scoped DynamoDB data access.
* ``app.services``      -- business rules and authorization enforcement points.
* ``app.routes``        -- HTTP interface.
* ``app.observability`` -- structured logging and request correlation.
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
