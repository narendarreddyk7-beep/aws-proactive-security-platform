"""The authenticated, authorized caller."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from app.models.membership import OrganizationRole


class Principal(BaseModel):
    """A caller whose identity has been established by a trusted source.

    A ``Principal`` must only ever be constructed from an identity source the
    application trusts. Constructing one from client-supplied data is
    equivalent to disabling authentication.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    organization_id: str
    role: OrganizationRole

    @property
    def is_admin(self) -> bool:
        """True when the principal holds the organization administrator role."""
        return self.role is OrganizationRole.ADMIN
