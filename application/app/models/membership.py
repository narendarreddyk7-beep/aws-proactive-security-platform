"""Organization membership: the server-controlled identity-to-tenant mapping."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class OrganizationRole(StrEnum):
    """Roles a user can hold within one organization."""

    MEMBER = "member"
    ADMIN = "admin"


class Membership(BaseModel):
    """A user's membership of one organization.

    This record is authoritative for the user's role. It is created by an
    out-of-band administrative process (not by this API), so a user cannot
    grant themselves a role by calling the support API.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    organization_id: str
    role: OrganizationRole
    status: str = "active"
