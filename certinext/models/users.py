# Copyright 2026 University of Maine System
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pydantic models for the v3 CLM users and roles API (``/api/v3/certinext/users``).

The v3 paths list only what the token's user is permitted to see, so a
less-privileged credential can return fewer rows while still answering 200.
"""

from typing import Any

from pydantic import Field

from ._base import CertiNextModel, _OptionalFlag, _V3DisplayDatetimeUTC


class User(CertiNextModel):
    """One row of ``GET /users``, the paged user list."""

    user_id: str | None = Field(
        default=None, alias="userId", description="Opaque user id; the value ``group_members(user_ids=...)`` takes."
    )
    name: str | None = Field(default=None, alias="name", description="Display name.")
    email: str | None = Field(default=None, alias="email", description="Email address.")
    employee_id: str | None = Field(default=None, alias="employeeId", description="Employee id, when set.")
    group: str | None = Field(default=None, alias="group", description="Group name.")
    role: str | None = Field(default=None, alias="role", description="Role name.")
    status: str | None = Field(
        default=None, alias="status", description='e.g. ``"Active"``, ``"Pending Activation"``.'
    )
    is_owner: bool | None = Field(default=None, alias="isOwner", description="Whether the user owns the account.")
    created_by: str | None = Field(default=None, alias="createdBy", description="Who created the user, when known.")
    created_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="createdDate", description="When the user was created (UTC)."
    )
    tags: list[Any] = Field(default_factory=list, alias="tags", description="Tags; empty on every captured row.")

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"User(user_id={self.user_id!r}, role={self.role!r}, status={self.status!r})"


class UserDetail(CertiNextModel):
    """One row of ``GET /users/detailed``, a bare array with different key names.

    Carries fields the paged list lacks (designation, custom role, password
    and block state) and spells shared ones differently (``id``,
    ``emailID``, ``employeeID``). Flags arrive as ``"0"``/``"1"`` strings.
    """

    id: str | None = Field(default=None, alias="id", description="Opaque user id (the list's ``userId``).")
    name: str | None = Field(default=None, alias="name", description="Display name.")
    email: str | None = Field(default=None, alias="emailID", description="Email address.")
    employee_id: str | None = Field(default=None, alias="employeeID", description="Employee id, when set.")
    designation: str | None = Field(default=None, alias="designation", description="Job title, when set.")
    role_name: str | None = Field(default=None, alias="roleName", description="Built-in role name.")
    custom_role_name: str | None = Field(default=None, alias="customRoleName", description="Custom role name.")
    status_id: str | None = Field(default=None, alias="statusID", description="Numeric status code, a string.")
    is_active: _OptionalFlag = Field(default=None, alias="isActive", description='Sent as ``"0"``/``"1"``.')
    is_password_set: _OptionalFlag = Field(default=None, alias="isPasswordSet", description='Sent as ``"0"``/``"1"``.')
    user_blocked: _OptionalFlag = Field(default=None, alias="userBlocked", description='Sent as ``"0"``/``"1"``.')
    isd_code: str | None = Field(default=None, alias="isdCode", description="Phone country code.")
    mobile_number: str | None = Field(default=None, alias="mobileNumber", description="Phone number.")
    created_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="createdDate", description="When the user was created (UTC)."
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"UserDetail(id={self.id!r}, role_name={self.role_name!r}, is_active={self.is_active!r})"


class GroupMember(CertiNextModel):
    """One row of ``GET /users/groups/members``."""

    user_id: str | None = Field(default=None, alias="userId", description="Opaque user id.")
    name: str | None = Field(default=None, alias="name", description="Display name.")
    email: str | None = Field(default=None, alias="email", description="Email address.")
    employee_id: str | None = Field(default=None, alias="employeeId", description="Employee id, when set.")
    role: str | None = Field(default=None, alias="role", description="Role name.")
    status: str | None = Field(default=None, alias="status", description='e.g. ``"Active"``, ``"Inactive"``.')
    created_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="createdDate", description="When the user was created (UTC)."
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"GroupMember(user_id={self.user_id!r}, role={self.role!r}, status={self.status!r})"


class CustomRole(CertiNextModel):
    """One row of ``GET /users/roles`` (custom roles only)."""

    custom_role_id: str | None = Field(
        default=None, alias="customRoleId", description="Opaque role id; the key for ``role_permissions()``."
    )
    custom_role_name: str | None = Field(default=None, alias="customRoleName", description="Role name.")
    status: str | None = Field(default=None, alias="status", description='e.g. ``"Active"``.')
    created_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="createdDate", description="When the role was created (UTC)."
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"CustomRole(custom_role_id={self.custom_role_id!r}, custom_role_name={self.custom_role_name!r})"


class RolePermission(CertiNextModel):
    """One row of ``GET /users/roles/{id}/permissions``."""

    permission_id: str | None = Field(default=None, alias="permissionId", description="Opaque permission id.")
    name: str | None = Field(default=None, alias="name", description="Permission name.")
    module: str | None = Field(default=None, alias="module", description="Module the permission belongs to.")

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"RolePermission(module={self.module!r}, name={self.name!r})"
