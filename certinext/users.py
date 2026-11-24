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

"""Read-only accessor for the v3 CLM users and roles API (``/api/v3/certinext/users``)."""

from collections.abc import Iterable

import structlog

from ._v3 import V3_BASE, iter_v3_rows, unwrap_v3
from .client import CertiNextClient, path_segment
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.users import CustomRole, GroupMember, RolePermission, User, UserDetail

__all__ = ["CustomRole", "GroupMember", "RolePermission", "User", "UserAccessor", "UserDetail"]

log = structlog.get_logger()

_PATH = f"{V3_BASE}/users"


class UserAccessor:
    """Accessor for users, custom roles and group membership.

    Mounted on a session as ``session.users``. Every list is scoped to what
    the token's user may see, so compare counts when switching credentials.

    Example::

        for user in sess.users.get_list():
            print(user.name, user.role, user.status)
        roles = {r.custom_role_id: r for r in sess.users.list_roles()}
    """

    def __init__(self, client: CertiNextClient) -> None:
        """Initialise the accessor.

        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def get_list(self, page_size: int = 100) -> list[User]:
        """Return every user, fetching all pages.

        Pages with ``recordLimit``; ``pageSize`` is ignored on this path and
        the page silently defaults to 20.

        Args:
            page_size: Rows per page (default 100).

        Returns:
            All users.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows = iter_v3_rows(self._client, _PATH, "users", page_size=page_size, size_param="recordLimit")
        return [User.model_validate(r) for r in rows]

    def list_detailed(self) -> list[UserDetail]:
        """Return every user from ``users/detailed`` (one unpaged bare array).

        Returns:
            All users, with the detailed key set.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows, _ = unwrap_v3(self._client.get(f"{_PATH}/detailed"), "users")
        return [UserDetail.model_validate(r) for r in rows]

    def list_roles(self, page_size: int = 100) -> list[CustomRole]:
        """Return every custom role, fetching all pages (by ``recordLimit``).

        Args:
            page_size: Rows per page (default 100).

        Returns:
            All custom roles. Built-in roles are not listed.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows = iter_v3_rows(
            self._client, f"{_PATH}/roles", "customRoles", page_size=page_size, size_param="recordLimit"
        )
        return [CustomRole.model_validate(r) for r in rows]

    def role_permissions(self, custom_role_id: str) -> list[RolePermission]:
        """Return the permissions granted by one custom role.

        Args:
            custom_role_id: :attr:`CustomRole.custom_role_id`.

        Returns:
            The role's permissions.

        Raises:
            ValueError: If ``custom_role_id`` is not a single path segment.
            CertiNextNotFoundError: If no role has that id.
            CertiNextAPIError: On any other non-2xx API response.
        """
        body = self._client.get(f"{_PATH}/roles/{path_segment(custom_role_id)}/permissions")
        rows, _ = unwrap_v3(body, "permissions")
        return [RolePermission.model_validate(r) for r in rows]

    def group_members(
        self, *, user_ids: Iterable[str] | None = None, group_id: str | None = None
    ) -> list[GroupMember]:
        """Return group-membership rows for the given users or group.

        The API needs one of the two (400 otherwise). ``user_ids`` works;
        ``group_id`` must be a v3 group id, which no list returns, and a v2
        ``groupNumber`` gets 404 "No such group.".

        The response is a paged envelope, but whether this endpoint honours
        ``pageNumber``/``pageSize`` has not been checked live, so only the
        first page is read. When ``totalResults`` exceeds the rows returned,
        ``v3_members_incomplete`` is logged at warning: the list is partial.

        Args:
            user_ids: :attr:`User.user_id` values, sent comma-separated.
            group_id: A v3 group id.

        Returns:
            The membership rows.

        Raises:
            TypeError: If ``user_ids`` is a bare ``str`` (it would iterate by
                character); pass ``[user_id]``.
            ValueError: If neither argument is given, or ``user_ids`` is empty.
            CertiNextAPIError: On a non-2xx API response.
        """
        params: dict[str, str] = {}
        if isinstance(user_ids, str):
            raise TypeError("user_ids must be an iterable of ids, not a str; pass [user_id]")
        if user_ids is not None:
            ids = [str(u) for u in user_ids]
            if not ids:
                raise ValueError("user_ids is empty")
            params["userIds"] = ",".join(ids)
        if group_id is not None:
            params["groupId"] = group_id
        if not params:
            raise ValueError("pass user_ids or group_id; the API rejects a request with neither")
        rows, total = unwrap_v3(self._client.get(f"{_PATH}/groups/members", params=params), "members")
        if total is not None and total > len(rows):
            log.warning("v3_members_incomplete", rows_seen=len(rows), total=total)
        return [GroupMember.model_validate(r) for r in rows]
