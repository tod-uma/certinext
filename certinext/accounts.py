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

"""Accounts API: identity, billing groups, and organizations.

Provides account identity and organisational structure needed for OV and EV
certificate ordering.

The response models (:class:`AccountInfo`, :class:`Group`,
:class:`Organization`) live in :mod:`certinext.models.accounts` and are
re-exported here for backward compatibility.
"""

from typing import Any

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.accounts import _ORGS_BASE, AccountInfo, Group, Organization

__all__ = ["AccountAccessor", "AccountInfo", "Group", "Organization"]

_ME_URL = "/api/certinext/v2/auth/me"
_GROUPS_BASE = "/api/certinext/v2/groups"


class AccountAccessor:
    """Accessor for the CertiNext Accounts API.

    Mounted on a session as ``session.accounts``. Provides methods to retrieve
    account identity, billing groups, and organizations.

    Use :meth:`list_organizations` to find organization numbers required when
    creating OV or EV certificates. Use :meth:`list_groups` to find group
    numbers for cost-centre billing.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        orgs = sess.accounts.list_organizations()
        org_id = orgs[0].organization_number
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def me(self) -> AccountInfo:
        """Return identity information for the authenticated OAuth client.

        Returns:
            :class:`AccountInfo` with account number, name, and type.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(_ME_URL)
        return AccountInfo.model_validate(result if isinstance(result, dict) else {})

    def list_groups(self) -> list[Group]:
        """Return all billing groups available to this account.

        Returns:
            List of :class:`Group` objects.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(_GROUPS_BASE)
        raw: list[Any] = []
        if isinstance(result, list):
            raw = result
        elif isinstance(result, dict):
            groups = result.get("groups", [])
            raw = groups if isinstance(groups, list) else []
        return [Group.model_validate(item) for item in raw if isinstance(item, dict)]

    def list_organizations(self) -> list[Organization]:
        """Return all organizations available to this account.

        The returned objects carry only the fields included in the list
        response. Accessing a detail-only property (e.g.
        :attr:`~Organization.validation_status`) on a returned object
        automatically fetches the detail endpoint on first access.

        Returns:
            List of :class:`Organization` objects. Each
            :attr:`Organization.organization_number` can be used as
            ``organization_id`` in OV or EV certificate create requests.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(_ORGS_BASE)
        raw: list[Any] = []
        if isinstance(result, list):
            raw = result
        elif isinstance(result, dict):
            orgs = result.get("organizations", [])
            raw = orgs if isinstance(orgs, list) else []
        return [
            Organization.from_payload(item, client=self._client)
            for item in raw
            if isinstance(item, dict)
        ]

    def get_organization(self, organization_id: str) -> Organization:
        """Return a single organization by its ID, including all detail fields.

        Unlike objects from :meth:`list_organizations`, the returned object is
        fully populated and will never make an additional API call.

        Args:
            organization_id: The ``organizationNumber`` value returned by
                :meth:`list_organizations`.

        Returns:
            :class:`Organization` for the given ID.

        Raises:
            CertiNextAPIError: On a non-2xx API response (404 if not found).
                Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_ORGS_BASE}/{organization_id}")
        return Organization.from_payload(result, detail_loaded=True)
