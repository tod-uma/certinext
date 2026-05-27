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
"""

from typing import Any

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

_ME_URL = "/api/certinext/v2/auth/me"
_GROUPS_BASE = "/api/certinext/v2/groups"
_ORGS_BASE = "/api/certinext/v2/organizations"


class AccountInfo:
    """Identity of the authenticated OAuth client.

    Returned by :meth:`AccountAccessor.me`. All API fields are exposed as
    read-only properties; the full raw response is available via :meth:`as_dict`.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        me = sess.accounts.me()
        print(me.account_number, me.account_name)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict from the ``/auth/me`` endpoint.
        """
        self._data = data

    @property
    def account_number(self) -> str | None:
        """Account number assigned by CertiNext."""
        return self._data.get("accountNumber")

    @property
    def account_name(self) -> str | None:
        """Human-readable account name."""
        return self._data.get("accountName")

    @property
    def account_type(self) -> str | None:
        """Account type string (e.g. ``"ENTERPRISE"``, ``"RESELLER"``)."""
        return self._data.get("accountType")

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"AccountInfo(account_number={self.account_number!r}, account_name={self.account_name!r})"


class Group:
    """A billing group associated with the account.

    Returned by :meth:`AccountAccessor.list_groups`. Pass :attr:`group_number`
    as the ``group_number`` field when creating certificates to assign
    cost-centre billing.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for group in sess.accounts.list_groups():
            print(group.group_number, group.group_name)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict for this group.
        """
        self._data = data

    @property
    def group_number(self) -> str | None:
        """Unique group identifier; use as ``group_number`` in order requests."""
        return self._data.get("groupNumber")

    @property
    def group_name(self) -> str | None:
        """Human-readable group name."""
        return self._data.get("groupName")

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"Group(group_number={self.group_number!r}, group_name={self.group_name!r})"


class Organization:
    """A pre-vetted organization eligible for OV and EV certificates.

    Returned by :meth:`AccountAccessor.list_organizations` and
    :meth:`AccountAccessor.get_organization`. Pass :attr:`organization_number`
    as the ``organization_id`` argument when creating OV or EV certificates.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for org in sess.accounts.list_organizations():
            print(org.organization_number, org.organization_name)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict for this organization.
        """
        self._data = data

    @property
    def organization_number(self) -> str | None:
        """Unique organization ID; use as ``organization_id`` in OV/EV order requests."""
        return self._data.get("organizationNumber")

    @property
    def organization_name(self) -> str | None:
        """Legal name of the organization."""
        return self._data.get("organizationName")

    @property
    def locality(self) -> str | None:
        """City or locality of the organization."""
        return self._data.get("organizationLocality")

    @property
    def country_code(self) -> str | None:
        """ISO 3166-1 alpha-2 country code."""
        return self._data.get("organizationCountryCode")

    @property
    def postal_code(self) -> str | None:
        """Postal or ZIP code of the organization."""
        return self._data.get("organizationPostalCode")

    @property
    def status_id(self) -> str | None:
        """Organization status identifier string."""
        return self._data.get("organizationStatusId")

    @property
    def is_pre_vetting_org(self) -> str | None:
        """``"1"`` if the organization has pre-vetting approval, otherwise ``"0"``."""
        return self._data.get("isPreVettingOrg")

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"Organization(organization_number={self.organization_number!r}, "
            f"organization_name={self.organization_name!r})"
        )


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
        return AccountInfo(result if isinstance(result, dict) else {})

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
        return [Group(item) for item in raw]

    def list_organizations(self) -> list[Organization]:
        """Return all organizations available to this account.

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
        return [Organization(item) for item in raw]

    def get_organization(self, organization_id: str) -> Organization:
        """Return a single organization by its ID.

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
        return Organization(result if isinstance(result, dict) else {})
