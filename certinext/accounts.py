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

    **Lazy detail loading**: objects returned by :meth:`~AccountAccessor.list_organizations`
    carry only the fields included in the list response (name, number, locality,
    country, postal code, status, and pre-vetting flag). Properties that require
    the detail endpoint — validation status, validation scope, subscriber
    agreement, representatives, domains — trigger a single ``GET
    /organizations/{id}`` call automatically on first access and cache the
    result. Objects from :meth:`~AccountAccessor.get_organization` are fully
    populated from construction and never make an additional call.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for org in sess.accounts.list_organizations():
            # These access the detail endpoint lazily on first call:
            print(org.organization_number, org.validation_status, org.validation_for)
    """

    def __init__(
        self,
        data: dict[str, Any],
        client: CertiNextClient | None = None,
        *,
        detail_loaded: bool = False,
    ) -> None:
        """
        Args:
            data: Raw API response dict for this organization.
            client: HTTP client used for lazy detail fetching. When ``None``
                detail-only properties return ``None`` without making a request.
            detail_loaded: Pass ``True`` when ``data`` already contains the
                full detail response (e.g. when constructed by
                :meth:`AccountAccessor.get_organization`) to suppress the
                automatic detail fetch.
        """
        self._data = data
        self._client = client
        self._detail_loaded = detail_loaded

    # ------------------------------------------------------------------
    # Internal lazy loader
    # ------------------------------------------------------------------

    def _ensure_detail(self) -> None:
        """Fetch the detail endpoint once and merge the result into ``_data``.

        No-op when the client is absent, the detail was already loaded, or
        ``organization_number`` is missing.  API errors are silently swallowed
        so that a network failure degrades gracefully to ``None`` returns rather
        than raising from a property accessor.
        """
        if self._detail_loaded or self._client is None:
            return
        self._detail_loaded = True  # set before the call so errors don't retry
        org_num = self._data.get("organizationNumber")
        if not org_num:
            return
        try:
            detail = self._client.get(f"{_ORGS_BASE}/{org_num}")
            if isinstance(detail, dict):
                self._data.update(detail)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # List-endpoint properties (always available)
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Detail-endpoint properties (lazy-loaded on first access)
    # ------------------------------------------------------------------

    @property
    def state_code(self) -> str | None:
        """ISO 3166-2 state/province code (e.g. ``"ME"``)."""
        self._ensure_detail()
        return self._data.get("organizationStateCode")

    @property
    def state_name(self) -> str | None:
        """Full state or province name (e.g. ``"Maine"``)."""
        self._ensure_detail()
        return self._data.get("organizationStateName")

    @property
    def street_address_1(self) -> str | None:
        """Primary street address line."""
        self._ensure_detail()
        return self._data.get("organizationStreetAddress1")

    @property
    def street_address_2(self) -> str | None:
        """Secondary street address line."""
        self._ensure_detail()
        return self._data.get("organizationStreetAddress2")

    @property
    def business_category_id(self) -> str | None:
        """Business category identifier (raw string from the API)."""
        self._ensure_detail()
        return self._data.get("businessCategoryId")

    @property
    def validation_status_id(self) -> str | None:
        """Raw validation status: ``"1"`` = Validated, ``"0"`` = Pending."""
        self._ensure_detail()
        return self._data.get("validationStatusId")

    @property
    def validation_status(self) -> str | None:
        """Human-readable validation status: ``"Validated"``, ``"Pending"``, or ``None``.

        ``None`` is returned when the field is absent (no client configured)
        rather than a default string, so callers can distinguish *unknown*
        from *pending*.
        """
        self._ensure_detail()
        _map = {"0": "Pending", "1": "Validated"}
        raw = self._data.get("validationStatusId")
        return _map.get(raw) if raw is not None else None

    @property
    def validation_for_id(self) -> str | None:
        """Raw validation scope identifier.

        Known values: ``"1"`` = OV, ``"2"`` = EV & OV, ``"3"`` = SMIME OV.
        """
        self._ensure_detail()
        return self._data.get("validationFor")

    @property
    def validation_for(self) -> str | None:
        """Human-readable validation scope (e.g. ``"OV"``, ``"EV & OV"``, ``"SMIME OV"``).

        Returns the raw integer string for unrecognised values so that future
        CA additions degrade to a number rather than ``None``.
        """
        self._ensure_detail()
        _map = {"1": "OV", "2": "EV & OV", "3": "SMIME OV"}
        raw = self._data.get("validationFor")
        return _map.get(raw, raw) if raw is not None else None

    @property
    def subscriber_agreement_signed(self) -> bool | None:
        """``True`` if the subscriber agreement has been signed, ``False`` if not, ``None`` if unknown."""
        self._ensure_detail()
        sa = self._data.get("subscriberAgreement")
        if not isinstance(sa, dict):
            return None
        return bool(sa.get("signed"))

    @property
    def subscriber_agreement_signer(self) -> str | None:
        """Name of the person who signed the subscriber agreement."""
        self._ensure_detail()
        sa = self._data.get("subscriberAgreement")
        return sa.get("signerName") if isinstance(sa, dict) else None

    @property
    def subscriber_agreement_date(self) -> str | None:
        """Date the subscriber agreement was signed (raw string from the API)."""
        self._ensure_detail()
        sa = self._data.get("subscriberAgreement")
        return sa.get("signedDate") if isinstance(sa, dict) else None

    @property
    def org_representatives(self) -> list[dict[str, Any]]:
        """List of organization representative records (raw dicts from the API)."""
        self._ensure_detail()
        reps = self._data.get("orgRepresentatives")
        return reps if isinstance(reps, list) else []

    @property
    def domains(self) -> list[str]:
        """List of domains authorized under this organization.

        Returns an empty list when the field is absent or empty (the API
        returns an empty string ``""`` rather than ``[]`` for orgs with no
        domains).
        """
        self._ensure_detail()
        raw = self._data.get("domains")
        if isinstance(raw, list):
            return raw
        return []

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict (fetches detail data if not yet loaded)."""
        self._ensure_detail()
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
        return [Organization(item, client=self._client) for item in raw]

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
        return Organization(result if isinstance(result, dict) else {}, detail_loaded=True)
