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

"""Pydantic models for the Accounts API (identity, groups, organizations).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
:class:`Organization` preserves the 0.3.x lazy detail fetch: list-response
objects GET ``/organizations/{id}`` once, on first access to a detail-only
property.
"""

from typing import Any, cast

from pydantic import Field, PrivateAttr, field_validator

from ..client import CertiNextClient
from ._base import CertiNextModel

_ORGS_BASE = "/api/certinext/v2/organizations"


class AccountInfo(CertiNextModel):
    """Identity of the authenticated OAuth client.

    Returned by :meth:`AccountAccessor.me`. All API fields are exposed as
    read-only attributes; the full raw response is available via :meth:`as_dict`.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        me = sess.accounts.me()
        print(me.account_number, me.account_name)
    """

    account_number: str | None = Field(
        default=None,
        alias="accountNumber",
        description="Account number assigned by CertiNext.",
    )
    account_name: str | None = Field(
        default=None,
        alias="accountName",
        description="Human-readable account name.",
    )
    account_type: str | None = Field(
        default=None,
        alias="accountType",
        description='Account type string (e.g. ``"ENTERPRISE"``, ``"RESELLER"``).',
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"AccountInfo(account_number={self.account_number!r}, account_name={self.account_name!r})"


class Group(CertiNextModel):
    """A billing group associated with the account.

    Returned by :meth:`AccountAccessor.list_groups`. Pass :attr:`group_number`
    as the ``group_number`` field when creating certificates to assign
    cost-centre billing.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for group in sess.accounts.list_groups():
            print(group.group_number, group.group_name)
    """

    group_number: str | None = Field(
        default=None,
        alias="groupNumber",
        description="Unique group identifier; use as ``group_number`` in order requests.",
    )
    group_name: str | None = Field(
        default=None,
        alias="groupName",
        description="Human-readable group name.",
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"Group(group_number={self.group_number!r}, group_name={self.group_name!r})"


class Organization(CertiNextModel):
    """A pre-vetted organization eligible for OV and EV certificates.

    Returned by :meth:`AccountAccessor.list_organizations` and
    :meth:`AccountAccessor.get_organization`. Pass :attr:`organization_number`
    as the ``organization_id`` argument when creating OV or EV certificates.

    **Lazy detail loading**: objects returned by :meth:`~AccountAccessor.list_organizations`
    carry only the fields included in the list response (name, number, locality,
    country, postal code, status, and pre-vetting flag) as model fields.
    Properties that require the detail endpoint — validation status, validation
    scope, subscriber agreement, representatives, domains — trigger a single
    ``GET /organizations/{id}`` call automatically on first access, merge the
    result into the raw payload, and read from it. Objects from
    :meth:`~AccountAccessor.get_organization` are fully populated from
    construction and never make an additional call.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for org in sess.accounts.list_organizations():
            # These access the detail endpoint lazily on first call:
            print(org.organization_number, org.validation_status, org.validation_for)
    """

    organization_number: str | None = Field(
        default=None,
        alias="organizationNumber",
        description="Unique organization ID; use as ``organization_id`` in OV/EV order requests.",
    )
    organization_name: str | None = Field(
        default=None,
        alias="organizationName",
        description="Legal name of the organization.",
    )
    locality: str | None = Field(
        default=None,
        alias="organizationLocality",
        description="City or locality of the organization.",
    )
    country_code: str | None = Field(
        default=None,
        alias="organizationCountryCode",
        description="ISO 3166-1 alpha-2 country code.",
    )
    postal_code: str | None = Field(
        default=None,
        alias="organizationPostalCode",
        description="Postal or ZIP code of the organization.",
    )
    status_id: str | None = Field(
        default=None,
        alias="organizationStatusId",
        description="Organization status identifier string.",
    )
    is_pre_vetting_org: str | None = Field(
        default=None,
        alias="isPreVettingOrg",
        description='``"1"`` if the organization has pre-vetting approval, otherwise ``"0"``.',
    )

    _client: CertiNextClient | None = PrivateAttr(default=None)
    _detail_loaded: bool = PrivateAttr(default=False)

    @field_validator("is_pre_vetting_org", mode="before")
    @classmethod
    def _pre_vetting_flag_to_string(cls, value: Any) -> Any:
        """Normalize boolean/int wire values to the documented ``"1"``/``"0"`` strings.

        The attribute surface promises the vendor's string flags; if the
        vendor drifts to real booleans or ints, coerce rather than fail
        (ADR 0005).

        Args:
            value: The raw wire value for ``isPreVettingOrg``.

        Returns:
            ``"1"``/``"0"`` for boolean or 0/1 int input, else the value unchanged.
        """
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, int):
            return "1" if value else "0"
        return value

    @classmethod
    def from_payload(
        cls,
        data: Any,
        *,
        client: CertiNextClient | None = None,
        detail_loaded: bool = False,
    ) -> "Organization":
        """Build an Organization from a wire payload and wire up lazy loading.

        Args:
            data: Raw API response dict for this organization (non-dict
                values validate as an empty payload).
            client: HTTP client used for lazy detail fetching. When ``None``
                detail-only properties return ``None`` without making a request.
            detail_loaded: Pass ``True`` when ``data`` already contains the
                full detail response (e.g. when constructed by
                :meth:`AccountAccessor.get_organization`) to suppress the
                automatic detail fetch.

        Returns:
            The validated Organization instance.
        """
        org = cls.model_validate(data if isinstance(data, dict) else {})
        org._client = client
        org._detail_loaded = detail_loaded
        return org

    # ------------------------------------------------------------------
    # Internal lazy loader
    # ------------------------------------------------------------------

    def _ensure_detail(self) -> None:
        """Fetch the detail endpoint once and merge the result into the raw payload.

        No-op when the client is absent, the detail was already loaded, or
        ``organization_number`` is missing.  API errors are silently swallowed
        so that a network failure degrades gracefully to ``None`` returns rather
        than raising from a property accessor.
        """
        if self._detail_loaded or self._client is None:
            return
        self._detail_loaded = True  # set before the call so errors don't retry
        org_num = self.organization_number
        if not org_num:
            return
        try:
            detail = self._client.get(f"{_ORGS_BASE}/{org_num}")
            if isinstance(detail, dict):
                if self._raw is None:
                    self._raw = {}
                self._raw.update(detail)
        except Exception:
            pass

    def _detail_get(self, key: str) -> Any:
        """Return a detail-endpoint field from the raw payload, lazy-loading first.

        Args:
            key: The wire key to read.

        Returns:
            The raw value, or ``None`` when absent.
        """
        self._ensure_detail()
        return (self._raw or {}).get(key)

    def _detail_str(self, key: str) -> str | None:
        """Return a detail-endpoint field typed as ``str | None``.

        Args:
            key: The wire key to read.

        Returns:
            The raw value (assumed string-or-absent on the wire), or ``None``.
        """
        return cast("str | None", self._detail_get(key))

    # ------------------------------------------------------------------
    # Detail-endpoint properties (lazy-loaded on first access)
    # ------------------------------------------------------------------

    @property
    def state_code(self) -> str | None:
        """ISO 3166-2 state/province code (e.g. ``"ME"``)."""
        return self._detail_str("organizationStateCode")

    @property
    def state_name(self) -> str | None:
        """Full state or province name (e.g. ``"Maine"``)."""
        return self._detail_str("organizationStateName")

    @property
    def street_address_1(self) -> str | None:
        """Primary street address line."""
        return self._detail_str("organizationStreetAddress1")

    @property
    def street_address_2(self) -> str | None:
        """Secondary street address line."""
        return self._detail_str("organizationStreetAddress2")

    @property
    def business_category_id(self) -> str | None:
        """Business category identifier (raw string from the API)."""
        return self._detail_str("businessCategoryId")

    @property
    def validation_status_id(self) -> str | None:
        """Raw validation status: ``"1"`` = Validated, ``"0"`` = Pending."""
        return self._detail_str("validationStatusId")

    @property
    def validation_status(self) -> str | None:
        """Human-readable validation status: ``"Validated"``, ``"Pending"``, or ``None``.

        ``None`` is returned when the field is absent (no client configured)
        rather than a default string, so callers can distinguish *unknown*
        from *pending*.
        """
        _map = {"0": "Pending", "1": "Validated"}
        raw = self._detail_str("validationStatusId")
        return _map.get(raw) if raw is not None else None

    @property
    def validation_for_id(self) -> str | None:
        """Raw validation scope identifier.

        Known values: ``"1"`` = OV, ``"2"`` = EV & OV, ``"3"`` = SMIME OV.
        """
        return self._detail_str("validationFor")

    @property
    def validation_for(self) -> str | None:
        """Human-readable validation scope (e.g. ``"OV"``, ``"EV & OV"``, ``"SMIME OV"``).

        Returns the raw integer string for unrecognised values so that future
        CA additions degrade to a number rather than ``None``.
        """
        _map = {"1": "OV", "2": "EV & OV", "3": "SMIME OV"}
        raw = self._detail_str("validationFor")
        return _map.get(raw, raw) if raw is not None else None

    @property
    def subscriber_agreement_signed(self) -> bool | None:
        """``True`` if the subscriber agreement has been signed, ``False`` if not, ``None`` if unknown."""
        sa = self._detail_get("subscriberAgreement")
        if not isinstance(sa, dict):
            return None
        return bool(sa.get("signed"))

    @property
    def subscriber_agreement_signer(self) -> str | None:
        """Name of the person who signed the subscriber agreement."""
        sa = self._detail_get("subscriberAgreement")
        return cast("str | None", sa.get("signerName")) if isinstance(sa, dict) else None

    @property
    def subscriber_agreement_date(self) -> str | None:
        """Date the subscriber agreement was signed (raw string from the API)."""
        sa = self._detail_get("subscriberAgreement")
        return cast("str | None", sa.get("signedDate")) if isinstance(sa, dict) else None

    @property
    def org_representatives(self) -> list[dict[str, Any]]:
        """List of organization representative records (raw dicts from the API)."""
        reps = self._detail_get("orgRepresentatives")
        return reps if isinstance(reps, list) else []

    @property
    def domains(self) -> list[str]:
        """List of domains authorized under this organization.

        Returns an empty list when the field is absent or empty (the API
        returns an empty string ``""`` rather than ``[]`` for orgs with no
        domains).
        """
        raw = self._detail_get("domains")
        if isinstance(raw, list):
            return raw
        return []

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict (fetches detail data if not yet loaded)."""
        self._ensure_detail()
        return super().as_dict()

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"Organization(organization_number={self.organization_number!r}, "
            f"organization_name={self.organization_name!r})"
        )
