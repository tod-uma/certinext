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

from pydantic import ConfigDict, Field, PrivateAttr, field_validator

from ..client import CertiNextClient
from ._base import CertiNextModel, _LenientDatetime

# Org CA-validation timestamps arrive as "YYYY-MM-DD HH:MM:SS" with no offset
# (sandbox 2026-11-09) and the vendor has not said which zone they are in, so
# they parse as naive datetimes (_base: use the UTC variant only once confirmed).
_NAIVE_NOTE = "naive datetime; the wire carries no offset and its zone is unconfirmed"

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

    def ca_levels(self, ca: str = "SSLCOM") -> list["CaLevelValidation"]:
        """Return this organization's per-level validation with a non-emSign CA.

        Reads the ``caValidations.<ca>`` block, which the org list rows and the
        detail response both carry on an SSL.com account (observed in the
        sandbox 2026-11-09). The detail endpoint is fetched only when the
        block is missing from what this object already holds.

        Args:
            ca: CA name, case-insensitive (``"SSLCOM"``). Matched against the
                wire key with dots and case removed, so ``"ssl.com"`` works.

        Returns:
            One :class:`CaLevelValidation` per level (``OV``, ``EV``) in wire
            order; an empty list when the account has no such block.
        """
        block = (self._raw or {}).get("caValidations")
        if not isinstance(block, dict):
            block = self._detail_get("caValidations")
        if not isinstance(block, dict):
            return []
        wanted = _ca_key(ca)
        per_ca = next((v for k, v in block.items() if _ca_key(k) == wanted), None)
        if not isinstance(per_ca, dict):
            return []
        return [
            CaLevelValidation.model_validate({**value, "level": key.upper()})
            for key, value in per_ca.items()
            if isinstance(value, dict)
        ]

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


def _ca_key(ca: str) -> str:
    """Normalise a CA name for comparison with wire keys and path segments.

    The org endpoints spell SSL.com as ``sslcom`` (path, ``caValidations``
    key, ``ca`` field) while the domain endpoints use ``SSLCOM``.

    Args:
        ca: A CA name in any of those spellings.

    Returns:
        The name lower-cased with dots, dashes and underscores removed.
    """
    return ca.lower().replace(".", "").replace("-", "").replace("_", "")


class CaLevelValidation(CertiNextModel):
    """One validation level (OV or EV) of an organization with a non-emSign CA.

    Built by :meth:`Organization.ca_levels` and
    :attr:`OrgCaValidation.levels`. Status values seen in the sandbox
    (2026-11-09): ``VALIDATED`` and ``NOT_SUBMITTED``; kept as ``str`` so new
    vendor states pass through.

    Example::

        for lvl in org.ca_levels("SSLCOM"):
            print(lvl.level, lvl.status, lvl.usable, lvl.valid_till)
    """

    level: str | None = Field(default=None, description='Validation level, upper case (``"OV"``, ``"EV"``).')
    status: str | None = Field(default=None, description='CA status, e.g. ``"VALIDATED"``, ``"NOT_SUBMITTED"``.')
    usable: bool = Field(
        default=False,
        description="True when certificates at this level may use the organization now.",
    )
    valid_till: _LenientDatetime = Field(
        default=None,
        alias="validTill",
        description=f"When the CA's validation lapses ({_NAIVE_NOTE}), or ``None`` when absent or blank.",
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"CaLevelValidation(level={self.level!r}, status={self.status!r}, usable={self.usable!r})"


class OrgCaValidation(CertiNextModel):
    """An organization's validation with a non-emSign CA (SSL.com today).

    Returned by :meth:`~certinext.accounts.AccountAccessor.get_ca_validation`,
    :meth:`~certinext.accounts.AccountAccessor.sync_ca_validation` and
    :meth:`~certinext.accounts.AccountAccessor.submit_ca_validation`.

    The ``readiness`` block's ``missing`` lists are exposed as fields. Its
    ``current`` values and the ``contact`` block hold a person's name, phone
    and email, so they are **not** model fields; read them through
    :meth:`as_dict` when needed, and keep them out of logs and fixtures.
    Unlike other models this one ignores unknown wire keys (ADR 0005's
    retention lives on in :meth:`as_dict` only), so ``model_dump()``,
    ``str()`` and ``repr()`` never carry that contact data.

    Example::

        val = sess.accounts.get_ca_validation("1234567")
        if val.usable("OV"):
            ...
        elif val.missing:
            print("Fix before submitting:", val.missing)
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True, coerce_numbers_to_str=True)

    organization_number: str | None = Field(default=None, alias="organizationNumber", description="Organization ID.")
    ca: str | None = Field(default=None, description='Wire CA name (``"sslcom"``).')
    status: str | None = Field(default=None, description='Overall status, e.g. ``"VALIDATED"``.')
    enabled: bool | None = Field(default=None, description="Whether the CA is enabled for this organization.")
    subscriber_agreement_accepted: bool | None = Field(
        default=None, alias="subscriberAgreementAccepted", description="Whether the CA's agreement was accepted.",
    )
    levels: list[CaLevelValidation] = Field(default_factory=list, description="Per-level validation state.")
    default_levels: list[str] = Field(
        default_factory=list, alias="defaultLevels", description="Levels a submit with no ``levels`` requests.",
    )
    validated_at: _LenientDatetime = Field(
        default=None, alias="validatedAt", description=f"When validated ({_NAIVE_NOTE}).",
    )
    submitted_at: _LenientDatetime = Field(
        default=None, alias="submittedAt", description=f"When submitted ({_NAIVE_NOTE}).",
    )
    last_synced_at: _LenientDatetime = Field(
        default=None, alias="lastSyncedAt", description=f"When last re-read from the CA ({_NAIVE_NOTE}).",
    )
    last_error: str | None = Field(default=None, alias="lastError", description="Last CA error, or empty.")

    @field_validator("levels", mode="before")
    @classmethod
    def _levels_keep_dict_rows(cls, value: Any) -> list[Any]:
        """Drop non-dict entries from the wire ``levels`` list (ADR 0005).

        Args:
            value: The raw wire value for ``levels``.

        Returns:
            The dict entries, or ``[]`` for non-list input.
        """
        return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []

    def _readiness(self) -> dict[str, Any]:
        """Return the raw ``readiness`` block, or an empty dict.

        Returns:
            The block as sent by the API.
        """
        block = (self._raw or {}).get("readiness")
        return block if isinstance(block, dict) else {}

    def _readiness_list(self, key: str) -> list[str]:
        """Return one of the ``readiness`` string lists.

        Args:
            key: The wire key (``missing``, ``evMissing``, ``softMissing``).

        Returns:
            The list's string entries; ``[]`` when absent.
        """
        value = self._readiness().get(key)
        return [str(v) for v in value] if isinstance(value, list) else []

    @property
    def ready(self) -> bool | None:
        """Whether the organization can be submitted for OV; ``None`` when unknown."""
        value = self._readiness().get("ready")
        return value if isinstance(value, bool) else None

    @property
    def ev_ready(self) -> bool | None:
        """Whether the organization can be submitted for EV; ``None`` when unknown."""
        value = self._readiness().get("evReady")
        return value if isinstance(value, bool) else None

    @property
    def missing(self) -> list[str]:
        """Items that block a submit (human-readable labels from the API)."""
        return self._readiness_list("missing")

    @property
    def ev_missing(self) -> list[str]:
        """Items that block an EV submit, e.g. ``"Business category"``."""
        return self._readiness_list("evMissing")

    @property
    def soft_missing(self) -> list[str]:
        """Recommended but non-blocking items."""
        return self._readiness_list("softMissing")

    def level(self, name: str) -> CaLevelValidation | None:
        """Return the entry of :attr:`levels` for one level, or ``None``.

        Args:
            name: ``"OV"`` or ``"EV"``, case-insensitive.

        Returns:
            The matching level, or ``None`` when the CA reports none.
        """
        return next((lvl for lvl in self.levels if (lvl.level or "").upper() == name.upper()), None)

    def usable(self, name: str) -> bool:
        """Return True when certificates at this level may use the organization now.

        Args:
            name: ``"OV"`` or ``"EV"``, case-insensitive.

        Returns:
            The level's ``usable`` flag; ``False`` when the level is absent.
        """
        lvl = self.level(name)
        return bool(lvl and lvl.usable)

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"OrgCaValidation(organization_number={self.organization_number!r}, ca={self.ca!r}, "
            f"status={self.status!r})"
        )
