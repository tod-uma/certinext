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
from .models.accounts import (
    _ORGS_BASE,
    AccountInfo,
    CaLevelValidation,
    Group,
    Organization,
    OrgCaValidation,
    _ca_key,
)

__all__ = ["AccountAccessor", "AccountInfo", "CaLevelValidation", "Group", "Organization", "OrgCaValidation"]

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

    def list_organizations(
        self,
        *,
        group_number: str | None = None,
        product_variant: str | None = None,
        validated_by: str | None = None,
    ) -> list[Organization]:
        """Return all organizations available to this account.

        The returned objects carry only the fields included in the list
        response. Accessing a detail-only property (e.g.
        :attr:`~Organization.validation_status`) on a returned object
        automatically fetches the detail endpoint on first access.

        Args:
            group_number: Only organizations of this group.
            product_variant: ``"ov"`` or ``"ev"``: only organizations usable
                for that variant (``ev`` = EV-validated; ``ov`` = OV- or
                EV-validated).
            validated_by: ``"SSLCOM"``: only organizations SSL.com
                certificates may use now (the SSL.com level for
                ``product_variant`` is VALIDATED and unexpired). Upper-cased
                and passed through, so a vendor-added CA needs no release.

        Returns:
            List of :class:`Organization` objects. Each
            :attr:`Organization.organization_number` can be used as
            ``organization_id`` in OV or EV certificate create requests.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        params: dict[str, Any] = {}
        if group_number is not None:
            params["groupNumber"] = group_number
        if product_variant is not None:
            params["productVariant"] = product_variant.lower()
        if validated_by is not None:
            params["validatedBy"] = validated_by.upper()
        result = self._client.get(_ORGS_BASE, params=params or None)
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

    # --- validation with a non-emSign CA (SSL.com today) ---

    @staticmethod
    def _ca_validation_url(organization_id: str, ca: str) -> str:
        """Return the ``ca-validations/<ca>`` URL for one organization.

        Args:
            organization_id: The organization number.
            ca: CA name in any spelling (``"SSLCOM"``, ``"ssl.com"``); sent
                as the lower-case path segment the API uses (``sslcom``).

        Returns:
            The endpoint path.
        """
        return f"{_ORGS_BASE}/{organization_id}/ca-validations/{_ca_key(ca)}"

    def get_ca_validation(self, organization_id: str, ca: str = "SSLCOM") -> OrgCaValidation:
        """Return an organization's validation status with a non-emSign CA.

        Read-only. Shows status and expiry per level (OV, EV), what is still
        missing before a submit, and whether the agreement was accepted.

        Args:
            organization_id: The organization number.
            ca: The CA (default ``"SSLCOM"``, the only one the API offers as
                of 2026-11-09).

        Returns:
            The :class:`OrgCaValidation`.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        return OrgCaValidation.model_validate(self._client.get(self._ca_validation_url(organization_id, ca)))

    def sync_ca_validation(self, organization_id: str, ca: str = "SSLCOM") -> OrgCaValidation:
        """Re-read an organization's status from the CA and return it.

        A ``POST`` (``.../sync``) that changes only CertiNext's cached copy
        of the CA's status, not the validation itself. Use it when the CA has
        finished vetting but :meth:`get_ca_validation` still shows the old
        state.

        Args:
            organization_id: The organization number.
            ca: The CA (default ``"SSLCOM"``).

        Returns:
            The refreshed :class:`OrgCaValidation`.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        url = self._ca_validation_url(organization_id, ca) + "/sync"
        return OrgCaValidation.model_validate(self._client.post(url))

    def submit_ca_validation(
        self,
        organization_id: str,
        *,
        subscriber_agreement_accepted: bool,
        levels: list[str] | None = None,
        ca: str = "SSLCOM",
        admin_email: str | None = None,
        organization_phone: str | None = None,
        business_category_id: str | None = None,
        registration_number: str | None = None,
        contact_title: str | None = None,
    ) -> OrgCaValidation:
        """Submit an organization to a non-emSign CA for OV and/or EV validation.

        **This is a write that starts real vetting with the CA.** The vendor
        documents it as safe to repeat: a level already requested is skipped.
        Check :attr:`OrgCaValidation.missing` from :meth:`get_ca_validation`
        first; the optional organization fields are needed only when the
        organization lacks them.

        Args:
            organization_id: The organization number.
            subscriber_agreement_accepted: Must be ``True``. Keyword-only and
                without a default so accepting the CA's subscriber agreement
                is always an explicit decision by the caller.
            levels: ``["OV"]``, ``["EV"]`` or both; ``None`` or empty means
                the organization's default levels.
            ca: The CA (default ``"SSLCOM"``).
            admin_email: Optional administrator email for the CA.
            organization_phone: Only if the organization has none.
            business_category_id: Only if the organization has none (EV).
            registration_number: Only if the organization has none.
            contact_title: Only if the organization has none (EV).

        Returns:
            The :class:`OrgCaValidation` after the submit.

        Raises:
            ValueError: If ``subscriber_agreement_accepted`` is not ``True``.
                Nothing is sent.
            CertiNextAPIError: On a non-2xx API response.
        """
        if subscriber_agreement_accepted is not True:
            raise ValueError(
                "submit_ca_validation() requires subscriber_agreement_accepted=True; "
                "the CA will not vet an organization whose agreement was not accepted"
            )
        body: dict[str, Any] = {
            "subscriberAgreementAccepted": True,
            "levels": [lvl.upper() for lvl in (levels or [])],
        }
        optional = {
            "adminEmail": admin_email,
            "organizationPhone": organization_phone,
            "businessCategoryId": business_category_id,
            "registrationNumber": registration_number,
            "contactTitle": contact_title,
        }
        body.update({k: v for k, v in optional.items() if v is not None})
        result = self._client.post(self._ca_validation_url(organization_id, ca), json=body)
        return OrgCaValidation.model_validate(result)
