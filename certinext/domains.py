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

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .client import CertiNextClient

_BASE = "/api/certinext/v2/domains"

VALID_DCV_METHODS: frozenset[str] = frozenset({"DNS-TXT", "HTTP-URL"})


@dataclass
class DcvInfo:
    """Parsed DCV configuration returned by :meth:`Domain.get_dcv`.

    Normalises the raw API response so callers don't need to handle multiple
    field name variants or case differences.

    Attributes:
        method: DCV method in upper case, e.g. ``DNS-TXT`` or ``HTTP-URL``.
        token:  Challenge value to publish. For DNS-TXT this is the TXT record
                content (``txtToken``); for HTTP-URL it is the file token
                (``fileToken``).
        host:   Sub-domain prefix for the challenge record. The Domains API
                does not return this field; the DNS-TXT challenge is implicitly
                placed at ``_emudhra-challenge.<domain>``.
    """

    method: str
    token: str
    host: str


class Domain:
    """Represents a single CertiNext domain resource.

    Instances are returned by `DomainAccessor` methods and should not be
    constructed directly. All API response fields are exposed as read-only
    properties; mutable fields (`name`, `dcv_method`) also have setters that
    update the local object — call the appropriate API method to persist
    changes to the server.

    Supports ``str()`` for human-readable output and ``repr()`` for a concise
    developer representation, so you can use ``print(domain)`` directly.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        domain = sess.domain.get("maine.edu")
        print(domain)
        domain.verify()
    """

    def __init__(self, client: CertiNextClient, data: dict[str, Any]) -> None:
        """
        Args:
            client: The underlying HTTP client used to make subsequent API calls.
            data: Raw API response dict for this domain.
        """
        self._client = client
        self._data: dict[str, Any] = data

    # --- properties ---

    @property
    def id(self) -> str | None:
        """Unique domain ID assigned by CertiNext."""
        return self._data.get("domainId")

    @property
    def name(self) -> str | None:
        """Fully-qualified domain name (e.g. ``maine.edu``)."""
        return self._data.get("domainName")

    @name.setter
    def name(self, value: str) -> None:
        """Update the domain name in the local object (does not call the API)."""
        self._data["domainName"] = value

    @property
    def organization_id(self) -> str | None:
        """ID of the organization this domain belongs to."""
        return self._data.get("organizationId")

    @property
    def organization_name(self) -> str | None:
        """Display name of the organization this domain belongs to."""
        return self._data.get("organizationName")

    @property
    def status(self) -> str | None:
        """Domain status, e.g. ``ACTIVE`` or ``INACTIVE``."""
        return self._data.get("status")

    @property
    def dcv_status(self) -> str | None:
        """Domain Control Validation status, e.g. ``VERIFIED`` or ``PENDING``."""
        return self._data.get("dcvStatus")

    @property
    def created_at(self) -> datetime | None:
        """Creation timestamp as a timezone-aware UTC ``datetime``, or ``None``.

        Returns ``None`` when the field is absent, null, or not a parseable
        ISO 8601 string.
        """
        raw = self._data.get("createdAt")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    # --- dunder methods ---

    def __str__(self) -> str:
        """Return a human-readable multi-line summary of the domain."""
        def row(label: str, value: Any) -> str:
            return f"  {label:<16} {value or ''}"
        lines = [f"Domain: {self.name or '(unknown)'}"]
        lines.append(row("id:", self.id))
        lines.append(row("status:", self.status))
        lines.append(row("dcv_status:", self.dcv_status))
        lines.append(row("organization:", self.organization_name))
        if self.created_at:
            lines.append(row("created:", self.created_at))
        return "\n".join(lines)

    def __repr__(self) -> str:
        """Return a concise developer representation of the domain."""
        return f"Domain(id={self.id!r}, name={self.name!r}, status={self.status!r}, dcv_status={self.dcv_status!r})"

    # --- public helpers ---

    @property
    def needs_dcv(self) -> bool:
        """Return True if this domain is active and not yet DCV-verified."""
        return self.status == "ACTIVE" and self.dcv_status != "VERIFIED"

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this domain."""
        return self._data

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` of key fields suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "name": _s(self.name),
            "status": _s(self.status),
            "dcv_status": _s(self.dcv_status),
            "organization": _s(self.organization_name),
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "id": _s(self.id),
        }

    # --- API methods ---

    def refresh(self) -> "Domain":
        """Re-fetch this domain from the API and update all properties in place.

        Returns:
            ``self``, allowing method chaining.
        """
        result = self._client.get(f"{_BASE}/{self.id}")
        if isinstance(result, dict):
            self._data = result
        return self

    def deactivate(self) -> "Domain":
        """Deactivate this domain and update properties from the API response.

        Returns:
            ``self``, allowing method chaining.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        self._data = self._client.post(f"{_BASE}/{self.id}/deactivate")
        return self

    def get_dcv(self) -> DcvInfo:
        """Return the current Domain Control Validation configuration from the API.

        Returns:
            :class:`DcvInfo` with normalised ``method``, ``token``, and ``host``.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        raw: dict[str, Any] = self._client.get(f"{_BASE}/{self.id}/dcv")
        if not isinstance(raw, dict):
            raw = {}
        method = (raw.get("dcvMethod") or raw.get("method") or "").upper()
        if method and method not in VALID_DCV_METHODS:
            raise ValueError(
                f"Unexpected DCV method {method!r} from API; "
                f"expected one of {sorted(VALID_DCV_METHODS)}"
            )
        token = raw.get("txtToken") or raw.get("fileToken") or raw.get("token") or raw.get("dnsContents") or ""
        host = raw.get("dnsHost") or raw.get("host") or ""
        return DcvInfo(method=method, token=token, host=host)

    def verify(self) -> dict[str, Any]:
        """Trigger DCV verification for this domain.

        Returns:
            Dict containing the verification attempt result.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        return self._client.post(f"{_BASE}/{self.id}/dcv/verify")

    def change_dcv_method(self, method: str) -> dict[str, Any]:
        """Change the DCV method for this domain.

        Args:
            method: The new DCV method. Accepted values: ``DNS-TXT``, ``HTTP-URL``.
                    Case-insensitive; normalized to lower case before sending.

        Returns:
            Dict containing the updated DCV configuration.

        Raises:
            ValueError: If ``method`` is not one of the accepted DCV methods.
            requests.HTTPError: On a non-2xx API response.
        """
        method_upper = method.upper()
        if method_upper not in VALID_DCV_METHODS:
            raise ValueError(
                f"Invalid DCV method {method_upper!r}; must be one of {sorted(VALID_DCV_METHODS)}"
            )
        return self._client.patch(
            f"{_BASE}/{self.id}/dcv/method", json={"dcvMethod": method_upper.lower()}
        )

    def last_dcv_attempt(self) -> dict[str, Any]:
        """Return details of the most recent DCV attempt for this domain.

        Returns:
            Dict containing the last DCV attempt details.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        result = self._client.get(f"{_BASE}/{self.id}/dcv/attempts/last")
        return result if isinstance(result, dict) else {}

    def dcv_attempt_history(self) -> dict[str, Any] | list[Any]:
        """Return the full DCV attempt history for this domain.

        Returns:
            Dict or list containing the history of DCV attempts.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        return self._client.get(f"{_BASE}/{self.id}/dcv/attempts")


class DomainAccessor:
    """Accessor for the CertiNext Domains API.

    Mounted on a session as ``session.domain``. Provides methods to list,
    retrieve, and create domains. Returned domain objects are instances of
    `Domain` and expose further API operations as methods.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        domains = sess.domain.list()
        domain = sess.domain.get("maine.edu")
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def list(
        self,
        offset: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        domain_status: str | None = None,
        dcv_status: str | None = None,
        pattern: str | None = None,
    ) -> list[Domain]:
        """Return a list of all domains in the account.

        Server-side filters (``search``, ``domain_status``, ``dcv_status``) are
        passed to the API and reduce the data transferred. ``pattern`` is applied
        client-side for cases that require regex matching.

        Args:
            offset: 0-based row offset for pagination.
            limit: Page size (API default 50; keep ≤200 for performance).
            search: Full FQDN for exact match (``maine.edu``) or a substring
                for LIKE matching (``maine``). Maps to the API ``search`` param.
                **Warning:** as of 2026-05-20 the API ``search`` parameter does
                not appear to filter results; all domains are returned regardless.
                Use ``pattern`` for reliable client-side filtering until this is
                resolved.
            domain_status: Comma-separated status filter, e.g.
                ``"ACTIVE,INACTIVE"``. Values: ACTIVE, INACTIVE, EXPIRED,
                REVOKED.
            dcv_status: Comma-separated DCV status filter, e.g.
                ``"PENDING,REJECTED"``. Values: VERIFIED, PENDING, REJECTED,
                EXPIRED.
            pattern: Optional regex applied client-side after the API response.
                Uses ``re.fullmatch`` with ``re.IGNORECASE``. Use when the API
                ``search`` substring is not precise enough.

        Returns:
            List of `Domain` objects.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            requests.HTTPError: On a non-2xx API response.
        """
        params: dict[str, Any] = {}
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if search is not None:
            params["search"] = search
        if domain_status is not None:
            params["domainStatus"] = domain_status
        if dcv_status is not None:
            params["dcvStatus"] = dcv_status
        result = self._client.get(_BASE, params=params or None)
        raw: list[Any]
        if isinstance(result, list):
            raw = result
        else:
            raw = []
            for val in result.values():
                if isinstance(val, list):
                    raw = val
                    break
        domains = [Domain(self._client, item) for item in raw]
        if pattern is not None:
            domains = [d for d in domains if re.fullmatch(pattern, d.name or "", re.IGNORECASE)]
        return domains

    def list_pending_dcv(self, search: str | None = None, pattern: str | None = None) -> list[Domain]:
        """Return all active domains that have not yet completed DCV verification.

        Fetches all domains and filters client-side using :attr:`Domain.needs_dcv`.

        **Note:** As of 2026-05-20 the API ``domainStatus`` and ``dcvStatus`` filter
        parameters return a 400 error when used together; server-side filtering is
        therefore disabled here until the API behaviour is clarified.

        Args:
            search: Optional search string passed to the API. See :meth:`list`.
            pattern: Optional client-side regex filter. See :meth:`list`.

        Returns:
            List of `Domain` objects where :attr:`Domain.needs_dcv` is ``True``.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            requests.HTTPError: On a non-2xx API response.
        """
        domains = self.list(search=search, pattern=pattern)
        return [d for d in domains if d.needs_dcv]

    def get(self, domain_id_or_name: str) -> Domain:
        """Return a single domain by ID or by fully-qualified domain name.

        When a name containing a ``.`` is passed, all domains are listed and
        the match is found by name (case-insensitive). When an opaque ID is
        passed, the single-domain endpoint is called directly.

        Args:
            domain_id_or_name: A domain name (e.g. ``maine.edu``) or a domain ID.

        Returns:
            The matching `Domain` object.

        Raises:
            KeyError: If a name lookup finds no matching domain.
            ValueError: If the API returns an unexpected response type for an ID lookup.
            requests.HTTPError: On a non-2xx API response.
        """
        if "." in domain_id_or_name:
            name = domain_id_or_name.lower()
            for domain in self.list():
                if (domain.name or "").lower() == name:
                    return domain
            raise KeyError(f"No domain found with name {domain_id_or_name!r}")
        result = self._client.get(f"{_BASE}/{domain_id_or_name}")
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected list response for domain {domain_id_or_name!r}")
        return Domain(self._client, result)

    def create(self, name: str, **fields: Any) -> Domain:
        """Create a new domain and return it as a `Domain` object.

        Args:
            name: The fully-qualified domain name to register (e.g. ``example.com``).
            **fields: Additional fields to include in the API request body.

        Returns:
            The newly created `Domain`.

        Raises:
            requests.HTTPError: On a non-2xx API response.
        """
        return Domain(self._client, self._client.post(_BASE, json={"name": name, **fields}))
