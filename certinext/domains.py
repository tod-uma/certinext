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

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

log = logging.getLogger(__name__)

_BASE = "/api/certinext/v2/domains"

DomainStatus = Literal["ACTIVE", "INACTIVE", "EXPIRED", "REVOKED"]
"""Valid values returned by :attr:`Domain.status`."""

DcvStatus = Literal["VERIFIED", "PENDING", "REJECTED", "EXPIRED"]
"""Valid values returned by :attr:`Domain.dcv_status`."""

DcvMethod = Literal["DNS-TXT", "HTTP-URL"]
"""Valid DCV method strings accepted by :meth:`Domain.change_dcv_method`."""

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


class DcvVerifyResult:
    """Summary of a DCV verification trigger returned by :meth:`Domain.verify`.

    Wraps the raw multi-perspective diagnostic response and exposes only the
    fields that matter for logging and decision-making. The raw response data
    is available via :attr:`raw` when deeper inspection is needed.

    Attributes:
        overall_status: Top-level outcome — typically ``"VERIFIED"`` or
            ``"PENDING"``.
        agreed: ``True`` when all queried perspectives reached consensus.
        perspectives_queried: Number of geographic perspectives that checked
            the challenge record.
    """

    def __init__(self, raw: dict[str, Any]) -> None:
        """
        Args:
            raw: The raw API response dict from the verify endpoint.
        """
        self.raw = raw
        consensus: dict[str, Any] = (raw.get("diagnostics") or {}).get("consensus") or {}
        self.overall_status: str = str(raw.get("overallStatus") or raw.get("status") or "unknown")
        self.agreed: bool = bool(consensus.get("agreed", False))
        self.perspectives_queried: int = int(consensus.get("totalPerspectivesQueried", 0))

    def __str__(self) -> str:
        """Return a short human-readable summary of the verification result."""
        return (
            f"overall_status={self.overall_status} "
            f"agreed={self.agreed} "
            f"perspectives={self.perspectives_queried}"
        )

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        return f"DcvVerifyResult({self!s})"


def _has_ns_records(name: str) -> bool:
    """Return True if name has its own NS records, indicating a DNS zone boundary.

    Requires dnspython (``pip install certinext[dns]``). Returns ``False``
    when dnspython is not installed or the query fails, erring on the side of
    assuming the parent covers the domain.

    Args:
        name: Fully-qualified domain name to query for NS records.

    Returns:
        ``True`` if NS records were found, ``False`` otherwise or on error.
    """
    try:
        import dns.resolver  # type: ignore[import-untyped]
        dns.resolver.resolve(name, "NS")
        return True
    except ImportError:
        log.debug(
            "%s: dnspython not installed; skipping NS check "
            "(pip install certinext[dns] to enable zone-boundary detection)",
            name,
        )
        return False
    except Exception:
        return False


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
        """Update the domain name in the local object only — does not call the API.

        Note:
            The CertiNext API does not provide a rename endpoint. This setter
            exists for internal use only; changes do not persist to the server.
        """
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
    def status(self) -> DomainStatus | None:
        """Domain status. One of ``ACTIVE``, ``INACTIVE``, ``EXPIRED``, ``REVOKED``."""
        return self._data.get("status")

    @property
    def dcv_status(self) -> DcvStatus | None:
        """DCV status. One of ``VERIFIED``, ``PENDING``, ``REJECTED``, ``EXPIRED``."""
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

    @property
    def dcv_expires(self) -> datetime | None:
        """DCV token expiry as a timezone-aware UTC ``datetime``, or ``None``.

        The API returns this as ``tokenExpiry`` — either at the top level of
        the domain object or nested inside a ``dcv`` sub-object depending on
        the endpoint.  Both locations are checked.

        Returns ``None`` when the field is absent, null, or not a parseable
        ISO 8601 string.
        """
        raw = self._data.get("tokenExpiry") or (self._data.get("dcv") or {}).get("tokenExpiry")
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
        if self.dcv_expires:
            lines.append(row("dcv_expires:", self.dcv_expires))
        lines.append(row("organization:", self.organization_name))
        if self.created_at:
            lines.append(row("created:", self.created_at))
        return "\n".join(lines)

    def __repr__(self) -> str:
        """Return a concise developer representation of the domain."""
        return f"Domain(name={self.name!r}, status={self.status!r})"

    # --- public helpers ---

    @property
    def needs_dcv(self) -> bool:
        """Return True if this domain is active and not yet DCV-verified."""
        return self.status == "ACTIVE" and self.dcv_status != "VERIFIED"

    def dcv_expires_soon(self, days: int = 30) -> bool:
        """Return True if the DCV token expires within ``days`` days.

        Useful for building proactive renewal workflows — call this before
        :meth:`verify` to avoid letting DCV lapse.  Returns ``False`` when
        :attr:`dcv_expires` is ``None`` (field not present in the API
        response or domain has no active DCV token).

        Args:
            days: Number of days ahead to check. Default is 30.

        Returns:
            ``True`` if the DCV expiry is known and within ``days`` days
            from now (including already-expired tokens).
        """
        exp = self.dcv_expires
        if exp is None:
            return False
        return exp <= datetime.now(timezone.utc) + timedelta(days=days)

    def dcv_covering_parent(
        self,
        all_domain_names: set[str],
        *,
        check_ns: bool = True,
    ) -> str | None:
        """Return the closest registered ancestor that covers this domain's DCV, or None.

        CertiNext propagates DCV verification down the domain tree: once a
        parent is verified, its subdomains inherit that status automatically.
        This method finds the closest ancestor in *all_domain_names* that
        provides that coverage.

        However, propagation stops at DNS zone boundaries.  A subdomain that
        has its own NS records forms a separate DNS zone and **will not**
        inherit DCV from its parent — it must be validated directly.  When
        *check_ns* is ``True`` an NS DNS lookup is performed; if NS records
        are found ``None`` is returned even when a parent exists in
        *all_domain_names*.  Requires ``dnspython``
        (``pip install certinext[dns]``); falls back gracefully when not
        installed.

        .. note::

            Zone-boundary behaviour confirmed by members of the InCommon
            cert-users mailing list (2026-06-01):

            - **Cory Gekoski, University of Maryland** — identified the
              pattern: subdomains with MX records pointing to their own DNS
              servers failed to inherit DCV while those sharing the parent's
              DNS succeeded, suggesting a zone-delegation root cause.
            - **Blake Bourgeois, Louisiana State University** — confirmed the
              definitive indicator: every subdomain that did not inherit DCV
              had its own NS records (a distinct DNS subzone), regardless of
              MX configuration.

        Args:
            all_domain_names: Set of all registered domain names (typically
                the full account list). Used to identify covering ancestors.
            check_ns: When ``True`` (the default), query DNS for NS records
                to detect zone boundaries. Set to ``False`` to skip DNS
                lookups (useful in tests or environments without DNS access).

        Returns:
            The covering ancestor domain name, or ``None`` if no ancestor is
            registered or this domain is a DNS zone boundary.
        """
        if check_ns and _has_ns_records(self.name or ""):
            log.debug(
                "%s: has NS records (DNS zone boundary) — DCV will not propagate from parent",
                self.name,
            )
            return None
        labels = (self.name or "").split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in all_domain_names:
                return parent
        return None

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
            "dcv_expires": self.dcv_expires.isoformat() if self.dcv_expires else "",
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
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        self._data = self._client.post(f"{_BASE}/{self.id}/deactivate")
        return self

    def get_dcv(self) -> DcvInfo:
        """Return the current Domain Control Validation configuration from the API.

        Returns:
            :class:`DcvInfo` with normalised ``method``, ``token``, and ``host``.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result: dict[str, Any] | list[Any] = self._client.get(f"{_BASE}/{self.id}/dcv")
        raw: dict[str, Any] = result if isinstance(result, dict) else {}
        method = (raw.get("dcvMethod") or raw.get("method") or "").upper()
        if method and method not in VALID_DCV_METHODS:
            raise ValueError(
                f"Unexpected DCV method {method!r} from API; "
                f"expected one of {sorted(VALID_DCV_METHODS)}"
            )
        token = raw.get("txtToken") or raw.get("fileToken") or raw.get("token") or raw.get("dnsContents") or ""
        host = raw.get("dnsHost") or raw.get("host") or ""
        return DcvInfo(method=method, token=token, host=host)

    def verify(self) -> DcvVerifyResult:
        """Trigger DCV verification for this domain.

        Returns:
            A :class:`DcvVerifyResult` summarising the outcome. Call
            :meth:`refresh` and check :attr:`dcv_status` to confirm the
            final status once the CA has processed the result.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw: Any = self._client.post(f"{_BASE}/{self.id}/dcv/verify")
        return DcvVerifyResult(raw if isinstance(raw, dict) else {})

    def change_dcv_method(self, method: DcvMethod) -> dict[str, Any]:
        """Change the DCV method for this domain.

        Args:
            method: The new DCV method. Must be ``"DNS-TXT"`` or ``"HTTP-URL"``.
                    Case-insensitive; normalized to upper case before validation
                    and to lower case before sending to the API.

        Returns:
            Raw API response dict containing the updated DCV configuration.

        Raises:
            ValueError: If ``method`` is not one of the accepted DCV methods.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
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
            Raw API response dict. Contains attempt metadata such as timestamp
            and result; exact keys depend on the API version.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_BASE}/{self.id}/dcv/attempts/last")
        return result if isinstance(result, dict) else {}

    def dcv_attempt_history(self) -> dict[str, Any] | list[Any]:
        """Return the full DCV attempt history for this domain.

        Returns:
            Raw API response. May be a list of attempt dicts or a wrapper dict
            depending on the API version; iterate defensively.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.get(f"{_BASE}/{self.id}/dcv/attempts")


def filter_needs_dcv(
    domains: list[Domain],
    all_domain_names: set[str],
    *,
    check_ns: bool = True,
) -> list[Domain]:
    """Return domains that genuinely need direct DCV validation.

    Removes any domain whose DCV would be covered by a registered ancestor
    in *all_domain_names* via CertiNext's propagation rules.  When
    *check_ns* is ``True`` (the default), a DNS NS lookup is performed for
    each domain to detect zone boundaries — domains with their own NS records
    form a separate DNS zone and cannot inherit DCV, so they are always
    included in the result even when an ancestor exists.

    Typical usage::

        all_names = {d.name for d in all_domains if d.name}
        to_validate = filter_needs_dcv(pending_domains, all_names)

    Args:
        domains: Domains to evaluate (typically only the pending-DCV subset).
        all_domain_names: Full set of registered domain names in the account,
            used to identify covering ancestors.
        check_ns: When ``True``, query DNS for NS records to detect zone
            boundaries. Set to ``False`` to skip DNS lookups (tests, no DNS
            access). Default is ``True``.

    Returns:
        Filtered list containing only domains that require direct DCV.
    """
    return [
        d for d in domains
        if d.dcv_covering_parent(all_domain_names, check_ns=check_ns) is None
    ]


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

    def get_list(
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
                **Warning:** the API ``search`` parameter remains broken after
                the vendor's claimed fix (re-tested 2026-05-27 with confirmed-
                correct usage per API docs). FQDN searches (any value containing
                ``"."``) still return all domains; substring searches (no ``"."``)
                now return 0 results. Use ``pattern`` for reliable client-side
                filtering.
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
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
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

    def get_pending_dcv(self, search: str | None = None, pattern: str | None = None) -> list[Domain]:
        """Return all active domains that have not yet completed DCV verification.

        Fetches all domains and filters client-side using :attr:`Domain.needs_dcv`.

        **Note:** The API ``domainStatus`` and ``dcvStatus`` filter parameters return
        a 400 error when used together — confirmed vendor bug (reported 2026-05-20).
        Server-side filtering is disabled until CertiNext notifies the fix is deployed.

        Args:
            search: Optional search string passed to the API. See :meth:`get_list`.
            pattern: Optional client-side regex filter. See :meth:`get_list`.

        Returns:
            List of `Domain` objects where :attr:`Domain.needs_dcv` is ``True``.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        domains = self.get_list(search=search, pattern=pattern)
        return [d for d in domains if d.needs_dcv]

    def get(self, domain_id_or_name: str) -> Domain:
        """Return a single domain by ID or by fully-qualified domain name.

        The lookup strategy depends on whether the argument contains a dot:

        - **Contains a dot** (e.g. ``maine.edu``): treated as a domain name.
          All domains are fetched and the first case-insensitive match is returned.
        - **No dot** (e.g. ``"dom-abc-123"``): treated as an opaque ID and the
          single-domain endpoint is called directly.

        **Edge case:** if a domain ID itself contains a dot, pass it via
        :meth:`get_list` and filter on :attr:`Domain.id` directly to avoid the
        ambiguity.

        Args:
            domain_id_or_name: A domain name (e.g. ``maine.edu``) or a domain ID.

        Returns:
            The matching `Domain` object.

        Raises:
            KeyError: If a name lookup finds no matching domain.
            ValueError: If the API returns an unexpected response type for an ID lookup.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if "." in domain_id_or_name:
            name = domain_id_or_name.lower()
            for domain in self.get_list():
                if (domain.name or "").lower() == name:
                    return domain
            raise KeyError(f"No domain found with name {domain_id_or_name!r}")
        result = self._client.get(f"{_BASE}/{domain_id_or_name}")
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected list response for domain {domain_id_or_name!r}")
        return Domain(self._client, result)

    def create(
        self,
        name: str,
        organization_id: str | None = None,
    ) -> Domain:
        """Create a new domain and return it as a :class:`Domain` object.

        Args:
            name: The fully-qualified domain name to register (e.g. ``"example.com"``).
            organization_id: Organization to associate this domain with. Required
                unless your account only has a single organization.

        Returns:
            The newly created :class:`Domain`.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        body: dict[str, Any] = {"name": name}
        if organization_id is not None:
            body["organizationId"] = organization_id
        return Domain(self._client, self._client.post(_BASE, json=body))

    def deactivate(self, domain_id: str) -> Domain:
        """Deactivate a domain by its ID.

        Equivalent to ``accessor.get(domain_id).deactivate()`` but avoids the
        extra GET request when the domain ID is already known.

        Args:
            domain_id: The domain's opaque ID (not the domain name). Retrieve it
                from :attr:`Domain.id` or :meth:`get`.

        Returns:
            A :class:`Domain` reflecting the deactivated state.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        data = self._client.post(f"{_BASE}/{domain_id}/deactivate")
        return Domain(self._client, data)
