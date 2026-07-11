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
from typing import Any

import structlog

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.domains import (
    _BASE,
    VALID_DCV_METHODS,
    DcvInfo,
    DcvMethod,
    DcvStatus,
    DcvVerifyResult,
    Domain,
    DomainStatus,
)

__all__ = [
    "VALID_DCV_METHODS",
    "DcvInfo",
    "DcvMethod",
    "DcvStatus",
    "DcvVerifyResult",
    "Domain",
    "DomainAccessor",
    "DomainStatus",
    "filter_needs_dcv",
]

log = structlog.get_logger()

# get_list() with no offset/limit is meant to return the whole account, but
# passing no `limit` at all just gets the server's own default page size back
# -- silently truncating large accounts. It also can't safely loop the raw
# offset/limit pages under the API's default sort, which vendor-confirmed is
# not a stable total order across offset values (tracked as issue #1 on UMS's
# private GitLab instance at gitlab.its.maine.edu -- not the public GitHub
# mirror's tracker, and not visible outside UMS). domainName is a unique,
# documented sortBy value instead, so paging under it is a stable total order
# regardless of account size; _LIST_PAGE_SIZE bounds each request (the API
# docs recommend limit <=200).
_LIST_PAGE_SIZE = 200
# Defensive ceiling on the number of pages get_list() will walk before giving
# up, in case pagination ever regresses to non-terminating drift. At
# _LIST_PAGE_SIZE rows per page this allows 200,000 domains -- far beyond any
# real account.
_MAX_LIST_PAGES = 1000

def _extract_domain_rows(result: dict[str, Any] | list[Any]) -> list[Any]:
    """Return the list of raw domain rows from a Domains API response.

    The endpoint sometimes returns a bare JSON array and sometimes a dict
    with the array nested under a key (e.g. total-count metadata alongside
    the rows); this normalizes both shapes.

    Args:
        result: The parsed JSON response from ``GET /domains``.

    Returns:
        The nested list of raw row dicts, or an empty list if none is found.
    """
    if isinstance(result, list):
        return result
    for val in result.values():
        if isinstance(val, list):
            return val
    return []


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

        When both ``offset`` and ``limit`` are omitted, this fetches the
        **complete** account by paging under an explicit ``sortBy=domainName``
        sort, which is a stable total order regardless of account size (the
        API's default sort order is not -- see the ``limit``/``offset`` note
        below). Pass ``offset``/``limit`` explicitly to fetch a single raw
        server page instead, under whichever ordering the API applies by
        default.

        Server-side filters (``search``, ``domain_status``, ``dcv_status``) are
        passed to the API and reduce the data transferred. ``pattern`` is applied
        client-side for cases that require regex matching (alternation,
        anchoring, wildcards) that the substring-only ``search`` can't express.

        Args:
            offset: 0-based row offset. When given together with ``limit``,
                fetches exactly that single server page instead of the whole
                account.
            limit: Page size. When given together with ``offset``, fetches
                exactly that single server page (API default 50; keep ≤200
                for performance) instead of the whole account. **Note:** the
                API's default sort order for a raw page like this is not a
                stable total order across offset values -- rows can be
                skipped or duplicated between pages (vendor-confirmed;
                tracked as issue #1 on UMS's private GitLab instance at
                gitlab.its.maine.edu, not the public GitHub mirror's issue
                tracker). Omit ``offset``/``limit`` for a reliable full list.
            search: Full FQDN for exact match (``maine.edu``) or a substring
                for LIKE matching (``maine``). Maps to the API ``search`` param
                and is applied server-side (reduces data transferred). Confirmed
                working for both exact and substring matches in **both**
                sandbox and production as of 2026-07-08 (GitLab issue #2,
                closed). It only does substring containment, not regex — use
                ``pattern`` when you need anchoring, alternation, or wildcards.
            domain_status: Comma-separated status filter, e.g.
                ``"ACTIVE,INACTIVE"``. Values: ACTIVE, INACTIVE, EXPIRED.
            dcv_status: Comma-separated DCV status filter, e.g.
                ``"PENDING,REJECTED"``. Values: VERIFIED, PENDING, REJECTED.
            pattern: Optional regex applied client-side after the API response.
                Uses ``re.fullmatch`` with ``re.IGNORECASE``. Use for matching
                ``search`` can't express: exact alternation of several names
                (``"maine\\.edu|umaine\\.edu"``), wildcards
                (``".*\\.maine\\.edu"``), or anchored exact match. For plain
                substring filtering, prefer ``search`` — it's server-side and
                reduces the data transferred.

        Returns:
            List of `Domain` objects.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if offset is None and limit is None:
            domains = self._get_all_domains(search, domain_status, dcv_status)
        else:
            domains = self._get_domains_page(offset, limit, search, domain_status, dcv_status)
        if pattern is not None:
            domains = [d for d in domains if re.fullmatch(pattern, d.name or "", re.IGNORECASE)]
        return domains

    def _get_domains_page(
        self,
        offset: int | None,
        limit: int | None,
        search: str | None,
        domain_status: str | None,
        dcv_status: str | None,
    ) -> list[Domain]:
        """Fetch a single raw server page, under whichever ordering the API applies by default.

        Args:
            offset: 0-based row offset, or ``None`` to omit.
            limit: Page size, or ``None`` to omit.
            search: Server-side ``search`` filter, or ``None`` to omit.
            domain_status: Server-side ``domainStatus`` filter, or ``None`` to omit.
            dcv_status: Server-side ``dcvStatus`` filter, or ``None`` to omit.

        Returns:
            List of `Domain` objects for that one page.
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
        return [Domain.from_payload(self._client, item) for item in _extract_domain_rows(result)]

    def _get_all_domains(
        self,
        search: str | None,
        domain_status: str | None,
        dcv_status: str | None,
    ) -> list[Domain]:
        """Fetch every domain in the account via stable sortBy=domainName offset paging.

        Args:
            search: Server-side ``search`` filter, or ``None`` to omit.
            domain_status: Server-side ``domainStatus`` filter, or ``None`` to omit.
            dcv_status: Server-side ``dcvStatus`` filter, or ``None`` to omit.

        Returns:
            List of `Domain` objects for the whole account, de-duplicated by
            id (or name, if id is absent) as a defensive measure against any
            residual server-side ordering drift.
        """
        params: dict[str, Any] = {
            "sortBy": "domainName",
            "sortDir": "asc",
            "limit": _LIST_PAGE_SIZE,
        }
        if search is not None:
            params["search"] = search
        if domain_status is not None:
            params["domainStatus"] = domain_status
        if dcv_status is not None:
            params["dcvStatus"] = dcv_status

        domains: list[Domain] = []
        seen: set[str] = set()
        offset = 0
        for _ in range(_MAX_LIST_PAGES):
            result = self._client.get(_BASE, params={**params, "offset": offset})
            raw = _extract_domain_rows(result)
            if not raw:
                break
            for item in raw:
                domain = Domain.from_payload(self._client, item)
                key = domain.id or domain.name or ""
                if key in seen:
                    continue
                seen.add(key)
                domains.append(domain)
            if len(raw) < _LIST_PAGE_SIZE:
                break
            offset += _LIST_PAGE_SIZE
        else:
            log.warning(
                "get_list hit the defensive page-count ceiling; results may be incomplete",
                pages=_MAX_LIST_PAGES,
                count=len(domains),
            )
        return domains

    def get_pending_dcv(self, search: str | None = None, pattern: str | None = None) -> list[Domain]:
        """Return all active domains that have not yet completed DCV verification.

        Fetches with a server-side ``domainStatus=ACTIVE`` filter, then applies
        :attr:`Domain.needs_dcv` client-side for the DCV-status half.

        **Note (R02 partial switch, 2026-07-06):** Probe R02 confirmed the
        combined ``domainStatus``+``dcvStatus`` filter is accepted in both
        environments (2026-07-02, GitLab issue #6), so ``domainStatus=ACTIVE``
        moved server-side — it exactly matches the first conjunct of
        :attr:`~Domain.needs_dcv`. The ``dcvStatus`` half stays client-side
        deliberately: ``needs_dcv`` means *anything other than VERIFIED*, and
        the server cannot express that — ``dcvStatus=EXPIRED`` still returns
        400 (vendor #135290 open), and unknown future statuses would be
        silently excluded from an allow-list filter. Revisit when issue #6
        settles the ``DcvStatus`` enum membership.

        Args:
            search: Optional search string passed to the API. See :meth:`get_list`.
            pattern: Optional client-side regex filter. See :meth:`get_list`.

        Returns:
            List of `Domain` objects where :attr:`Domain.needs_dcv` is ``True``.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        domains = self.get_list(search=search, domain_status="ACTIVE", pattern=pattern)
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
        return Domain.from_payload(self._client, result)

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
        return Domain.from_payload(self._client, self._client.post(_BASE, json=body))

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
        return Domain.from_payload(self._client, data)
