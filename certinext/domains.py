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
from datetime import datetime, timezone
from typing import Any

import structlog

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.domains import (
    _BASE,
    VALID_DCV_METHODS,
    CaStatus,
    CertificateAuthority,
    DcvInfo,
    DcvMethod,
    DcvOption,
    DcvStatus,
    DcvVerifyResult,
    Domain,
    DomainStatus,
)

__all__ = [
    "VALID_DCV_METHODS",
    "CaStatus",
    "CertificateAuthority",
    "DcvInfo",
    "DcvMethod",
    "DcvOption",
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
# mirror's tracker, and not visible outside UMS). domainName is a documented
# sortBy value instead, so paging under it is a stable order regardless of
# account size; _LIST_PAGE_SIZE bounds each request (the API docs recommend
# limit <=200). domainName stopped being *unique* when the vendor let an
# organization hold the same name once per CA (GitLab #38): rows tied on a name
# can swap across a page boundary, skipping one. _get_all_domains() therefore
# re-fetches every name sitting on a page boundary with an exact search and
# merges by id.
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


def _filter_params(
    search: str | None,
    domain_status: str | None,
    dcv_status: str | None,
    validated_by: str | None,
) -> dict[str, Any]:
    """Build the server-side filter params shared by the list paths.

    Args:
        search: ``search`` filter, or ``None`` to omit.
        domain_status: ``domainStatus`` filter, or ``None`` to omit.
        dcv_status: ``dcvStatus`` filter, or ``None`` to omit.
        validated_by: ``validatedBy`` CA filter, or ``None`` to omit. Passed
            through upper-cased without checking against known CAs, so a
            vendor-added CA works without a library release.

    Returns:
        A dict holding only the filters that were given.
    """
    params: dict[str, Any] = {}
    if search is not None:
        params["search"] = search
    if domain_status is not None:
        params["domainStatus"] = domain_status
    if dcv_status is not None:
        params["dcvStatus"] = dcv_status
    if validated_by is not None:
        params["validatedBy"] = validated_by.upper()
    return params


def filter_needs_dcv(
    domains: list[Domain],
    all_domains: list[Domain],
    *,
    check_ns: bool = False,
) -> list[Domain]:
    """Return domains that genuinely need direct DCV validation.

    Removes any domain whose DCV would be covered by a same-organization,
    registered ancestor in *all_domains* via CertiNext's propagation rules.
    See :meth:`Domain.dcv_covering_parent` for how coverage — and the
    optional NS zone-boundary check — is determined.

    Typical usage::

        to_validate = filter_needs_dcv(pending_domains, all_domains)

    Args:
        domains: Domains to evaluate (typically only the pending-DCV subset).
        all_domains: Full list of registered domains in the account, used to
            identify covering ancestors.
        check_ns: When ``True``, query DNS for NS records and treat a zone
            boundary as blocking inheritance regardless of a same-org
            ancestor. Default is ``False`` — see
            :meth:`Domain.dcv_covering_parent` for why.

    Returns:
        Filtered list containing only domains that require direct DCV.
    """
    return [
        d for d in domains
        if d.dcv_covering_parent(all_domains, check_ns=check_ns) is None
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
        validated_by: str | None = None,
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
            validated_by: Server-side CA filter, e.g. ``"SSLCOM"`` or
                ``"EMSIGN"`` (see :data:`CertificateAuthority`; verified in
                the sandbox 2026-11-06, GitLab #38). Any string is passed
                through, so future CAs need no library change. An
                organization may hold the same name once per CA, so without
                this filter a name can appear more than once.

        Returns:
            List of `Domain` objects.

        Raises:
            re.error: If ``pattern`` is not a valid regular expression.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        filters = _filter_params(search, domain_status, dcv_status, validated_by)
        if offset is None and limit is None:
            domains = self._get_all_domains(filters)
        else:
            domains = self._get_domains_page(offset, limit, filters)
        if validated_by is not None:
            # Also filter client-side: prod's spec lacked the validatedBy filter
            # as of 2026-11-05, and an ignored filter would return every CA's rows.
            wanted = validated_by.strip().upper()
            domains = [d for d in domains if d.ca == wanted]
        if pattern is not None:
            domains = [d for d in domains if re.fullmatch(pattern, d.name or "", re.IGNORECASE)]
        return domains

    def _get_domains_page(
        self,
        offset: int | None,
        limit: int | None,
        filters: dict[str, Any],
    ) -> list[Domain]:
        """Fetch a single raw server page, under whichever ordering the API applies by default.

        Args:
            offset: 0-based row offset, or ``None`` to omit.
            limit: Page size, or ``None`` to omit.
            filters: Server-side filter params from :func:`_filter_params`.

        Returns:
            List of `Domain` objects for that one page.
        """
        params: dict[str, Any] = {}
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        params.update(filters)
        result = self._client.get(_BASE, params=params or None)
        return [Domain.from_payload(self._client, item) for item in _extract_domain_rows(result)]

    def _get_all_domains(self, filters: dict[str, Any]) -> list[Domain]:
        """Fetch every domain in the account via stable sortBy=domainName offset paging.

        Args:
            filters: Server-side filter params from :func:`_filter_params`.

        Returns:
            List of `Domain` objects for the whole account, de-duplicated by
            id (or CA + name, if id is absent) as a defensive measure against any
            residual server-side ordering drift. Two records sharing a name
            (one per CA) have distinct ids, so both are kept.
        """
        params: dict[str, Any] = {
            "sortBy": "domainName",
            "sortDir": "asc",
            "limit": _LIST_PAGE_SIZE,
            **filters,
        }

        domains: list[Domain] = []
        seen: set[str] = set()

        def _add(items: list[Any]) -> None:
            for item in items:
                domain = Domain.from_payload(self._client, item)
                # Without an id, key on CA + name: the same name is legitimately
                # held once per CA, and a bare-name key would collapse them.
                key = domain.id or f"{domain.ca}:{(domain.name or '').lower()}"
                if key in seen:
                    continue
                seen.add(key)
                domains.append(domain)

        boundary_names: set[str] = set()
        offset = 0
        for _ in range(_MAX_LIST_PAGES):
            result = self._client.get(_BASE, params={**params, "offset": offset})
            raw = _extract_domain_rows(result)
            if not raw:
                break
            _add(raw)
            if len(raw) < _LIST_PAGE_SIZE:
                break
            last = raw[-1]
            if isinstance(last, dict) and last.get("domainName"):
                boundary_names.add(str(last["domainName"]))
            offset += _LIST_PAGE_SIZE
        else:
            log.warning(
                "get_list hit the defensive page-count ceiling; results may be incomplete",
                pages=_MAX_LIST_PAGES,
                count=len(domains),
            )

        # A name held once per CA ties under sortBy=domainName; a tie straddling
        # a page boundary can drop a row. Re-fetch each boundary name exactly.
        for name in sorted(boundary_names):
            _add([
                r for r in self._get_exact_rows(name, filters)
                if isinstance(r, dict) and str(r.get("domainName", "")).lower() == name.lower()
            ])
        return domains

    def _get_exact_rows(self, name: str, filters: dict[str, Any]) -> list[Any]:
        """Return every raw row an exact-match search finds for one name, paging to the end.

        One row per CA per name means a single page suffices today, but the
        loop keeps the boundary re-fetch complete if that ever changes (Codex
        review of #38). It is bounded by :data:`_MAX_LIST_PAGES` and warns
        when it stops early.

        Args:
            name: The domain name to search for exactly.
            filters: Server-side filter params from :func:`_filter_params`.

        Returns:
            All raw rows returned across the pages, in server order.
        """
        rows: list[Any] = []
        params: dict[str, Any] = {
            **filters, "search": name, "exactMatch": "true",
            "sortBy": "domainName", "sortDir": "asc", "limit": _LIST_PAGE_SIZE,
        }
        offset = 0
        for _ in range(_MAX_LIST_PAGES):
            page = _extract_domain_rows(self._client.get(_BASE, params={**params, "offset": offset}))
            rows.extend(page)
            if len(page) < _LIST_PAGE_SIZE:
                return rows
            offset += _LIST_PAGE_SIZE
        log.warning(
            "exact-match boundary re-fetch hit the page-count ceiling; results may be incomplete",
            domain=name,
            count=len(rows),
        )
        return rows

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

    def get(self, domain_id_or_name: str, validated_by: str | None = None) -> Domain:
        """Return a single domain by ID or by fully-qualified domain name.

        The lookup strategy depends on whether the argument contains a dot:

        - **Contains a dot** (e.g. ``maine.edu``): treated as a domain name.
          All domains are fetched and the case-insensitive matches considered.
        - **No dot** (e.g. ``"dom-abc-123"``): treated as an opaque ID and the
          single-domain endpoint is called directly.

        **One name, several CAs.** An organization may hold the same name once
        per CA (GitLab #38), so a name can match more than one record. Pass
        ``validated_by`` to pick one. Without it: a single match is returned
        as before; with several, the emSign record is returned (the behavior
        callers had before other CAs existed) and a warning lists the others;
        with several and no emSign record among them, ``ValueError`` is raised
        rather than guessing between non-emSign CAs.

        **Edge case:** if a domain ID itself contains a dot, pass it via
        :meth:`get_list` and filter on :attr:`Domain.id` directly to avoid the
        ambiguity.

        Args:
            domain_id_or_name: A domain name (e.g. ``maine.edu``) or a domain ID.
            validated_by: For a name lookup, only consider the record validated
                by this CA (e.g. ``"SSLCOM"``, ``"EMSIGN"``). Ignored for an ID
                lookup, which is already unambiguous.

        Returns:
            The matching `Domain` object.

        Raises:
            KeyError: If a name lookup finds no matching domain.
            ValueError: If a name matches several non-emSign records and
                ``validated_by`` was not given, or the API returns an
                unexpected response type for an ID lookup.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if "." in domain_id_or_name:
            name = domain_id_or_name.lower()
            matches = [d for d in self.get_list(validated_by=validated_by) if (d.name or "").lower() == name]
            if not matches:
                suffix = f" validated by {validated_by.upper()}" if validated_by else ""
                raise KeyError(f"No domain found with name {domain_id_or_name!r}{suffix}")
            if len(matches) == 1:
                return matches[0]
            cas = sorted(d.ca for d in matches)
            emsign = [d for d in matches if d.is_emsign]
            if len(emsign) == 1:
                log.warning(
                    "domain name has one record per CA; returning the emSign record "
                    "(pass validated_by= to choose)",
                    domain=domain_id_or_name,
                    cas=cas,
                )
                return emsign[0]
            raise ValueError(
                f"Domain name {domain_id_or_name!r} matches {len(matches)} records (CAs: {cas}); "
                "pass validated_by= to choose one"
            )
        result = self._client.get(f"{_BASE}/{domain_id_or_name}")
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected list response for domain {domain_id_or_name!r}")
        return Domain.from_payload(self._client, result)

    def find_covering(self, name: str, ca: str, domains: list[Domain] | None = None) -> Domain | None:
        """Return the domain record that lets ``ca`` issue for ``name``, or ``None``.

        A record covers ``name`` when it is that name or a parent of it
        (``*.`` is stripped from a wildcard first), belongs to ``ca``, is
        ``ACTIVE`` and DCV ``VERIFIED``, and its DCV has not expired. The
        closest such record wins.

        **This check is deliberately liberal.** A list row cannot say whether
        a parent's validation reaches subdomains: emSign inherits by account
        setting, and an SSL.com ``dns-persist`` record covers subdomains while
        an exact-name option does not. A wrongly passed check costs a vendor
        reject at order time; a wrongly failed one would block issuance, so
        parents are assumed to cover their subdomains.

        Args:
            name: A certificate name (CN or SAN), e.g. ``www.maine.edu`` or
                ``*.maine.edu``.
            ca: The CA that will issue, e.g. ``"SSLCOM"``. The API credential
                picks the CA (ADR 0020 amendment), so this is the caller's
                statement of which CA its credential is bound to.
            domains: Records to search, e.g. from one
                ``get_list(validated_by=ca)`` call reused across names. When
                ``None`` that list is fetched.

        Returns:
            The covering :class:`Domain`, or ``None``.

        Raises:
            CertiNextAPIError: On a non-2xx API response while fetching.
        """
        wanted_ca = ca.strip().upper()
        if domains is None:
            domains = self.get_list(validated_by=wanted_ca)
        target = name.strip().lower().removeprefix("*.").rstrip(".")
        now = datetime.now(timezone.utc)
        best: Domain | None = None
        for d in domains:
            record = (d.name or "").lower().rstrip(".")
            if not record or d.ca != wanted_ca:
                continue
            if d.status != "ACTIVE" or d.dcv_status != "VERIFIED":
                continue
            if d.dcv_expires is not None and d.dcv_expires <= now:
                continue
            if target != record and not target.endswith("." + record):
                continue
            if best is None or len(record) > len(best.name or ""):
                best = d
        return best

    def uncovered_names(self, names: list[str], ca: str) -> list[str]:
        """Return the names no domain record of ``ca`` covers: an order pre-flight.

        Fetches ``ca``'s records once and applies :meth:`find_covering` to
        each name. An empty result means the order may go ahead; see
        :meth:`find_covering` for why the check errs towards passing.

        Args:
            names: The certificate's CN and SANs.
            ca: The CA the calling credential issues from, e.g. ``"SSLCOM"``.

        Returns:
            The uncovered names, in input order and without duplicates.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        domains = self.get_list(validated_by=ca)
        seen: set[str] = set()
        uncovered: list[str] = []
        for n in names:
            key = n.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            if self.find_covering(n, ca, domains) is None:
                uncovered.append(n)
        return uncovered

    def create(
        self,
        name: str,
        organization_id: str | None = None,
        dcv_method: str | None = None,
        mode: str | None = None,
        ca: str | None = None,
    ) -> Domain:
        """Create a new domain, or renew an existing independently-verified one.

        Args:
            name: The fully-qualified domain name (e.g. ``"example.com"``).
            organization_id: Organization to associate this domain with. Required
                unless your account only has a single organization.
            dcv_method: DCV method to use (e.g. ``"dns-txt"``). Required by the API.
            mode: ``"create"`` (the API default) adds a new domain and rejects an
                existing same-org domain with 409. ``"renew"`` renews an existing,
                independently-verified (ADN) domain that is expired or within its
                renewal window — inherited domains cannot be renewed this way.
            ca: Certificate authority to validate the domain (e.g.
                ``"EMSIGN"``, ``"SSLCOM"`` — see :data:`CertificateAuthority`;
                any string is passed through for future CAs). **When omitted
                the account decides** — SSL.com on an account that uses
                SSL.com, else emSign — so pass it explicitly when the DCV flow
                that follows depends on the CA. The organization may hold the
                same name once per CA. A CA the account doesn't use returns
                422; SSL.com failing to register the domain returns 502.

        Returns:
            The created or renewed :class:`Domain`.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        body: dict[str, Any] = {"domainName": name}
        if organization_id is not None:
            body["organizationId"] = organization_id
        if dcv_method is not None:
            body["dcvMethod"] = dcv_method
        if mode is not None:
            body["mode"] = mode
        if ca is not None:
            body["ca"] = ca.upper()
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
