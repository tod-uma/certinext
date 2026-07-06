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

from typing import Any, Literal

import structlog

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

log = structlog.get_logger()

_BASE = "/api/certinext/v2/reports/orders"

CertificateStatus = Literal[
    "pending-dcv",
    "pending-organization-verification",
    "pending-csr",
    "pending-documents",
    "pending-agreement",
    "pending-approval",
    "issued",
    "revoked",
    "cancelled",
    "rejected",
    "expired",
    "unknown",
]
"""Valid ``certificateStatus`` values returned by :attr:`OrderRecord.certificate_status`.

.. note::
    The orders report API returns human-readable display strings (e.g.
    ``"Pending for Approver"``, ``"Certificate Downloaded"``) rather than these
    enum values. :attr:`OrderRecord.certificate_status` passes them through as-is;
    do not compare against this ``Literal`` type at runtime. Use
    :attr:`OrderRecord.order_status` (``"Order Fulfilled"`` / ``"Order Accepted"``)
    for reliable programmatic checks.
"""


class OrderRecord:
    """Represents a single row from the CertiNext orders report.

    Instances are returned by `OrderAccessor` methods and should not be
    constructed directly. All API response fields are exposed as read-only
    properties.

    The ``common_name`` property attempts to locate the certificate's primary
    domain from multiple candidate field names (``commonName``, ``cn``,
    ``domain``, ``domainName``). If the orders report response does not include
    a domain field, ``common_name`` returns ``None``.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for order in sess.orders.get_list(status="issued"):
            print(order.common_name, order.certificate_status)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict for this order row.
        """
        self._data: dict[str, Any] = data

    # --- properties ---

    @property
    def order_number(self) -> str | None:
        """Unique order number assigned by CertiNext."""
        return self._data.get("orderNumber")

    @property
    def request_number(self) -> str | None:
        """Request number associated with this order."""
        return self._data.get("requestNumber")

    @property
    def product_code(self) -> str | None:
        """Certificate product code (e.g. ``OV_SSL``, ``DV_SSL``)."""
        return self._data.get("productCode")

    @property
    def order_status(self) -> str | None:
        """High-level order status string."""
        return self._data.get("orderStatus")

    @property
    def certificate_status(self) -> CertificateStatus | None:
        """Certificate lifecycle status.

        Common values: ``issued``, ``expired``, ``revoked``, ``pending-dcv``.
        See `CertificateStatus` for the full set.
        """
        return self._data.get("certificateStatus")

    @property
    def common_name(self) -> str | None:
        """Common name (primary domain) of the certificate.

        Tries the field names ``commonName``, ``cn``, ``domain``, and
        ``domainName`` in order. Returns ``None`` if none are present.
        """
        return (
            self._data.get("commonName")
            or self._data.get("cn")
            or self._data.get("domain")
            or self._data.get("domainName")
            or None
        )

    # --- helpers ---

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this order."""
        return self._data

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "common_name": _s(self.common_name),
            "certificate_status": _s(self.certificate_status),
            "order_status": _s(self.order_status),
            "order_number": _s(self.order_number),
            "product_code": _s(self.product_code),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"OrderRecord(order_number={self.order_number!r}, "
            f"common_name={self.common_name!r}, "
            f"certificate_status={self.certificate_status!r})"
        )


class OrderAccessor:
    """Accessor for the CertiNext Orders Report API.

    Mounted on a session as ``session.orders``. Provides methods to list order
    history with optional status filtering. All pages are automatically fetched
    by :meth:`get_list`; single-page access is available via :meth:`get_page`.

    The orders endpoint uses 1-based ``page`` / ``size`` pagination (max 100
    per page), unlike the Domains endpoint which uses offset/limit.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        issued = sess.orders.get_list(status="issued")
        expired = sess.orders.get_list(status="expired")
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def _fetch_page(
        self,
        page: int,
        size: int,
        status: str | None = None,
    ) -> tuple[list[Any], int | None]:
        """Fetch one raw report page plus the server-reported total page count.

        Args:
            page: 1-based page number.
            size: Number of records per page; maximum 100.
            status: Optional certificate status filter passed to the API.

        Returns:
            ``(rows, total_pages)`` — ``total_pages`` is taken from the
            wrapper dict's ``totalPages`` key and is ``None`` when the
            response is a bare array (or the key is missing).

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        params: dict[str, Any] = {"page": page, "size": size}
        if status is not None:
            params["status"] = status
        result = self._client.get(_BASE, params=params)
        if isinstance(result, list):
            return result, None
        raw: list[Any] = []
        for val in result.values():
            if isinstance(val, list):
                raw = val
                break
        total_pages = result.get("totalPages")
        return raw, total_pages if isinstance(total_pages, int) else None

    def get_page(
        self,
        page: int = 1,
        size: int = 100,
        status: str | None = None,
    ) -> list[OrderRecord]:
        """Fetch a single page of orders from the report endpoint.

        Note:
            The server clamps out-of-range page numbers to the valid range
            (confirmed 2026-07-02, probe R16): requesting a page past the
            last one returns the *last page's* rows again, never an empty
            list. Use :meth:`get_list` to fetch everything safely.

        Args:
            page: 1-based page number (default: 1).
            size: Number of records per page; maximum 100 (default: 100).
            status: Optional certificate status filter (e.g. ``"issued"``,
                ``"expired"``). Passed directly to the API ``status`` param.

        Returns:
            List of `OrderRecord` objects for this page.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw, _ = self._fetch_page(page, size, status)
        return [OrderRecord(item) for item in raw]

    def get_list(
        self,
        status: str | None = None,
        page_size: int = 100,
    ) -> list[OrderRecord]:
        """Return all orders by iterating through all pages automatically.

        Terminates on the wrapper's ``totalPages`` when the server provides
        it. Short-page termination alone is unsafe because the server clamps
        out-of-range pages to the last page instead of returning an empty
        list: when the total is an exact multiple of ``page_size``, the page
        after the last would repeat the last page forever. The short-page
        rule remains only as a fallback for bare-array responses.

        Args:
            status: Optional certificate status filter (e.g. ``"issued"``,
                ``"expired"``). Passed to the API ``status`` param each page.
            page_size: Records per page; maximum 100 (default: 100).

        Returns:
            Combined list of `OrderRecord` objects from all pages.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        records: list[OrderRecord] = []
        page = 1
        while True:
            raw, total_pages = self._fetch_page(page, page_size, status)
            records.extend(OrderRecord(item) for item in raw)
            if total_pages is not None:
                if page >= total_pages:
                    break
            elif len(raw) < page_size:
                break
            page += 1
        return records

    def find_by_domain(
        self,
        domain: str,
        status: str | None = "issued",
        page_size: int = 100,
    ) -> list[OrderRecord]:
        """Return orders whose CN matches ``domain`` (case-insensitive).

        The orders report API has no server-side domain filter, so this
        fetches all pages for the given ``status`` and filters client-side.
        Call with ``status=None`` to search across all certificate statuses.

        This method does not run automatically — callers must invoke it
        explicitly. The ``certinext-issue-cert`` CLI calls it before creating
        an order (disable with ``--no-domain-check``).

        Args:
            domain: Primary domain name to match against order CNs.
            status: Certificate status to filter by (default: ``"issued"``).
                Pass ``None`` to include all statuses.
            page_size: Records per page; maximum 100 (default: 100).

        Returns:
            List of :class:`OrderRecord` objects whose
            :attr:`~OrderRecord.common_name` matches ``domain``
            case-insensitively.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.

        Example::

            matches = sess.orders.find_by_domain("example.maine.edu")
            if matches:
                print(f"Active cert: order {matches[0].order_number}")
        """
        domain_lower = domain.lower()
        all_records = self.get_list(status=status, page_size=page_size)
        log.debug("find_by_domain total orders", count=len(all_records))
        return [r for r in all_records if (r.common_name or "").lower() == domain_lower]
