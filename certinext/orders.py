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

from typing import Any

import structlog

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.orders import CertificateStatus, OrderRecord

__all__ = ["CertificateStatus", "OrderAccessor", "OrderRecord"]

log = structlog.get_logger()

_BASE = "/api/certinext/v2/reports/orders"

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
            status: Optional order status filter passed to the API (e.g.
                ``"issued"``, ``"expired"`` — see :meth:`get_list` for the
                distinction from :attr:`OrderRecord.certificate_status`).

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
            status: Optional order status filter (e.g. ``"issued"``,
                ``"expired"``). Passed directly to the API ``status`` param
                — see :meth:`get_list` for why this does not guarantee
                anything about the returned records' ``certificate_status``.

        Returns:
            List of `OrderRecord` objects for this page.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw, _ = self._fetch_page(page, size, status)
        return [OrderRecord.model_validate(item) for item in raw if isinstance(item, dict)]

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
            status: Optional order status filter (e.g. ``"issued"``,
                ``"expired"``; the vendor's documented enum also includes
                the pending-* / revoked / cancelled / rejected order
                states). Passed to the API ``status`` param each page.

                This filters on ORDER status, a field independent of the
                returned records' :attr:`OrderRecord.certificate_status` —
                do not assume ``status="issued"`` implies
                ``certificate_status == "issued"`` on the results (the
                vendor sends human display strings for certificate_status,
                e.g. ``"Certificate Downloaded"`` once a customer downloads
                an already-issued cert; see :attr:`OrderRecord.order_status`
                for a more reliable programmatic check, and
                :class:`~certinext.models.orders.CertificateStatus` for
                more detail).
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
            records.extend(OrderRecord.model_validate(item) for item in raw if isinstance(item, dict))
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
        Call with ``status=None`` to search across all order statuses.

        This method does not run automatically — callers must invoke it
        explicitly. The ``certinext-issue-cert`` CLI calls it before creating
        an order (disable with ``--no-domain-check``).

        Args:
            domain: Primary domain name to match against order CNs.
            status: Order status to filter by (default: ``"issued"`` — see
                :meth:`get_list` for what this does and doesn't guarantee
                about the results). Pass ``None`` to include all statuses.
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
