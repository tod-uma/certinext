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

"""Read-only accessor for the v3 CLM orders API (``/api/v3/certinext/orders``)."""

from typing import Any

from ._v3 import V3_BASE, get_v3_page, iter_v3_rows
from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.v3_orders import V3CertificateInfo, V3IssuerCA, V3Order, V3OrderDetail, V3Requestor

__all__ = ["V3CertificateInfo", "V3IssuerCA", "V3Order", "V3OrderAccessor", "V3OrderDetail", "V3Requestor"]

_PATH = f"{V3_BASE}/orders"


class V3OrderAccessor:
    """Accessor for the v3 orders list and detail.

    Mounted on a session as ``session.v3_orders``. This is a different order
    set from ``session.orders`` (the v2 report): v3 includes unsubmitted
    portal drafts (``order_status == "Auto Save"``) and omits most v2
    "Order Accepted" orders, many of them ACME. Every issued certificate is
    in both. Pick the source by what you need to see.

    Only filters verified against the live API are exposed. The spec lists
    more (``orderStatus``, ``certificateStatusId``, ``fromDate``, ...); add
    each once a probe confirms it, since unverified v2 status filters
    returned 422.

    Example::

        drafts = [o for o in sess.v3_orders.get_list() if o.order_status == "Auto Save"]
        detail = sess.v3_orders.get(drafts[0].order_id)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """Initialise the accessor.

        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    @staticmethod
    def _params(exclude_ignored: bool | None) -> dict[str, Any]:
        """Build the filter parameters.

        Args:
            exclude_ignored: See :meth:`get_list`.

        Returns:
            The query parameters to send with every page.
        """
        # The API rejects true/false with 400; it wants 0 or 1.
        return {} if exclude_ignored is None else {"excludeIgnored": int(exclude_ignored)}

    def get_page(
        self, page: int = 1, page_size: int = 100, *, exclude_ignored: bool | None = None
    ) -> list[V3Order]:
        """Fetch one page of the v3 orders list.

        Args:
            page: 1-based page number.
            page_size: Rows per page (default 100).
            exclude_ignored: See :meth:`get_list`.

        Returns:
            The page's orders.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows, _ = get_v3_page(
            self._client, _PATH, "orders", page=page, page_size=page_size, params=self._params(exclude_ignored)
        )
        return [V3Order.model_validate(r) for r in rows]

    def get_list(self, page_size: int = 100, *, exclude_ignored: bool | None = None) -> list[V3Order]:
        """Return every v3 order, fetching all pages.

        A full prod walk at 100 per page took about 19 s for 1,694 orders
        (2026-11-23).

        Args:
            page_size: Rows per page (default 100).
            exclude_ignored: When set, sent as ``excludeIgnored=1``/``0``.
                Verified accepted; on 2026-11-23 it changed nothing because
                no order was marked ignored. ``None`` (default) omits it.

        Returns:
            All orders, in server order.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows = iter_v3_rows(self._client, _PATH, "orders", page_size=page_size, params=self._params(exclude_ignored))
        return [V3Order.model_validate(r) for r in rows]

    def get(self, order_id: str) -> V3OrderDetail:
        """Fetch one order's detail by its v3 ``order_id``.

        The detail has no order history (see :class:`V3OrderDetail`).

        Args:
            order_id: :attr:`V3Order.order_id`. An ``order_number`` returns
                404 "No such order.".

        Returns:
            The order detail.

        Raises:
            CertiNextNotFoundError: If no order has that id.
            CertiNextAPIError: On any other non-2xx API response.
        """
        body = self._client.get(f"{_PATH}/{order_id}")
        return V3OrderDetail.model_validate(body)
