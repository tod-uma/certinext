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

"""Shared envelope and paging helpers for the v3 CLM paths (``/api/v3/certinext/``).

v3 list envelopes differ from v2:

- ``totalResults``, ``pageNumber`` and ``pageSize`` plus one list key that
  differs per path (``orders``, ``auditLogs``, ``users``, ``customRoles``,
  ``credentials``, ``members``). The orders envelope sends the three numbers
  as strings.
- There is no ``totalPages``.
- The page-size parameter is ``pageSize`` on most paths but ``recordLimit``
  on ``users`` and ``users/roles``, where ``pageSize`` is silently ignored
  and the page defaults to 20.

:func:`iter_v3_rows` stops on whichever comes first: the reported total, a
short page, or a page identical to the previous one (the v2 report repeats
its last page past the end; v3 is unverified, so guard anyway).
"""

from collections.abc import Iterator
from typing import Any, Literal

import structlog

from .client import CertiNextClient

log = structlog.get_logger()

V3_BASE = "/api/v3/certinext"
"""Path prefix of every v3 CLM endpoint."""

SizeParam = Literal["pageSize", "recordLimit"]


def _as_int(value: Any) -> int | None:
    """Return ``value`` as an int when it is an int or a digit string.

    Args:
        value: A wire value such as ``totalResults``.

    Returns:
        The integer, or ``None`` when absent or not numeric.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def unwrap_v3(body: Any, list_key: str) -> tuple[list[dict[str, Any]], int | None]:
    """Split a v3 response body into its row dicts and reported total.

    Args:
        body: The decoded JSON body (an envelope dict or a bare list).
        list_key: The envelope key holding the rows.

    Returns:
        ``(rows, total)``. ``rows`` holds only dict items; ``total`` is
        ``totalResults`` as an int, or ``None`` for a bare list or a missing
        or non-numeric total.
    """
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)], None
    if not isinstance(body, dict):
        return [], None
    rows = body.get(list_key)
    if not isinstance(rows, list):
        rows = []
    return [r for r in rows if isinstance(r, dict)], _as_int(body.get("totalResults"))


def get_v3_page(
    client: CertiNextClient,
    path: str,
    list_key: str,
    *,
    page: int = 1,
    page_size: int = 100,
    size_param: SizeParam = "pageSize",
    params: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Fetch one page of a v3 list.

    Args:
        client: The HTTP client.
        path: Full API path (``V3_BASE`` + endpoint).
        list_key: The envelope key holding the rows.
        page: 1-based page number.
        page_size: Rows per page.
        size_param: The page-size parameter name this path takes.
        params: Extra query parameters (filters).

    Returns:
        ``(rows, total)`` as :func:`unwrap_v3` returns them.

    Raises:
        CertiNextAPIError: On a non-2xx API response.
    """
    query = {**(params or {}), "pageNumber": page, size_param: page_size}
    return unwrap_v3(client.get(path, params=query), list_key)


def iter_v3_rows(
    client: CertiNextClient,
    path: str,
    list_key: str,
    *,
    page_size: int = 100,
    size_param: SizeParam = "pageSize",
    params: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield every row of a paged v3 list, fetching pages as needed.

    Stops on the reported ``totalResults``, on a short page, or on a page
    identical to the previous one (logged as a warning, since it means the
    server clamped an out-of-range page).

    Args:
        client: The HTTP client.
        path: Full API path (``V3_BASE`` + endpoint).
        list_key: The envelope key holding the rows.
        page_size: Rows per page.
        size_param: The page-size parameter name this path takes.
        params: Extra query parameters (filters), sent on every page.

    Yields:
        Each row dict, in server order.

    Raises:
        ValueError: If ``page_size`` is less than 1.
        CertiNextAPIError: On a non-2xx API response.
    """
    if page_size < 1:
        raise ValueError(f"page_size must be at least 1, got {page_size}")
    page = 1
    seen = 0
    previous: list[dict[str, Any]] | None = None
    while True:
        rows, total = get_v3_page(
            client, path, list_key, page=page, page_size=page_size, size_param=size_param, params=params
        )
        if previous is not None and rows and rows == previous:
            log.warning("v3_page_repeated", path=path, page=page, rows_seen=seen, total=total)
            return
        yield from rows
        seen += len(rows)
        if len(rows) < page_size or (total is not None and seen >= total):
            return
        previous = rows
        page += 1
