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

"""Read-only accessor for the v3 CLM audit log (``/api/v3/certinext/audit-logs``)."""

from datetime import date
from typing import Any

from ._v3 import V3_BASE, get_v3_page, iter_v3_rows
from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.audit import AuditLogEntry

__all__ = ["AuditAccessor", "AuditLogEntry"]

_PATH = f"{V3_BASE}/audit-logs"


class AuditAccessor:
    """Accessor for the account audit log.

    Mounted on a session as ``session.audit``. The date filter is by whole
    day and timestamps have minute resolution, so an incremental reader
    should re-read an overlapping day and de-duplicate on
    :attr:`AuditLogEntry.audit_log_id`.

    Example::

        from datetime import date, timedelta
        since = date.today() - timedelta(days=1)
        for entry in sess.audit.get_list(since=since):
            print(entry.timestamp, entry.module, entry.activity)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """Initialise the accessor.

        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    @staticmethod
    def _params(since: date | None, until: date | None) -> dict[str, Any]:
        """Build the date-filter parameters.

        Args:
            since: See :meth:`get_list`.
            until: See :meth:`get_list`.

        Returns:
            The query parameters to send with every page.
        """
        params: dict[str, Any] = {}
        if since is not None:
            params["fromDate"] = since.isoformat()
        if until is not None:
            params["toDate"] = until.isoformat()
        return params

    def get_page(
        self, page: int = 1, page_size: int = 100, *, since: date | None = None, until: date | None = None
    ) -> list[AuditLogEntry]:
        """Fetch one page of audit records.

        Args:
            page: 1-based page number.
            page_size: Rows per page (default 100).
            since: See :meth:`get_list`.
            until: See :meth:`get_list`.

        Returns:
            The page's records.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows, _ = get_v3_page(
            self._client, _PATH, "auditLogs", page=page, page_size=page_size, params=self._params(since, until)
        )
        return [AuditLogEntry.model_validate(r) for r in rows]

    def get_list(
        self, page_size: int = 100, *, since: date | None = None, until: date | None = None
    ) -> list[AuditLogEntry]:
        """Return every audit record in the window, fetching all pages.

        Args:
            page_size: Rows per page (default 100).
            since: First day to include, sent as ``fromDate`` (``YYYY-MM-DD``).
                Verified 2026-11-23: a seven-day window returned 120 of
                3,202 records, and a ten-year window the full total.
            until: Last day to include, sent as ``toDate``.

        Returns:
            All matching records, in server order (newest first on the
            captured pages).

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows = iter_v3_rows(self._client, _PATH, "auditLogs", page_size=page_size, params=self._params(since, until))
        return [AuditLogEntry.model_validate(r) for r in rows]

    def list_modules(self) -> list[str]:
        """Return the audit module names (24 in prod, 12 in sandbox on 2026-11-23).

        Returns:
            Module names as the API lists them.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        body = self._client.get(f"{_PATH}/modules")
        return [str(m) for m in body] if isinstance(body, list) else []
