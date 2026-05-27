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

"""Ledger Report API: account transaction history.

Provides paginated access to the account ledger statement. Uses the same
Spring-style page/size pagination as the Orders Report.
"""

from typing import Any

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

_BASE = "/api/certinext/v2/reports/ledger"


class LedgerRecord:
    """Represents a single row from the CertiNext ledger statement report.

    Instances are returned by :class:`LedgerAccessor` methods and should not
    be constructed directly. Common fields are promoted to typed properties;
    all raw API fields are accessible via :meth:`as_dict`.

    The exact set of fields returned depends on the API version and account
    type. Properties that are not present in the response return ``None``.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for entry in sess.ledger.get_list():
            print(entry.transaction_date, entry.description, entry.credit)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict for this ledger row.
        """
        self._data: dict[str, Any] = data

    @property
    def transaction_date(self) -> str | None:
        """Date and time of the transaction as an ISO 8601 string."""
        return self._data.get("transactionDate") or self._data.get("date")

    @property
    def description(self) -> str | None:
        """Human-readable description of the transaction."""
        return self._data.get("description")

    @property
    def order_number(self) -> str | None:
        """Order number associated with this transaction, if any."""
        return self._data.get("orderNumber")

    @property
    def transaction_type(self) -> str | None:
        """Type of transaction (e.g. ``"PURCHASE"``, ``"RENEWAL"``, ``"REFUND"``)."""
        return self._data.get("transactionType") or self._data.get("type")

    @property
    def debit(self) -> str | None:
        """Debit amount as a string, if applicable."""
        return self._data.get("debit")

    @property
    def credit(self) -> str | None:
        """Credit amount as a string, if applicable."""
        return self._data.get("credit")

    @property
    def balance(self) -> str | None:
        """Account balance after this transaction."""
        return self._data.get("balance")

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this ledger row."""
        return self._data

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "transaction_date": _s(self.transaction_date),
            "description": _s(self.description),
            "order_number": _s(self.order_number),
            "transaction_type": _s(self.transaction_type),
            "debit": _s(self.debit),
            "credit": _s(self.credit),
            "balance": _s(self.balance),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"LedgerRecord(transaction_date={self.transaction_date!r}, "
            f"description={self.description!r})"
        )


class LedgerAccessor:
    """Accessor for the CertiNext Ledger Report API.

    Mounted on a session as ``session.ledger``. Provides paginated access to
    the account transaction history. Uses the same 1-based page/size pagination
    as the Orders Report (maximum 100 records per page).

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        entries = sess.ledger.get_list()
        print(f"{len(entries)} transactions found")
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def get_page(
        self,
        page: int = 1,
        size: int = 100,
    ) -> list[LedgerRecord]:
        """Fetch a single page of ledger entries.

        Args:
            page: 1-based page number (default: 1).
            size: Number of records per page; maximum 100 (default: 100).

        Returns:
            List of :class:`LedgerRecord` objects for this page. Returns an
            empty list when past the last page.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        params: dict[str, Any] = {"page": page, "size": size}
        result = self._client.get(_BASE, params=params)
        raw: list[Any]
        if isinstance(result, list):
            raw = result
        else:
            raw = []
            for val in result.values():
                if isinstance(val, list):
                    raw = val
                    break
        return [LedgerRecord(item) for item in raw]

    def get_list(
        self,
        page_size: int = 100,
    ) -> list[LedgerRecord]:
        """Return all ledger entries by iterating through all pages automatically.

        Stops when a page returns fewer records than ``page_size``, indicating
        the last page has been reached.

        Args:
            page_size: Records per page; maximum 100 (default: 100).

        Returns:
            Combined list of :class:`LedgerRecord` objects from all pages.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        records: list[LedgerRecord] = []
        page = 1
        while True:
            page_records = self.get_page(page=page, size=page_size)
            records.extend(page_records)
            if len(page_records) < page_size:
                break
            page += 1
        return records
