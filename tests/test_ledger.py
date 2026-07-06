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

"""Tests for certinext.ledger: LedgerRecord and LedgerAccessor."""

from unittest.mock import MagicMock

from certinext.client import CertiNextClient
from certinext.ledger import LedgerAccessor, LedgerRecord

_BASE_URL = "/api/certinext/v2/reports/ledger"


def _make_client() -> tuple[CertiNextClient, MagicMock]:
    """Return a CertiNextClient with auth and HTTP session mocked out."""
    client = CertiNextClient(
        base_url="https://us-api.certinext.io",
        token_url="https://us-api.certinext.io/oauth/token",
        client_id="test",
        client_secret="secret",
    )
    client._auth = MagicMock()
    client._auth.get_token.return_value = "test-token"
    mock_session = MagicMock()
    client._session = mock_session  # type: ignore[assignment]
    return client, mock_session


def _ok_response(payload: object) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.is_error = False
    resp.json.return_value = payload
    resp.content = b"{}"
    return resp


def _make_record(n: int = 1) -> dict:
    return {
        "transactionDate": f"2026-05-0{n}T00:00:00Z",
        "description": f"DV SSL Certificate #{n}",
        "orderNumber": f"ORD-00{n}",
        "transactionType": "PURCHASE",
        "debit": "50.00",
        "credit": None,
        "balance": str(1000 - n * 50),
    }


# ---------------------------------------------------------------------------
# LedgerRecord
# ---------------------------------------------------------------------------

class TestLedgerRecordProperties:
    """LedgerRecord exposes expected properties."""

    _DATA = _make_record()

    def test_transaction_date(self):
        """transaction_date reads transactionDate."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.transaction_date == "2026-05-01T00:00:00Z"

    def test_transaction_date_falls_back_to_date(self):
        """transaction_date falls back to 'date' when transactionDate is absent."""
        record = LedgerRecord.model_validate({"date": "2026-05-01"})
        assert record.transaction_date == "2026-05-01"

    def test_description(self):
        """description reads description."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.description == "DV SSL Certificate #1"

    def test_order_number(self):
        """order_number reads orderNumber."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.order_number == "ORD-001"

    def test_transaction_type(self):
        """transaction_type reads transactionType."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.transaction_type == "PURCHASE"

    def test_transaction_type_falls_back_to_type(self):
        """transaction_type falls back to 'type' when transactionType is absent."""
        record = LedgerRecord.model_validate({"type": "RENEWAL"})
        assert record.transaction_type == "RENEWAL"

    def test_debit(self):
        """debit reads debit."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.debit == "50.00"

    def test_credit_none_when_null(self):
        """credit returns None when the field is None."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.credit is None

    def test_balance(self):
        """balance reads balance."""
        record = LedgerRecord.model_validate(self._DATA)
        assert record.balance == "950"

    def test_missing_fields_return_none(self):
        """Missing fields return None."""
        record = LedgerRecord.model_validate({})
        assert record.transaction_date is None
        assert record.description is None
        assert record.order_number is None
        assert record.transaction_type is None
        assert record.debit is None
        assert record.credit is None
        assert record.balance is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        data = _make_record()
        record = LedgerRecord.model_validate(data)
        assert record.as_dict() is data


class TestLedgerRecordToRow:
    """LedgerRecord.to_row() returns a flat dict[str, str]."""

    def test_to_row_keys(self):
        """to_row() includes all expected keys."""
        record = LedgerRecord.model_validate(_make_record())
        row = record.to_row()
        expected_keys = {
            "transaction_date", "description", "order_number",
            "transaction_type", "debit", "credit", "balance",
        }
        assert set(row.keys()) == expected_keys

    def test_to_row_values_are_strings(self):
        """to_row() returns string values for all keys."""
        record = LedgerRecord.model_validate(_make_record())
        row = record.to_row()
        assert all(isinstance(v, str) for v in row.values())

    def test_to_row_none_becomes_empty_string(self):
        """to_row() converts None fields to empty string."""
        record = LedgerRecord.model_validate({"credit": None})
        row = record.to_row()
        assert row["credit"] == ""

    def test_to_row_populated_values(self):
        """to_row() returns the correct values from the record data."""
        record = LedgerRecord.model_validate(_make_record(1))
        row = record.to_row()
        assert row["description"] == "DV SSL Certificate #1"
        assert row["order_number"] == "ORD-001"
        assert row["debit"] == "50.00"

    def test_repr_contains_date_and_description(self):
        """repr() includes transaction_date and description."""
        record = LedgerRecord.model_validate(_make_record(1))
        r = repr(record)
        assert "2026-05-01" in r
        assert "DV SSL Certificate #1" in r


# ---------------------------------------------------------------------------
# LedgerAccessor.get_page
# ---------------------------------------------------------------------------

class TestLedgerAccessorGetPage:
    """LedgerAccessor.get_page() fetches a single page of records."""

    def test_calls_ledger_endpoint(self):
        """get_page() GETs the ledger report endpoint."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([_make_record()])
        accessor = LedgerAccessor(client)
        accessor.get_page()
        url = mock_session.get.call_args[0][0]
        assert _BASE_URL in url

    def test_sends_page_and_size_params(self):
        """get_page() passes page and size as query parameters."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        accessor = LedgerAccessor(client)
        accessor.get_page(page=2, size=50)
        _, kwargs = mock_session.get.call_args
        assert kwargs["params"]["page"] == 2
        assert kwargs["params"]["size"] == 50

    def test_returns_list_of_ledger_records(self):
        """get_page() returns a list of LedgerRecord instances."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([_make_record(1), _make_record(2)])
        accessor = LedgerAccessor(client)
        records = accessor.get_page()
        assert len(records) == 2
        assert all(isinstance(r, LedgerRecord) for r in records)

    def test_handles_wrapped_response(self):
        """get_page() unwraps a Spring-style {content: [...]} response."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"content": [_make_record()]})
        accessor = LedgerAccessor(client)
        records = accessor.get_page()
        assert len(records) == 1
        assert isinstance(records[0], LedgerRecord)

    def test_returns_empty_list_past_last_page(self):
        """get_page() returns [] when the API returns an empty list."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        accessor = LedgerAccessor(client)
        assert accessor.get_page(page=99) == []


# ---------------------------------------------------------------------------
# LedgerAccessor.get_list
# ---------------------------------------------------------------------------

class TestLedgerAccessorGetList:
    """LedgerAccessor.get_list() auto-paginates through all pages."""

    def test_single_page(self):
        """get_list() returns all records when they fit on one page."""
        client, mock_session = _make_client()
        records = [_make_record(i) for i in range(1, 4)]
        mock_session.get.return_value = _ok_response(records)
        accessor = LedgerAccessor(client)
        result = accessor.get_list(page_size=100)
        assert len(result) == 3
        assert mock_session.get.call_count == 1

    def test_multi_page(self):
        """get_list() fetches multiple pages when the first is full."""
        client, mock_session = _make_client()
        page1 = [_make_record(i) for i in range(1, 3)]  # 2 records
        page2 = [_make_record(3)]                         # 1 record (partial)
        mock_session.get.side_effect = [
            _ok_response(page1),
            _ok_response(page2),
        ]
        accessor = LedgerAccessor(client)
        result = accessor.get_list(page_size=2)
        assert len(result) == 3
        assert mock_session.get.call_count == 2

    def test_empty_account(self):
        """get_list() returns [] when no ledger records exist."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        accessor = LedgerAccessor(client)
        result = accessor.get_list()
        assert result == []
        assert mock_session.get.call_count == 1

    def test_exact_full_page_fetches_next(self):
        """get_list() fetches the next page when the current page is exactly full."""
        client, mock_session = _make_client()
        page1 = [_make_record(i) for i in range(1, 3)]  # 2 records = full page
        page2: list = []                                   # empty = last page
        mock_session.get.side_effect = [
            _ok_response(page1),
            _ok_response(page2),
        ]
        accessor = LedgerAccessor(client)
        result = accessor.get_list(page_size=2)
        assert len(result) == 2
        assert mock_session.get.call_count == 2

    def test_wrapper_total_pages_terminates(self):
        """get_list() stops at the wrapper's totalPages instead of fetching further."""
        client, mock_session = _make_client()
        mock_session.get.side_effect = [
            _ok_response({"content": [_make_record(1), _make_record(2)], "totalElements": 3, "totalPages": 2}),
            _ok_response({"content": [_make_record(3)], "totalElements": 3, "totalPages": 2}),
        ]
        accessor = LedgerAccessor(client)
        result = accessor.get_list(page_size=2)
        assert len(result) == 3
        assert mock_session.get.call_count == 2

    def test_wrapper_exact_multiple_no_infinite_loop(self):
        """A total that is an exact multiple of page_size must not refetch the clamped last page.

        The server clamps out-of-range pages to the last page (probe R16,
        2026-07-02), so without totalPages termination a full final page
        would be refetched forever.
        """
        client, mock_session = _make_client()
        full_last = {"content": [_make_record(1), _make_record(2)], "totalElements": 2, "totalPages": 1}
        mock_session.get.side_effect = [_ok_response(full_last)] * 3
        accessor = LedgerAccessor(client)
        result = accessor.get_list(page_size=2)
        assert len(result) == 2
        assert mock_session.get.call_count == 1
