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

"""Tests that verify graceful error handling for bad data and failed API calls."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from certinext.auth import OAuth2ClientCredentials
from certinext.domains import Domain, DomainAccessor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain(client: MagicMock, data: dict) -> Domain:
    """Construct a Domain from a mock client and a raw data dict."""
    return Domain(client, data)


def _make_auth() -> OAuth2ClientCredentials:
    """Return an OAuth2ClientCredentials with test defaults."""
    return OAuth2ClientCredentials(
        token_url="https://us-api.certinext.io/oauth/token",
        client_id="test-account",
        client_secret="test-secret",
    )


def _make_http_error_response(status_code: int) -> MagicMock:
    """Return a mock response that raises HTTPError on raise_for_status."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status.side_effect = requests.HTTPError(
        f"{status_code} Error", response=resp
    )
    return resp


# ---------------------------------------------------------------------------
# Domain — bad field data
# ---------------------------------------------------------------------------

class TestDomainBadFieldData:
    """Domain properties return safe values when the API sends malformed data."""

    def test_malformed_created_at_returns_none(self, mock_client: MagicMock):
        """created_at returns None when createdAt is not a parseable date string."""
        d = _domain(mock_client, {"createdAt": "not-a-date"})
        assert d.created_at is None

    def test_integer_created_at_returns_none(self, mock_client: MagicMock):
        """created_at returns None when createdAt is an integer Unix timestamp."""
        d = _domain(mock_client, {"createdAt": 1746396434})
        assert d.created_at is None

    def test_empty_string_created_at_returns_none(self, mock_client: MagicMock):
        """created_at returns None when createdAt is an empty string."""
        d = _domain(mock_client, {"createdAt": ""})
        assert d.created_at is None

    def test_null_created_at_returns_none(self, mock_client: MagicMock):
        """created_at returns None when createdAt is explicitly null."""
        d = _domain(mock_client, {"createdAt": None})
        assert d.created_at is None

    def test_missing_created_at_returns_none(self, mock_client: MagicMock):
        """created_at returns None when the createdAt field is absent."""
        d = _domain(mock_client, {"domainId": "abc", "domainName": "test.example.edu"})
        assert d.created_at is None

    def test_null_name_returns_none(self, mock_client: MagicMock):
        """name returns None when domainName is explicitly null."""
        d = _domain(mock_client, {"domainId": "abc", "domainName": None})
        assert d.name is None

    def test_all_fields_missing_returns_none_for_all_properties(self, mock_client: MagicMock):
        """All properties return None when the API returns an empty dict."""
        d = _domain(mock_client, {})
        assert d.id is None
        assert d.name is None
        assert d.status is None
        assert d.dcv_status is None
        assert d.organization_id is None
        assert d.organization_name is None
        assert d.created_at is None

    def test_extra_unknown_fields_do_not_raise(self, mock_client: MagicMock):
        """Domain does not raise when the API response includes unrecognised fields."""
        d = _domain(mock_client, {
            "domainId": "abc",
            "domainName": "test.example.edu",
            "unknownField": "some value",
            "anotherUnknown": 42,
            "nestedUnknown": {"key": "value"},
        })
        assert d.id == "abc"
        assert d.name == "test.example.edu"

    def test_str_with_null_name_does_not_raise(self, mock_client: MagicMock):
        """str() does not raise when domainName is None."""
        d = _domain(mock_client, {"domainId": "abc", "domainName": None})
        result = str(d)
        assert isinstance(result, str)

    def test_str_with_empty_dict_does_not_raise(self, mock_client: MagicMock):
        """str() does not raise when all fields are missing."""
        d = _domain(mock_client, {})
        result = str(d)
        assert isinstance(result, str)

    def test_repr_with_empty_dict_does_not_raise(self, mock_client: MagicMock):
        """repr() does not raise when all fields are missing."""
        d = _domain(mock_client, {})
        result = repr(d)
        assert result.startswith("Domain(")

    def test_to_row_with_missing_fields_returns_empty_strings(self, mock_client: MagicMock):
        """to_row() returns empty strings for all missing fields."""
        d = _domain(mock_client, {})
        row = d.to_row()
        assert all(v == "" for v in row.values())

    def test_to_row_with_null_name_returns_empty_string(self, mock_client: MagicMock):
        """to_row() converts a null name to an empty string."""
        d = _domain(mock_client, {"domainName": None})
        assert d.to_row()["name"] == ""

    def test_as_dict_returns_raw_data_including_unknown_fields(self, mock_client: MagicMock):
        """as_dict() returns the full raw dict even when it contains unknown fields."""
        raw = {"domainId": "abc", "unknownField": "value"}
        d = _domain(mock_client, raw)
        assert d.as_dict() is raw


class TestDomainBadDataFixture:
    """Run the complete bad-data fixture file through Domain construction."""

    def test_all_bad_entries_construct_without_raising(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """Every entry in the bad-data fixture can be wrapped in a Domain without raising."""
        for entry in bad_domain_data:
            Domain(mock_client, entry)  # must not raise

    def test_all_bad_entries_support_str(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """str() succeeds for every bad-data entry."""
        for entry in bad_domain_data:
            str(Domain(mock_client, entry))  # must not raise

    def test_all_bad_entries_support_repr(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """repr() succeeds for every bad-data entry."""
        for entry in bad_domain_data:
            repr(Domain(mock_client, entry))  # must not raise

    def test_all_bad_entries_support_to_row(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """to_row() succeeds for every bad-data entry and returns only strings."""
        for entry in bad_domain_data:
            row = Domain(mock_client, entry).to_row()
            assert all(isinstance(v, str) for v in row.values())

    def test_all_bad_entries_created_at_is_none_or_datetime(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """created_at is either None or a datetime — never raises."""
        from datetime import datetime
        for entry in bad_domain_data:
            result = Domain(mock_client, entry).created_at
            assert result is None or isinstance(result, datetime)


# ---------------------------------------------------------------------------
# DomainAccessor — unexpected API response shapes
# ---------------------------------------------------------------------------

class TestDomainAccessorBadResponses:
    """DomainAccessor handles unexpected response shapes without crashing."""

    def test_list_with_empty_dict_returns_empty_list(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """list() returns [] when the API returns an empty dict."""
        mock_client.get.return_value = {}
        assert accessor.list() == []

    def test_list_with_dict_containing_no_list_values_returns_empty(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """list() returns [] when the dict response has no list-typed values."""
        mock_client.get.return_value = {"total": 0, "page": 1}
        assert accessor.list() == []

    def test_list_with_empty_nested_list_returns_empty(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """list() returns [] when the nested list in a paginated response is empty."""
        mock_client.get.return_value = {"total": 0, "domains": []}
        assert accessor.list() == []

    def test_get_by_id_raises_value_error_when_api_returns_list(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get() by ID raises ValueError when the API unexpectedly returns a list."""
        mock_client.get.return_value = [{"domainId": "abc"}]
        with pytest.raises(ValueError, match="Unexpected list response"):
            accessor.get("SomeDomainIdWithoutADot")

    def test_get_by_name_raises_key_error_on_empty_list(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get() by name raises KeyError when the API returns an empty list."""
        mock_client.get.return_value = []
        with pytest.raises(KeyError, match="notfound.example.edu"):
            accessor.get("notfound.example.edu")

    def test_get_by_name_raises_key_error_on_no_match(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get() by name raises KeyError when no domain in the list matches."""
        mock_client.get.return_value = [
            {"domainId": "abc", "domainName": "other.example.edu"}
        ]
        with pytest.raises(KeyError, match="wanted.example.edu"):
            accessor.get("wanted.example.edu")


# ---------------------------------------------------------------------------
# Auth — failed token requests
# ---------------------------------------------------------------------------

class TestAuthErrorMessages:
    """RuntimeError messages include diagnostic details for easy debugging."""

    def test_http_error_message_includes_status_code(self):
        """RuntimeError from a failed token request includes the HTTP status code."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.ok = False
        bad_resp.status_code = 401
        bad_resp.reason = "Unauthorized"
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = '{"error": "invalid_client"}'

        with patch("certinext.auth.requests.post", return_value=bad_resp):
            with pytest.raises(RuntimeError, match="401"):
                auth.get_token()

    def test_http_error_message_includes_url(self):
        """RuntimeError from a failed token request includes the endpoint URL."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.ok = False
        bad_resp.status_code = 401
        bad_resp.reason = "Unauthorized"
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = ""

        with patch("certinext.auth.requests.post", return_value=bad_resp):
            with pytest.raises(RuntimeError, match="us-api.certinext.io"):
                auth.get_token()

    def test_non_json_error_message_includes_body_excerpt(self):
        """RuntimeError from a non-JSON response includes the raw response body."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.ok = True
        bad_resp.status_code = 200
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = "<html>Service Unavailable</html>"
        bad_resp.json.side_effect = ValueError("No JSON")

        with patch("certinext.auth.requests.post", return_value=bad_resp):
            with pytest.raises(RuntimeError, match="non-JSON"):
                auth.get_token()

    def test_403_raises_runtime_error(self):
        """A 403 Forbidden response raises RuntimeError."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.ok = False
        bad_resp.status_code = 403
        bad_resp.reason = "Forbidden"
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = "Forbidden"

        with patch("certinext.auth.requests.post", return_value=bad_resp):
            with pytest.raises(RuntimeError):
                auth.get_token()

    def test_500_raises_runtime_error(self):
        """A 500 Internal Server Error response raises RuntimeError."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.ok = False
        bad_resp.status_code = 500
        bad_resp.reason = "Internal Server Error"
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = "Internal Server Error"

        with patch("certinext.auth.requests.post", return_value=bad_resp):
            with pytest.raises(RuntimeError):
                auth.get_token()


# ---------------------------------------------------------------------------
# Client — HTTP errors from API endpoints
# ---------------------------------------------------------------------------

class TestClientHTTPErrors:
    """CertiNextClient propagates HTTPError for non-2xx API responses."""

    def _make_client(self):
        """Return a CertiNextClient with auth and session mocked."""
        from certinext.client import CertiNextClient
        client = CertiNextClient(
            base_url="https://us-api.certinext.io",
            token_url="https://us-api.certinext.io/oauth/token",
            client_id="test",
            client_secret="secret",
        )
        client._auth = MagicMock()
        client._auth.get_token.return_value = "test-token"
        client._session = MagicMock()
        return client

    def test_get_raises_on_401(self):
        """get() propagates HTTPError on a 401 Unauthorized response."""
        client = self._make_client()
        client._session.get.return_value = _make_http_error_response(401)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_get_raises_on_403(self):
        """get() propagates HTTPError on a 403 Forbidden response."""
        client = self._make_client()
        client._session.get.return_value = _make_http_error_response(403)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_get_raises_on_404(self):
        """get() propagates HTTPError on a 404 Not Found response."""
        client = self._make_client()
        client._session.get.return_value = _make_http_error_response(404)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains/missing-id")

    def test_get_raises_on_500(self):
        """get() propagates HTTPError on a 500 Internal Server Error response."""
        client = self._make_client()
        client._session.get.return_value = _make_http_error_response(500)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_post_raises_on_422(self):
        """post() propagates HTTPError on a 422 Unprocessable Entity response."""
        client = self._make_client()
        client._session.post.return_value = _make_http_error_response(422)
        with pytest.raises(requests.HTTPError):
            client.post("/api/certinext/v2/domains", json={"name": ""})

    def test_post_raises_on_409(self):
        """post() propagates HTTPError on a 409 Conflict response."""
        client = self._make_client()
        client._session.post.return_value = _make_http_error_response(409)
        with pytest.raises(requests.HTTPError):
            client.post("/api/certinext/v2/domains", json={"name": "duplicate.example.edu"})

    def test_delete_raises_on_404(self):
        """delete() propagates HTTPError on a 404 Not Found response."""
        client = self._make_client()
        client._session.delete.return_value = _make_http_error_response(404)
        with pytest.raises(requests.HTTPError):
            client.delete("/api/certinext/v2/domains/missing-id")
