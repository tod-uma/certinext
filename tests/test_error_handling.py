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

from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
import requests

from certinext.auth import OAuth2ClientCredentials
from certinext.client import CertiNextClient
from certinext.domains import VALID_DCV_METHODS, DcvMethod, Domain, DomainAccessor
from certinext.exceptions import (
    CertiNextAPIError,
    CertiNextConflictError,
    CertiNextNotFoundError,
    CertiNextRateLimitError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain(client: MagicMock, data: dict) -> Domain:
    """Construct a Domain from a mock client and a raw data dict."""
    return Domain.from_payload(client, data)


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
            Domain.from_payload(mock_client, entry)  # must not raise

    def test_all_bad_entries_support_str(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """str() succeeds for every bad-data entry."""
        for entry in bad_domain_data:
            str(Domain.from_payload(mock_client, entry))  # must not raise

    def test_all_bad_entries_support_repr(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """repr() succeeds for every bad-data entry."""
        for entry in bad_domain_data:
            repr(Domain.from_payload(mock_client, entry))  # must not raise

    def test_all_bad_entries_support_to_row(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """to_row() succeeds for every bad-data entry and returns only strings."""
        for entry in bad_domain_data:
            row = Domain.from_payload(mock_client, entry).to_row()
            assert all(isinstance(v, str) for v in row.values())

    def test_all_bad_entries_created_at_is_none_or_datetime(
        self, mock_client: MagicMock, bad_domain_data: list[dict]
    ):
        """created_at is either None or a datetime — never raises."""
        from datetime import datetime
        for entry in bad_domain_data:
            result = Domain.from_payload(mock_client, entry).created_at
            assert result is None or isinstance(result, datetime)


# ---------------------------------------------------------------------------
# DomainAccessor — unexpected API response shapes
# ---------------------------------------------------------------------------

class TestDomainAccessorBadResponses:
    """DomainAccessor handles unexpected response shapes without crashing."""

    def test_list_with_empty_dict_returns_empty_list(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get_list() returns [] when the API returns an empty dict."""
        mock_client.get.return_value = {}
        assert accessor.get_list() == []

    def test_list_with_dict_containing_no_list_values_returns_empty(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get_list() returns [] when the dict response has no list-typed values."""
        mock_client.get.return_value = {"total": 0, "page": 1}
        assert accessor.get_list() == []

    def test_list_with_empty_nested_list_returns_empty(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ):
        """get_list() returns [] when the nested list in a paginated response is empty."""
        mock_client.get.return_value = {"total": 0, "domains": []}
        assert accessor.get_list() == []

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

    def _make_client(self) -> tuple[CertiNextClient, MagicMock]:
        """Return a CertiNextClient with auth and session mocked."""
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

    def test_get_raises_on_401(self):
        """get() propagates HTTPError on a 401 Unauthorized response."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_http_error_response(401)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_get_raises_on_403(self):
        """get() propagates HTTPError on a 403 Forbidden response."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_http_error_response(403)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_get_raises_on_404(self):
        """get() propagates HTTPError on a 404 Not Found response."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_http_error_response(404)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains/missing-id")

    def test_get_raises_on_500(self):
        """get() propagates HTTPError on a 500 Internal Server Error response."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_http_error_response(500)
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains")

    def test_post_raises_on_422(self):
        """post() propagates HTTPError on a 422 Unprocessable Entity response."""
        client, mock_session = self._make_client()
        mock_session.post.return_value = _make_http_error_response(422)
        with pytest.raises(requests.HTTPError):
            client.post("/api/certinext/v2/domains", json={"name": ""})

    def test_post_raises_on_409(self):
        """post() propagates HTTPError on a 409 Conflict response."""
        client, mock_session = self._make_client()
        mock_session.post.return_value = _make_http_error_response(409)
        with pytest.raises(requests.HTTPError):
            client.post("/api/certinext/v2/domains", json={"name": "duplicate.example.edu"})

    def test_delete_raises_on_404(self):
        """delete() propagates HTTPError on a 404 Not Found response."""
        client, mock_session = self._make_client()
        mock_session.delete.return_value = _make_http_error_response(404)
        with pytest.raises(requests.HTTPError):
            client.delete("/api/certinext/v2/domains/missing-id")


# ---------------------------------------------------------------------------
# DCV method validation
# ---------------------------------------------------------------------------

class TestDcvMethodValidation:
    """get_dcv() rejects unknown DCV methods; change_dcv_method() validates input."""

    def _domain_with_id(self, client: MagicMock) -> Domain:
        return Domain.from_payload(client, {"domainId": "abc", "domainName": "test.example.edu"})

    # get_dcv — API response validation

    def test_get_dcv_accepts_dns_txt(self, mock_client: MagicMock):
        """get_dcv() accepts DNS-TXT as a valid method."""
        mock_client.get.return_value = {"dcvMethod": "DNS-TXT", "txtToken": "token123"}
        d = self._domain_with_id(mock_client)
        info = d.get_dcv()
        assert info.method == "DNS-TXT"
        assert info.token == "token123"

    def test_get_dcv_accepts_http_url(self, mock_client: MagicMock):
        """get_dcv() accepts HTTP-URL as a valid method."""
        mock_client.get.return_value = {"dcvMethod": "HTTP-URL", "fileToken": "tok"}
        d = self._domain_with_id(mock_client)
        info = d.get_dcv()
        assert info.method == "HTTP-URL"
        assert info.token == "tok"

    def test_get_dcv_rejects_email(self, mock_client: MagicMock):
        """get_dcv() raises ValueError for EMAIL, which is not supported by the Domains API."""
        mock_client.get.return_value = {"dcvMethod": "EMAIL"}
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError, match="EMAIL"):
            d.get_dcv()

    def test_get_dcv_rejects_http(self, mock_client: MagicMock):
        """get_dcv() raises ValueError for HTTP, which is not a valid Domains API method."""
        mock_client.get.return_value = {"dcvMethod": "HTTP"}
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError, match="HTTP"):
            d.get_dcv()

    def test_get_dcv_normalizes_lowercase_to_uppercase(self, mock_client: MagicMock):
        """get_dcv() normalizes method values to upper case before checking."""
        mock_client.get.return_value = {"dcvMethod": "dns-txt", "dnsContents": "tok"}
        d = self._domain_with_id(mock_client)
        info = d.get_dcv()
        assert info.method == "DNS-TXT"

    def test_get_dcv_raises_on_unknown_method(self, mock_client: MagicMock):
        """get_dcv() raises ValueError when the API returns an unrecognised DCV method."""
        mock_client.get.return_value = {"dcvMethod": "DNS", "dnsContents": "tok"}
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError, match="DNS"):
            d.get_dcv()

    def test_get_dcv_raises_on_cname_method(self, mock_client: MagicMock):
        """get_dcv() raises ValueError for any unrecognised method string."""
        mock_client.get.return_value = {"dcvMethod": "CNAME"}
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError):
            d.get_dcv()

    def test_get_dcv_empty_response_returns_empty_method(self, mock_client: MagicMock):
        """get_dcv() returns an empty method string when the API omits dcvMethod."""
        mock_client.get.return_value = {}
        d = self._domain_with_id(mock_client)
        info = d.get_dcv()
        assert info.method == ""

    # change_dcv_method — input validation

    def test_change_dcv_method_accepts_dns_txt(self, mock_client: MagicMock):
        """change_dcv_method() accepts DNS-TXT and calls the API."""
        mock_client.patch.return_value = {}
        d = self._domain_with_id(mock_client)
        d.change_dcv_method("DNS-TXT")
        mock_client.patch.assert_called_once()

    def test_change_dcv_method_accepts_lowercase(self, mock_client: MagicMock):
        """change_dcv_method() normalizes lowercase input and sends lowercase to the API."""
        mock_client.patch.return_value = {}
        d = self._domain_with_id(mock_client)
        d.change_dcv_method(cast(DcvMethod, "dns-txt"))  # cast: testing case-insensitive normalisation
        _, kwargs = mock_client.patch.call_args
        assert kwargs["json"]["dcvMethod"] == "dns-txt"

    def test_change_dcv_method_raises_on_dns(self, mock_client: MagicMock):
        """change_dcv_method() raises ValueError when passed the old 'DNS' method name."""
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError, match="DNS"):
            d.change_dcv_method(cast(DcvMethod, "DNS"))  # cast: intentionally testing invalid runtime value

    def test_change_dcv_method_raises_on_unknown_value(self, mock_client: MagicMock):
        """change_dcv_method() raises ValueError for any unrecognised method."""
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError, match="BOGUS"):
            d.change_dcv_method(cast(DcvMethod, "BOGUS"))  # cast: intentionally testing invalid runtime value

    def test_change_dcv_method_raises_before_api_call(self, mock_client: MagicMock):
        """change_dcv_method() raises ValueError without calling the API for bad input."""
        d = self._domain_with_id(mock_client)
        with pytest.raises(ValueError):
            d.change_dcv_method(cast(DcvMethod, "DNS"))  # cast: intentionally testing invalid runtime value
        mock_client.patch.assert_not_called()

    def test_valid_dcv_methods_constant_contains_expected_values(self):
        """VALID_DCV_METHODS contains DNS-TXT and HTTP-URL."""
        assert VALID_DCV_METHODS == {"DNS-TXT", "HTTP-URL"}


# ---------------------------------------------------------------------------
# Typed exception dispatch
# ---------------------------------------------------------------------------

def _make_rfc7807_response(status_code: int, body: dict, headers: dict | None = None) -> MagicMock:
    """Return a mock response with an RFC 7807 JSON body."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = str(body)
    resp.headers = headers or {}
    resp.raise_for_status.side_effect = requests.HTTPError(
        f"{status_code} Error", response=resp
    )
    return resp


class TestTypedExceptionDispatch:
    """_raise_api_error dispatches typed subclasses for specific status codes."""

    def _make_client(self) -> tuple[CertiNextClient, MagicMock]:
        """Return a CertiNextClient with auth and session mocked."""
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

    def test_404_raises_not_found_error(self):
        """A 404 response raises CertiNextNotFoundError."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            404, {"title": "Not Found", "status": 404}
        )
        with pytest.raises(CertiNextNotFoundError):
            client.get("/api/certinext/v2/domains/missing")

    def test_404_is_also_certinext_api_error(self):
        """CertiNextNotFoundError is a subclass of CertiNextAPIError and HTTPError."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            404, {"title": "Not Found", "status": 404}
        )
        with pytest.raises(CertiNextAPIError):
            client.get("/api/certinext/v2/domains/missing")

    def test_409_raises_conflict_error(self):
        """A 409 response raises CertiNextConflictError."""
        client, mock_session = self._make_client()
        mock_session.post.return_value = _make_rfc7807_response(
            409, {
                "title": "Domain already registered",
                "status": 409,
                "detail": "EMS-DOMAIN-101: Domain already registered",
                "existingDomainId": "dom-abc-123",
            }
        )
        with pytest.raises(CertiNextConflictError):
            client.post("/api/certinext/v2/domains", json={"domainName": "dup.example.edu"})

    def test_409_conflict_error_exposes_existing_domain_id(self):
        """CertiNextConflictError.existing_domain_id returns the ID from the response body."""
        client, mock_session = self._make_client()
        mock_session.post.return_value = _make_rfc7807_response(
            409, {
                "title": "Domain already registered",
                "status": 409,
                "detail": "EMS-DOMAIN-101: Domain already registered",
                "existingDomainId": "dom-abc-123",
            }
        )
        with pytest.raises(CertiNextConflictError) as exc_info:
            client.post("/api/certinext/v2/domains", json={"domainName": "dup.example.edu"})
        assert exc_info.value.existing_domain_id == "dom-abc-123"

    def test_409_conflict_error_existing_domain_id_none_when_absent(self):
        """CertiNextConflictError.existing_domain_id is None when not in the response."""
        client, mock_session = self._make_client()
        mock_session.post.return_value = _make_rfc7807_response(
            409, {"title": "Conflict", "status": 409, "detail": "EMS-DOMAIN-002: duplicate"}
        )
        with pytest.raises(CertiNextConflictError) as exc_info:
            client.post("/api/certinext/v2/domains", json={"domainName": "dup.example.edu"})
        assert exc_info.value.existing_domain_id is None

    def test_429_raises_rate_limit_error(self):
        """A 429 response raises CertiNextRateLimitError."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            429, {"title": "Too Many Requests", "status": 429},
            headers={"Retry-After": "30"},
        )
        with pytest.raises(CertiNextRateLimitError):
            client.get("/api/certinext/v2/domains")

    def test_429_rate_limit_error_parses_retry_after(self):
        """CertiNextRateLimitError.retry_after is set from the Retry-After header."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            429, {"title": "Too Many Requests", "status": 429},
            headers={"Retry-After": "60"},
        )
        with pytest.raises(CertiNextRateLimitError) as exc_info:
            client.get("/api/certinext/v2/domains")
        assert exc_info.value.retry_after == 60.0

    def test_429_rate_limit_error_retry_after_none_when_header_absent(self):
        """CertiNextRateLimitError.retry_after is None when the Retry-After header is absent."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            429, {"title": "Too Many Requests", "status": 429},
        )
        with pytest.raises(CertiNextRateLimitError) as exc_info:
            client.get("/api/certinext/v2/domains")
        assert exc_info.value.retry_after is None

    def test_other_status_raises_base_certinext_api_error(self):
        """Status codes other than 404/409/429 raise CertiNextAPIError directly."""
        client, mock_session = self._make_client()
        mock_session.get.return_value = _make_rfc7807_response(
            422, {
                "title": "Unprocessable Entity",
                "status": 422,
                "detail": "EMS-921: CSR malformed",
            }
        )
        exc: CertiNextAPIError
        with pytest.raises(CertiNextAPIError) as exc_info:
            client.get("/api/certinext/v2/domains")
        exc = exc_info.value
        assert type(exc) is CertiNextAPIError
        assert not isinstance(exc, (CertiNextNotFoundError, CertiNextConflictError, CertiNextRateLimitError))


class TestCertiNextAPIErrorProperties:
    """CertiNextAPIError exposes RFC 7807 fields via ems_code and field_errors."""

    def test_str_extracts_detail_from_rfc7807_body(self):
        """__str__() returns the detail field when the body is an RFC 7807 dict."""
        err = CertiNextAPIError(422, {
            "title": "Unprocessable Entity",
            "detail": "EMS-921: CSR malformed",
            "status": 422,
        })
        assert str(err) == "HTTP 422: EMS-921: CSR malformed"

    def test_str_falls_back_to_title_when_detail_absent(self):
        """__str__() uses title when detail is not in the body."""
        err = CertiNextAPIError(422, {"title": "Bad Request", "status": 422})
        assert str(err) == "HTTP 422: Bad Request"

    def test_str_falls_back_to_full_body_when_neither_detail_nor_title(self):
        """__str__() falls back to the full body dict when neither detail nor title is present."""
        body: dict[str, Any] = {"status": 422}
        err = CertiNextAPIError(422, body)
        assert "422" in str(err)

    def test_str_with_plain_text_body(self):
        """__str__() includes the raw text when the body is a string."""
        err = CertiNextAPIError(500, "Internal Server Error")
        assert str(err) == "HTTP 500: Internal Server Error"

    def test_ems_code_extracted_from_detail(self):
        """ems_code extracts the EMS code from the detail field."""
        err = CertiNextAPIError(422, {
            "detail": "EMS-921: CSR malformed or missing required fields",
        })
        assert err.ems_code == "EMS-921"

    def test_ems_code_extracted_from_domain_detail(self):
        """ems_code handles compound EMS codes like EMS-DOMAIN-002."""
        err = CertiNextAPIError(409, {
            "detail": "EMS-DOMAIN-002: domain already exists",
        })
        assert err.ems_code == "EMS-DOMAIN-002"

    def test_ems_code_falls_back_to_type_url(self):
        """ems_code extracts the code from the type URL when detail has none."""
        err = CertiNextAPIError(409, {
            "type": "https://api.certinext.io/errors/EMS-DOMAIN-101",
            "detail": "Domain already registered",
        })
        assert err.ems_code == "EMS-DOMAIN-101"

    def test_ems_code_none_when_absent(self):
        """ems_code returns None when no EMS code is in the body."""
        err = CertiNextAPIError(404, {"title": "Not Found", "status": 404})
        assert err.ems_code is None

    def test_ems_code_none_when_body_is_string(self):
        """ems_code returns None when the body is raw text."""
        err = CertiNextAPIError(500, "Internal Server Error")
        assert err.ems_code is None

    def test_field_errors_returns_errors_array(self):
        """field_errors returns the errors list from an RFC 7807 body."""
        err = CertiNextAPIError(422, {
            "status": 422,
            "errors": [
                {"field": "certificate.domain", "message": "must not be blank"},
                {"field": "csr", "message": "invalid format"},
            ],
        })
        assert err.field_errors == [
            {"field": "certificate.domain", "message": "must not be blank"},
            {"field": "csr", "message": "invalid format"},
        ]

    def test_field_errors_empty_when_no_errors_key(self):
        """field_errors returns [] when the body has no errors key."""
        err = CertiNextAPIError(422, {"status": 422, "detail": "something went wrong"})
        assert err.field_errors == []

    def test_field_errors_empty_when_body_is_string(self):
        """field_errors returns [] when the body is raw text."""
        err = CertiNextAPIError(500, "Internal Server Error")
        assert err.field_errors == []
