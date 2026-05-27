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

"""Tests for certinext.client.CertiNextClient."""

from unittest.mock import MagicMock

import pytest
import requests

from certinext.client import CertiNextClient


def _make_client() -> tuple[CertiNextClient, MagicMock]:
    """Return a CertiNextClient with auth and session mocked out."""
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


def _ok_response(payload: object = None) -> MagicMock:
    """Return a mock response with a 200 status and the given JSON payload."""
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload if payload is not None else {}
    resp.content = b"{}"
    return resp


class TestHeaders:
    """CertiNextClient._headers includes the required fields."""

    def test_includes_bearer_token(self):
        """Authorization header contains the Bearer token from auth."""
        client, _ = _make_client()
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-token"

    def test_includes_json_content_type(self):
        """Content-Type and Accept headers are set to application/json."""
        client, _ = _make_client()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"


class TestGet:
    """CertiNextClient.get sends the correct request."""

    def test_calls_correct_url(self):
        """get() constructs the full URL from base_url and path."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"domainId": "abc"})
        client.get("/api/certinext/v2/domains/abc")
        mock_session.get.assert_called_once_with(
            "https://us-api.certinext.io/api/certinext/v2/domains/abc",
            headers=client._headers(),
            params=None,
        )

    def test_passes_query_params(self):
        """get() forwards the params argument to the underlying session."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        client.get("/api/certinext/v2/domains", params={"limit": 10})
        _, kwargs = mock_session.get.call_args
        assert kwargs["params"] == {"limit": 10}

    def test_raises_on_http_error(self):
        """get() propagates HTTPError when raise_for_status raises."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.HTTPError("404")
        mock_session.get.return_value = resp
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains/missing")


class TestPost:
    """CertiNextClient.post sends the correct request."""

    def test_calls_correct_url_with_json(self):
        """post() constructs the full URL and passes the json body."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({"domainId": "new"})
        client.post("/api/certinext/v2/domains", json={"name": "test.example.edu"})
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"] == {"name": "test.example.edu"}

    def test_returns_parsed_json(self):
        """post() returns the parsed JSON payload from the response."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({"domainId": "xyz"})
        result = client.post("/api/certinext/v2/domains", json={"name": "test.example.edu"})
        assert result == {"domainId": "xyz"}


class TestDelete:
    """CertiNextClient.delete handles responses with and without a body."""

    def test_returns_none_when_no_body(self):
        """delete() returns None when the response has no content."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b""
        mock_session.delete.return_value = resp
        result = client.delete("/api/certinext/v2/domains/abc")
        assert result is None

    def test_returns_parsed_json_when_body_present(self):
        """delete() returns the parsed JSON body when content is present."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b'{"status": "deleted"}'
        resp.json.return_value = {"status": "deleted"}
        mock_session.delete.return_value = resp
        result = client.delete("/api/certinext/v2/domains/abc")
        assert result == {"status": "deleted"}


class TestPostExtraHeaders:
    """CertiNextClient.post() merges extra_headers into the request headers."""

    def test_extra_headers_are_included(self):
        """post() sends the extra_headers merged with default headers."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({"orderId": "X"})
        client.post("/api/certinext/v2/ssl/dv", extra_headers={"X-Product-Code": "842"})
        _, kwargs = mock_session.post.call_args
        assert kwargs["headers"]["X-Product-Code"] == "842"

    def test_extra_headers_do_not_remove_auth(self):
        """post() retains the Authorization header when extra_headers are provided."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({})
        client.post("/api/certinext/v2/ssl/dv", extra_headers={"X-Product-Code": "842"})
        _, kwargs = mock_session.post.call_args
        assert "Bearer" in kwargs["headers"]["Authorization"]

    def test_no_extra_headers_does_not_raise(self):
        """post() with no extra_headers works as before."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({"domainId": "new"})
        result = client.post("/api/certinext/v2/domains", json={"name": "test.example.edu"})
        assert result == {"domainId": "new"}


class TestGetBytes:
    """CertiNextClient.get_bytes() returns raw bytes with a custom Accept header."""

    def test_calls_correct_url(self):
        """get_bytes() constructs the full URL from base_url and path."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b"-----BEGIN CERTIFICATE-----\n..."
        mock_session.get.return_value = resp
        client.get_bytes("/api/certinext/v2/ssl/ORDER-1/certificate", accept="application/x-pem-file")
        url = mock_session.get.call_args[0][0]
        assert url.endswith("/ssl/ORDER-1/certificate")

    def test_sets_accept_header(self):
        """get_bytes() sends the Accept header provided by the caller."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b"\x30\x82"
        mock_session.get.return_value = resp
        client.get_bytes(
            "/api/certinext/v2/ssl/ORDER-1/certificate",
            accept="application/pkix-cert",
        )
        _, kwargs = mock_session.get.call_args
        assert kwargs["headers"]["Accept"] == "application/pkix-cert"

    def test_returns_raw_bytes(self):
        """get_bytes() returns the response content as bytes."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b"raw-cert-bytes"
        mock_session.get.return_value = resp
        result = client.get_bytes("/api/certinext/v2/ssl/ORDER-1/certificate", accept="application/pkix-cert")
        assert result == b"raw-cert-bytes"

    def test_passes_query_params(self):
        """get_bytes() forwards the params argument."""
        client, mock_session = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b""
        mock_session.get.return_value = resp
        client.get_bytes("/path", accept="application/x-pem-file", params={"format": "pem"})
        _, kwargs = mock_session.get.call_args
        assert kwargs["params"] == {"format": "pem"}
