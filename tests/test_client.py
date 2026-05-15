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


def _make_client() -> CertiNextClient:
    """Return a CertiNextClient with auth and session mocked out."""
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
        client = _make_client()
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-token"

    def test_includes_json_content_type(self):
        """Content-Type and Accept headers are set to application/json."""
        client = _make_client()
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"


class TestGet:
    """CertiNextClient.get sends the correct request."""

    def test_calls_correct_url(self):
        """get() constructs the full URL from base_url and path."""
        client = _make_client()
        client._session.get.return_value = _ok_response({"domainId": "abc"})
        client.get("/api/certinext/v2/domains/abc")
        client._session.get.assert_called_once_with(
            "https://us-api.certinext.io/api/certinext/v2/domains/abc",
            headers=client._headers(),
            params=None,
        )

    def test_passes_query_params(self):
        """get() forwards the params argument to the underlying session."""
        client = _make_client()
        client._session.get.return_value = _ok_response([])
        client.get("/api/certinext/v2/domains", params={"limit": 10})
        _, kwargs = client._session.get.call_args
        assert kwargs["params"] == {"limit": 10}

    def test_raises_on_http_error(self):
        """get() propagates HTTPError when raise_for_status raises."""
        client = _make_client()
        resp = MagicMock()
        resp.raise_for_status.side_effect = requests.HTTPError("404")
        client._session.get.return_value = resp
        with pytest.raises(requests.HTTPError):
            client.get("/api/certinext/v2/domains/missing")


class TestPost:
    """CertiNextClient.post sends the correct request."""

    def test_calls_correct_url_with_json(self):
        """post() constructs the full URL and passes the json body."""
        client = _make_client()
        client._session.post.return_value = _ok_response({"domainId": "new"})
        client.post("/api/certinext/v2/domains", json={"name": "test.example.edu"})
        _, kwargs = client._session.post.call_args
        assert kwargs["json"] == {"name": "test.example.edu"}

    def test_returns_parsed_json(self):
        """post() returns the parsed JSON payload from the response."""
        client = _make_client()
        client._session.post.return_value = _ok_response({"domainId": "xyz"})
        result = client.post("/api/certinext/v2/domains", json={"name": "test.example.edu"})
        assert result == {"domainId": "xyz"}


class TestDelete:
    """CertiNextClient.delete handles responses with and without a body."""

    def test_returns_none_when_no_body(self):
        """delete() returns None when the response has no content."""
        client = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b""
        client._session.delete.return_value = resp
        result = client.delete("/api/certinext/v2/domains/abc")
        assert result is None

    def test_returns_parsed_json_when_body_present(self):
        """delete() returns the parsed JSON body when content is present."""
        client = _make_client()
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.content = b'{"status": "deleted"}'
        resp.json.return_value = {"status": "deleted"}
        client._session.delete.return_value = resp
        result = client.delete("/api/certinext/v2/domains/abc")
        assert result == {"status": "deleted"}
