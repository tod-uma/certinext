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

"""Tests for certinext.auth.OAuth2ClientCredentials."""

import time
from unittest.mock import MagicMock, patch

import pytest

from certinext.auth import OAuth2ClientCredentials


def _make_auth(client_id: str = "test-account", client_secret: str = "test-secret") -> OAuth2ClientCredentials:
    """Return an OAuth2ClientCredentials with test defaults."""
    return OAuth2ClientCredentials(
        token_url="https://us-api.certinext.io/oauth/token",
        client_id=client_id,
        client_secret=client_secret,
    )


def _mock_token_response(token: str = "test-bearer-token-abc123", expires_in: int = 3600) -> MagicMock:
    """Return a mock response that yields a valid token payload."""
    resp = MagicMock()
    resp.is_success = True
    resp.json.return_value = {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    return resp


class TestGetToken:
    """OAuth2ClientCredentials.get_token fetches and caches bearer tokens."""

    def test_fetches_token_on_first_call(self):
        """get_token fetches a new token when none is cached."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            token = auth.get_token()
        assert token == "test-bearer-token-abc123"
        mock_post.assert_called_once()

    def test_returns_cached_token(self):
        """get_token returns the cached token without making a second request."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            first = auth.get_token()
            second = auth.get_token()
        assert first == second
        mock_post.assert_called_once()

    def test_refreshes_expired_token(self):
        """get_token fetches a new token when the cached one is within 60s of expiry."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
            # Wind the expiry back so the token appears about to expire.
            auth._expires_at = time.monotonic() + 30
            auth.get_token()
        assert mock_post.call_count == 2

    def test_sends_correct_form_fields(self):
        """get_token POSTs the expected client_credentials form fields."""
        auth = _make_auth(client_id="my-account", client_secret="my-secret")
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
        _, kwargs = mock_post.call_args
        data = kwargs["data"]
        assert data["grant_type"] == "client_credentials"
        assert data["client_id"] == "my-account"
        assert data["client_secret"] == "my-secret"

    def test_includes_scope_when_set(self):
        """get_token includes the scope field when one is configured."""
        auth = OAuth2ClientCredentials(
            token_url="https://us-api.certinext.io/oauth/token",
            client_id="acct",
            client_secret="secret",
            scope="read:domains",
        )
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
        _, kwargs = mock_post.call_args
        assert kwargs["data"]["scope"] == "read:domains"

    def test_omits_scope_when_empty(self):
        """get_token omits the scope field when scope is an empty string."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
        _, kwargs = mock_post.call_args
        assert "scope" not in kwargs["data"]

    def test_sets_request_timeout(self):
        """get_token sends the token request with a finite timeout."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
        _, kwargs = mock_post.call_args
        assert kwargs["timeout"] is not None


class TestFetchTokenErrors:
    """OAuth2ClientCredentials surfaces clear errors on failed token requests."""

    def test_raises_on_http_error(self):
        """get_token raises RuntimeError when the token endpoint returns a non-2xx status."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.is_success = False
        bad_resp.status_code = 401
        bad_resp.reason_phrase = "Unauthorized"
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = '{"error": "invalid_client"}'

        with patch("certinext.auth.httpx.post", return_value=bad_resp):
            with pytest.raises(RuntimeError, match="401"):
                auth.get_token()

    def test_raises_on_non_json_response(self):
        """get_token raises RuntimeError when the response body is not valid JSON."""
        auth = _make_auth()
        bad_resp = MagicMock()
        bad_resp.is_success = True
        bad_resp.status_code = 200
        bad_resp.url = "https://us-api.certinext.io/oauth/token"
        bad_resp.text = "<html>Service Unavailable</html>"
        bad_resp.json.side_effect = ValueError("No JSON")

        with patch("certinext.auth.httpx.post", return_value=bad_resp):
            with pytest.raises(RuntimeError, match="non-JSON"):
                auth.get_token()


class TestInvalidate:
    """OAuth2ClientCredentials.invalidate() clears the cached token."""

    def test_invalidate_causes_fresh_fetch(self):
        """invalidate() forces get_token() to fetch a new token on the next call."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()) as mock_post:
            auth.get_token()
            auth.invalidate()
            auth.get_token()
        assert mock_post.call_count == 2

    def test_invalidate_clears_cached_token(self):
        """After invalidate(), the cached token attribute is None."""
        auth = _make_auth()
        with patch("certinext.auth.httpx.post", return_value=_mock_token_response()):
            auth.get_token()
        auth.invalidate()
        assert auth._access_token is None
