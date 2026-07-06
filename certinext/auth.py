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

import time
from typing import Optional

import httpx

#: Timeout for token-endpoint requests. The old ``requests`` implementation
#: had no timeout at all, so any finite value is stricter; 10 s to connect
#: and 30 s to read is generous for an OAuth token endpoint.
_TOKEN_TIMEOUT = httpx.Timeout(10.0, read=30.0)


class OAuth2ClientCredentials:
    """Manages an OAuth 2.0 Client Credentials bearer token.

    Fetches a token on first use and caches it, automatically refreshing it
    60 seconds before expiry so callers always receive a valid token.

    This is the single place in the library that issues an HTTP request
    outside :class:`~certinext.client.CertiNextClient` — the token endpoint
    is not part of the API surface the client wraps.
    """

    def __init__(self, token_url: str, client_id: str, client_secret: str, scope: str = "") -> None:
        """
        Args:
            token_url: Full URL of the OAuth 2.0 token endpoint.
            client_id: OAuth client ID (your CertiNext account number).
            client_secret: OAuth client secret.
            scope: Optional space-separated OAuth scopes.
        """
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0

    def get_token(self) -> str:
        """Return a valid bearer token, fetching a new one if necessary.

        Returns:
            A current OAuth access token string.

        Raises:
            RuntimeError: If the token endpoint returns an error or non-JSON response.
        """
        if self._access_token and time.monotonic() < self._expires_at - 60:
            return self._access_token
        self._fetch_token()
        assert self._access_token is not None
        return self._access_token

    def invalidate(self) -> None:
        """Discard the cached token, forcing a fresh fetch on the next :meth:`get_token` call."""
        self._access_token = None
        self._expires_at = 0.0

    def _fetch_token(self) -> None:
        """Request a new token from the token endpoint and cache it.

        Raises:
            RuntimeError: On a non-2xx response or a non-JSON body. The message
                carries the HTTP status code and raw body (e.g. ``invalid_client``)
                — the healthcheck classifies auth failures by string-matching
                these markers, so change them only together with it.
        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope

        resp = httpx.post(self.token_url, data=data, timeout=_TOKEN_TIMEOUT)
        if not resp.is_success:
            raise RuntimeError(
                f"Token request failed: {resp.status_code} {resp.reason_phrase}\n"
                f"URL: {resp.url}\n"
                f"Body: {resp.text!r}"
            )
        try:
            payload = resp.json()
        except Exception as exc:
            raise RuntimeError(
                f"Token endpoint returned non-JSON (status {resp.status_code})\n"
                f"URL: {resp.url}\n"
                f"Body: {resp.text!r}"
            ) from exc
        self._access_token = payload["access_token"]
        self._expires_at = time.monotonic() + payload.get("expires_in", 3600)
