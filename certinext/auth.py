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

import threading
import time
from typing import Optional

import httpx
import structlog

from certinext.exceptions import TRANSIENT_STATUS_CODES, CertiNextAuthError

log = structlog.get_logger(__name__)

#: Timeout for token-endpoint requests. The old ``requests`` implementation
#: had no timeout at all, so any finite value is stricter; 10 s to connect
#: and 30 s to read is generous for an OAuth token endpoint.
_TOKEN_TIMEOUT = httpx.Timeout(10.0, read=30.0)

#: Seconds to wait before each retry of a token request that failed with a
#: transport error or a 502/503/504. Two retries ride out a gateway blip;
#: a longer outage still fails within about a minute. Only the token request
#: retries: API calls leave retries to their callers (see CertiNextClient).
_TOKEN_RETRY_DELAYS = (2.0, 5.0)

#: Seconds after a failed token fetch (retries included) during which
#: :meth:`OAuth2ClientCredentials.get_token` re-raises that failure instead of
#: trying again. Parallel workers queued on the lock then fail together in
#: seconds rather than each running the full retry sequence in turn.
_FAILURE_HOLDOFF = 10.0


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
        self._lock = threading.Lock()
        self._failure: tuple[float, Exception] | None = None

    def get_token(self) -> str:
        """Return a valid bearer token, fetching a new one if necessary.

        A fetch that failed (after its retries) less than
        :data:`_FAILURE_HOLDOFF` seconds ago is re-raised without a new
        request.

        Returns:
            A current OAuth access token string.

        Raises:
            CertiNextAuthError: If the token endpoint returns an error or a
                non-JSON response (a :exc:`RuntimeError` subclass).
            httpx.TransportError: If the token endpoint cannot be reached.
        """
        # One lock around check-and-fetch: threads sharing a session (parallel
        # replacement-report downloads) must not each fetch a token at expiry.
        with self._lock:
            if self._access_token and time.monotonic() < self._expires_at - 60:
                return self._access_token
            if self._failure and time.monotonic() - self._failure[0] < _FAILURE_HOLDOFF:
                raise self._failure[1]
            try:
                self._fetch_token()
            except (CertiNextAuthError, httpx.TransportError) as exc:
                self._failure = (time.monotonic(), exc)
                raise
            self._failure = None
            assert self._access_token is not None
            return self._access_token

    def invalidate(self, stale: str | None = None) -> None:
        """Discard the cached token, forcing a fresh fetch on the next :meth:`get_token` call.

        Args:
            stale: The token that was rejected. If another thread has
                already replaced it, the newer token is kept. None always
                discards.
        """
        with self._lock:
            if stale is not None and stale != self._access_token:
                return
            self._access_token = None
            self._expires_at = 0.0

    def _fetch_token(self) -> None:
        """Request a new token from the token endpoint and cache it.

        A transport error (timeout, refused connection) or a 502/503/504 is
        retried after each delay in :data:`_TOKEN_RETRY_DELAYS`, logging a
        warning each time. Other statuses (e.g. 401 ``invalid_client``) fail
        at once: retrying cannot fix them.

        Raises:
            CertiNextAuthError: On a non-2xx response (after any retries) or a
                non-JSON body. A :exc:`RuntimeError` subclass. The message
                carries the HTTP status code and raw body (e.g.
                ``invalid_client``) — the healthcheck classifies auth failures
                by string-matching these markers, so change them only together
                with it.
            httpx.TransportError: If the last attempt could not reach the
                endpoint at all.
        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope

        resp = self._post_with_retry(data)
        if not resp.is_success:
            raise CertiNextAuthError(
                f"Token request failed: {resp.status_code} {resp.reason_phrase}\n"
                f"URL: {resp.url}\n"
                f"Body: {resp.text!r}",
                resp.status_code,
                resp.reason_phrase,
            )
        try:
            payload = resp.json()
        except Exception as exc:
            raise CertiNextAuthError(
                f"Token endpoint returned non-JSON (status {resp.status_code})\n"
                f"URL: {resp.url}\n"
                f"Body: {resp.text!r}",
                resp.status_code,
                resp.reason_phrase,
            ) from exc
        self._access_token = payload["access_token"]
        self._expires_at = time.monotonic() + payload.get("expires_in", 3600)

    def _post_with_retry(self, data: dict[str, str]) -> httpx.Response:
        """POST the token request, retrying transient failures.

        Called with :attr:`_lock` held, so parallel workers wait for this one
        fetch rather than each retrying their own.

        Args:
            data: The form fields to send.

        Returns:
            The last response: a success, a non-transient error, or the
            transient error left after the final retry.

        Raises:
            httpx.TransportError: If the final attempt could not reach the
                endpoint.
        """
        for delay in (*_TOKEN_RETRY_DELAYS, None):
            try:
                resp = httpx.post(self.token_url, data=data, timeout=_TOKEN_TIMEOUT)
            except httpx.TransportError as exc:
                if delay is None:
                    raise
                log.warning("Token request failed; retrying", error=str(exc) or type(exc).__name__,
                            error_type=type(exc).__name__, retry_in=delay)
            else:
                if resp.status_code not in TRANSIENT_STATUS_CODES or delay is None:
                    return resp
                log.warning("Token request failed; retrying",
                            status=f"{resp.status_code} {resp.reason_phrase}", retry_in=delay)
            time.sleep(delay)
        raise AssertionError("unreachable: the last attempt returns or raises")
