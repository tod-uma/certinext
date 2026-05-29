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

from collections.abc import Callable
from typing import Any, cast

import requests

from .auth import OAuth2ClientCredentials
from .exceptions import (
    CertiNextAPIError,
    CertiNextConflictError,
    CertiNextNotFoundError,
    CertiNextRateLimitError,
)


class CertiNextClient:
    """Low-level HTTP client for the CertiNext REST API.

    Handles authentication automatically by delegating to
    `OAuth2ClientCredentials`. All requests include a Bearer token and
    JSON content-type headers. HTTP errors raise `CertiNextAPIError`.
    """

    def __init__(
        self,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
    ) -> None:
        """
        Args:
            base_url: CertiNext API base URL (e.g. ``https://us-api.certinext.io``).
            token_url: OAuth 2.0 token endpoint URL.
            client_id: OAuth client ID (your CertiNext account number).
            client_secret: OAuth client secret.
            scope: Optional OAuth scope string.
        """
        self.base_url = base_url.rstrip("/")
        self._auth = OAuth2ClientCredentials(token_url, client_id, client_secret, scope)
        self._session = requests.Session()

    def _headers(self) -> dict[str, str]:
        """Build request headers with a fresh bearer token."""
        return {
            "Authorization": f"Bearer {self._auth.get_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _raise_api_error(self, resp: requests.Response) -> None:
        """Raise a typed CertiNextAPIError subclass if the response has a non-2xx status.

        Parses the RFC 7807 ``application/problem+json`` body and raises the
        most specific exception type available:

        - :class:`~certinext.exceptions.CertiNextNotFoundError` for 404
        - :class:`~certinext.exceptions.CertiNextConflictError` for 409
        - :class:`~certinext.exceptions.CertiNextRateLimitError` for 429
          (with :attr:`~certinext.exceptions.CertiNextRateLimitError.retry_after`
          from the ``Retry-After`` header)
        - :class:`~certinext.exceptions.CertiNextAPIError` for all other errors

        Args:
            resp: The HTTP response to check.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            try:
                body: dict[str, Any] | str = resp.json()
            except Exception:
                body = resp.text

            status = resp.status_code
            if status == 404:
                raise CertiNextNotFoundError(status, body, response=resp) from exc
            if status == 409:
                raise CertiNextConflictError(status, body, response=resp) from exc
            if status == 429:
                retry_after: float | None = None
                raw = resp.headers.get("Retry-After")
                if raw is not None:
                    try:
                        retry_after = float(raw)
                    except (ValueError, TypeError):
                        pass
                raise CertiNextRateLimitError(status, body, retry_after=retry_after, response=resp) from exc
            raise CertiNextAPIError(status, body, response=resp) from exc

    def _execute(self, make_request: Callable[[], requests.Response]) -> requests.Response:
        """Execute a request callable, retrying once with a fresh token on 401.

        If the server returns 401 (e.g. ``ACCESS_TOKEN_REVOKED`` when the token
        expires mid-poll), the cached token is invalidated and the request is
        retried once. If the retry also returns 401, the error propagates normally.

        Args:
            make_request: Zero-argument callable that performs the HTTP request
                and returns the response. Called a second time on 401 after the
                token cache is cleared, so the callable must call
                ``self._headers()`` rather than capturing pre-built headers.

        Returns:
            The HTTP response (from the original call or the retry).
        """
        resp = make_request()
        if resp.status_code == 401:
            self._auth.invalidate()
            resp = make_request()
        return resp

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
        """Send a GET request and return the parsed JSON response.

        Args:
            path: API path relative to ``base_url`` (e.g. ``/api/certinext/v2/domains``).
            params: Optional query-string parameters.

        Returns:
            Parsed JSON response as a dict or list.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        resp = self._execute(
            lambda: self._session.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        )
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json())

    def get_bytes(self, path: str, accept: str, params: dict[str, Any] | None = None) -> bytes:
        """Send a GET request with a custom Accept header and return raw response bytes.

        Used for endpoints that return binary or non-JSON content (e.g. DER
        certificates or PEM text).

        Args:
            path: API path relative to ``base_url``.
            accept: Value for the ``Accept`` request header (e.g.
                ``"application/x-pem-file"`` or ``"application/pkix-cert"``).
            params: Optional query-string parameters.

        Returns:
            Raw response body as bytes.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        def _req() -> requests.Response:
            headers = self._headers()
            headers["Accept"] = accept
            return self._session.get(f"{self.base_url}{path}", headers=headers, params=params)
        resp = self._execute(_req)
        self._raise_api_error(resp)
        return resp.content

    def post(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a POST request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.
            extra_headers: Optional additional HTTP headers to include (e.g.
                ``{"X-Product-Code": "842"}`` for SSL certificate creation).

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        def _req() -> requests.Response:
            headers = self._headers()
            if extra_headers:
                headers.update(extra_headers)
            return self._session.post(f"{self.base_url}{path}", headers=headers, json=json)
        resp = self._execute(_req)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json() if resp.content else {})

    def put(
        self,
        path: str,
        json: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a PUT request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.
            extra_headers: Optional additional HTTP headers to include.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        def _req() -> requests.Response:
            headers = self._headers()
            if extra_headers:
                headers.update(extra_headers)
            return self._session.put(f"{self.base_url}{path}", headers=headers, json=json)
        resp = self._execute(_req)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json() if resp.content else {})

    def patch(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a PATCH request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        resp = self._execute(
            lambda: self._session.patch(f"{self.base_url}{path}", headers=self._headers(), json=json)
        )
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json() if resp.content else {})

    def delete(self, path: str) -> dict[str, Any] | None:
        """Send a DELETE request and return the parsed response body if present.

        Args:
            path: API path relative to ``base_url``.

        Returns:
            Parsed JSON response as a dict, or ``None`` if the response has no body.

        Raises:
            CertiNextAPIError: On a non-2xx response. Provides ``.status_code`` and ``.body``.
        """
        resp = self._execute(
            lambda: self._session.delete(f"{self.base_url}{path}", headers=self._headers())
        )
        self._raise_api_error(resp)
        return resp.json() if resp.content else None
