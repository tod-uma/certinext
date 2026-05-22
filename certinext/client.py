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

from typing import Any, cast

import requests

from .auth import OAuth2ClientCredentials
from .exceptions import CertiNextAPIError


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
        """Raise CertiNextAPIError if the response has a non-2xx status.

        Preserves the API response body (parsed JSON or raw text) so callers
        can inspect what the server actually returned.

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
            raise CertiNextAPIError(resp.status_code, body, response=resp) from exc

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
        """Send a GET request and return the parsed JSON response.

        Args:
            path: API path relative to ``base_url`` (e.g. ``/api/certinext/v2/domains``).
            params: Optional query-string parameters.

        Returns:
            Parsed JSON response as a dict or list.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        resp = self._session.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json())

    def post(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a POST request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        resp = self._session.post(f"{self.base_url}{path}", headers=self._headers(), json=json)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json())

    def put(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a PUT request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        resp = self._session.put(f"{self.base_url}{path}", headers=self._headers(), json=json)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json())

    def patch(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a PATCH request with an optional JSON body and return the parsed response.

        Args:
            path: API path relative to ``base_url``.
            json: Optional request body to serialize as JSON.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        resp = self._session.patch(f"{self.base_url}{path}", headers=self._headers(), json=json)
        self._raise_api_error(resp)
        return cast(dict[str, Any], resp.json())

    def delete(self, path: str) -> dict[str, Any] | None:
        """Send a DELETE request and return the parsed response body if present.

        Args:
            path: API path relative to ``base_url``.

        Returns:
            Parsed JSON response as a dict, or ``None`` if the response has no body.

        Raises:
            CertiNextAPIError: On a non-2xx response.
        """
        resp = self._session.delete(f"{self.base_url}{path}", headers=self._headers())
        self._raise_api_error(resp)
        return resp.json() if resp.content else None
