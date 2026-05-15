import time
from typing import Optional

import requests


class OAuth2ClientCredentials:
    """Manages an OAuth 2.0 Client Credentials bearer token.

    Fetches a token on first use and caches it, automatically refreshing it
    60 seconds before expiry so callers always receive a valid token.
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
        if self._access_token and time.time() < self._expires_at - 60:
            return self._access_token
        self._fetch_token()
        return self._access_token  # type: ignore[return-value]

    def _fetch_token(self) -> None:
        """Request a new token from the token endpoint and cache it."""
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope

        resp = requests.post(self.token_url, data=data)
        if not resp.ok:
            raise RuntimeError(
                f"Token request failed: {resp.status_code} {resp.reason}\n"
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
        self._expires_at = time.time() + payload.get("expires_in", 3600)
