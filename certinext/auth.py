import time
from typing import Optional

import requests


class OAuth2ClientCredentials:
    def __init__(self, token_url: str, client_id: str, client_secret: str, scope: str = ""):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0

    def get_token(self) -> str:
        if self._access_token and time.time() < self._expires_at - 60:
            return self._access_token
        self._fetch_token()
        return self._access_token

    def _fetch_token(self) -> None:
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
