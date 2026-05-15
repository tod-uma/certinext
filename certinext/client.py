from typing import Any
import requests
from .auth import OAuth2ClientCredentials


class CertiNextClient:
    def __init__(
        self,
        base_url: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._auth = OAuth2ClientCredentials(token_url, client_id, client_secret, scope)
        self._session = requests.Session()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._auth.get_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
        resp = self._session.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def post(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._session.post(f"{self.base_url}{path}", headers=self._headers(), json=json)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def put(self, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = self._session.put(f"{self.base_url}{path}", headers=self._headers(), json=json)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def delete(self, path: str) -> dict[str, Any] | None:
        resp = self._session.delete(f"{self.base_url}{path}", headers=self._headers())
        resp.raise_for_status()
        return resp.json() if resp.content else None  # type: ignore[no-any-return]
