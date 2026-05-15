from .client import CertiNextClient
from .domains import DomainAccessor


class CertiNextSession:
    def __init__(
        self,
        base_url: str = "https://us-api.certinext.io",
        token_url: str = "https://us-api.certinext.io/oauth/token",
        client_id: str = "",
        client_secret: str = "",
        scope: str = "",
    ) -> None:
        self._client = CertiNextClient(base_url, token_url, client_id, client_secret, scope)
        self.domain = DomainAccessor(self._client)
