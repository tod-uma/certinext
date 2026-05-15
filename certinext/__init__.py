from .client import CertiNextClient
from .domains import Domain, DomainAccessor
from .session import CertiNextSession


def session(
    base_url: str = "https://us-api.certinext.io",
    token_url: str = "https://us-api.certinext.io/oauth/token",
    client_id: str = "",
    client_secret: str = "",
    scope: str = "",
) -> CertiNextSession:
    return CertiNextSession(base_url, token_url, client_id, client_secret, scope)


__all__ = ["session", "CertiNextClient", "CertiNextSession", "Domain", "DomainAccessor"]
