"""CertiNext API client library.

Typical usage::

    import certinext

    sess = certinext.session(
        client_id="YOUR_ACCOUNT_NUMBER",
        client_secret="YOUR_CLIENT_SECRET",
    )

    for domain in sess.domain.list():
        print(domain)
"""

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
    """Create and return a new `CertiNextSession`.

    This is the recommended entry point for the library. The session obtains
    and caches an OAuth 2.0 bearer token automatically.

    Args:
        base_url: CertiNext API base URL. Defaults to the US production endpoint.
        token_url: OAuth 2.0 token endpoint URL.
        client_id: Your CertiNext account number (used as the OAuth client ID).
        client_secret: OAuth client secret generated in the CertiNext portal
            under Integrations → APIs → OAuth mode.
        scope: Optional OAuth scope string. Leave empty if not required.

    Returns:
        A configured `CertiNextSession` ready to make API calls.
    """
    return CertiNextSession(base_url, token_url, client_id, client_secret, scope)


__all__ = ["session", "CertiNextClient", "CertiNextSession", "Domain", "DomainAccessor"]
