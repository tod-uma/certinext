from .client import CertiNextClient
from .domains import DomainAccessor


class CertiNextSession:
    """Top-level entry point for interacting with the CertiNext API.

    Instantiate directly or via the ``certinext.session()`` factory function.
    Resource accessors are available as attributes:

        sess = certinext.session(client_id="...", client_secret="...")
        domains = sess.domain.list()

    Attributes:
        domain: Accessor for the Domains API. See `DomainAccessor`.
    """

    def __init__(
        self,
        base_url: str = "https://us-api.certinext.io",
        token_url: str = "https://us-api.certinext.io/oauth/token",
        client_id: str = "",
        client_secret: str = "",
        scope: str = "",
    ) -> None:
        """
        Args:
            base_url: CertiNext API base URL.
            token_url: OAuth 2.0 token endpoint URL.
            client_id: Your CertiNext account number (used as the OAuth client ID).
            client_secret: OAuth client secret generated in the CertiNext portal.
            scope: Optional OAuth scope string.
        """
        self._client = CertiNextClient(base_url, token_url, client_id, client_secret, scope)
        self.domain = DomainAccessor(self._client)
