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

from .accounts import AccountAccessor
from .catalog import CatalogAccessor
from .client import CertiNextClient
from .domains import DomainAccessor
from .ledger import LedgerAccessor
from .orders import OrderAccessor
from .ssl_certificates import SslAccessor


class CertiNextSession:
    """Top-level entry point for interacting with the CertiNext API.

    Instantiate directly or via the ``certinext.session()`` factory function.
    Resource accessors are available as attributes:

        sess = certinext.session(client_id="...", client_secret="...")
        domains = sess.domain.get_list()
        orders = sess.orders.get_list(status="issued")
        orgs = sess.accounts.list_organizations()
        order = sess.ssl.create_dv("example.com")

    Attributes:
        sandbox: True when connected to the sandbox API; False for production.
        accounts: Accessor for identity, groups, and organizations. See `AccountAccessor`.
        catalog: Accessor for the Catalog API (products and custom fields). See `CatalogAccessor`.
        domain: Accessor for the Domains API. See `DomainAccessor`.
        ledger: Accessor for the Ledger Report API. See `LedgerAccessor`.
        orders: Accessor for the Orders Report API. See `OrderAccessor`.
        ssl: Accessor for the SSL/TLS Certificates API. See `SslAccessor`.
    """

    def __init__(
        self,
        base_url: str = "https://us-api.certinext.io",
        token_url: str = "https://us-api.certinext.io/oauth/token",
        client_id: str = "",
        client_secret: str = "",
        scope: str = "",
        sandbox: bool = False,
    ) -> None:
        """
        Args:
            base_url: CertiNext API base URL.
            token_url: OAuth 2.0 token endpoint URL.
            client_id: Your CertiNext account number (used as the OAuth client ID).
            client_secret: OAuth client secret generated in the CertiNext portal.
            scope: Optional OAuth scope string.
            sandbox: Whether this session is connected to the sandbox API. Callers
                can read this attribute to adjust behaviour (e.g. mark audit records
                as sandbox entries) without re-inspecting the base URL.
        """
        self.sandbox = sandbox
        self._client = CertiNextClient(base_url, token_url, client_id, client_secret, scope)
        self.accounts = AccountAccessor(self._client)
        self.catalog = CatalogAccessor(self._client)
        self.domain = DomainAccessor(self._client)
        self.ledger = LedgerAccessor(self._client)
        self.orders = OrderAccessor(self._client)
        self.ssl = SslAccessor(self._client)
