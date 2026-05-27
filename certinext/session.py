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

from .client import CertiNextClient
from .domains import DomainAccessor
from .orders import OrderAccessor


class CertiNextSession:
    """Top-level entry point for interacting with the CertiNext API.

    Instantiate directly or via the ``certinext.session()`` factory function.
    Resource accessors are available as attributes:

        sess = certinext.session(client_id="...", client_secret="...")
        domains = sess.domain.list()
        orders = sess.orders.get_list(status="issued")

    Attributes:
        domain: Accessor for the Domains API. See `DomainAccessor`.
        orders: Accessor for the Orders Report API. See `OrderAccessor`.
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
        self.orders = OrderAccessor(self._client)
