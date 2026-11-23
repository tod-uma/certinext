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

from collections.abc import Iterator
from contextlib import contextmanager

from .accounts import AccountAccessor
from .api_credentials import ApiCredentialAccessor
from .audit import AuditAccessor
from .catalog import CatalogAccessor
from .client import CertiNextClient, TimeoutSpec
from .domains import DomainAccessor
from .ledger import LedgerAccessor
from .orders import OrderAccessor
from .retry import RetryPolicy
from .ssl_certificates import SslAccessor
from .users import UserAccessor
from .v3_orders import V3OrderAccessor


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
        api_credentials: Accessor for the v3 API-credentials list. See `ApiCredentialAccessor`.
        audit: Accessor for the v3 audit log. See `AuditAccessor`.
        users: Accessor for v3 users, custom roles and group membership. See `UserAccessor`.
        v3_orders: Accessor for the v3 orders list and detail, a different
            order set from ``orders``. See `V3OrderAccessor`.
    """

    def __init__(
        self,
        base_url: str = "",
        token_url: str = "",
        client_id: str = "",
        client_secret: str = "",
        scope: str = "",
        sandbox: bool = False,
        timeout: TimeoutSpec | None = None,
        create_timeout: TimeoutSpec | None = None,
        retry: RetryPolicy | None = None,
    ) -> None:
        """
        Args:
            base_url: CertiNext API base URL. Defaults to the US production
                endpoint, or the US sandbox endpoint when ``sandbox=True``.
                Explicit values always take precedence over the ``sandbox`` flag.
            token_url: OAuth 2.0 token endpoint URL. Defaults to match
                ``base_url`` (production or sandbox).
            client_id: Your CertiNext account number (used as the OAuth client ID).
            client_secret: OAuth client secret generated in the CertiNext portal.
            scope: Optional OAuth scope string.
            sandbox: When ``True``, default ``base_url`` / ``token_url`` to the
                sandbox endpoints. Callers can also read this attribute to adjust
                behaviour without re-inspecting the base URL.
            timeout: Default request timeout (:class:`httpx.Timeout` or
                seconds). See :class:`~certinext.client.CertiNextClient`.
            create_timeout: Timeout for certificate creation only. See
                :class:`~certinext.client.CertiNextClient`.
            retry: Retry policy for reads, or None (the default) for none.
                See :class:`~certinext.retry.RetryPolicy`.
        """
        from . import BASE_URL, SANDBOX_BASE_URL, SANDBOX_TOKEN_URL, TOKEN_URL
        self.sandbox = sandbox
        resolved_base = base_url or (SANDBOX_BASE_URL if sandbox else BASE_URL)
        resolved_token = token_url or (SANDBOX_TOKEN_URL if sandbox else TOKEN_URL)
        self._client = CertiNextClient(
            resolved_base, resolved_token, client_id, client_secret, scope,
            timeout=timeout, create_timeout=create_timeout, retry=retry,
        )
        self.accounts = AccountAccessor(self._client)
        self.catalog = CatalogAccessor(self._client)
        self.domain = DomainAccessor(self._client)
        self.ledger = LedgerAccessor(self._client)
        self.orders = OrderAccessor(self._client)
        self.ssl = SslAccessor(self._client)
        self.api_credentials = ApiCredentialAccessor(self._client)
        self.audit = AuditAccessor(self._client)
        self.users = UserAccessor(self._client)
        self.v3_orders = V3OrderAccessor(self._client)

    @property
    def retry(self) -> RetryPolicy | None:
        """The retry policy for reads, or None when reads are not retried (ADR 0025)."""
        return self._client.retry

    @retry.setter
    def retry(self, policy: RetryPolicy | None) -> None:
        """Replace the retry policy for reads.

        Applies to every accessor, and to models already returned, since
        they share this session's client.

        Args:
            policy: The new policy, or None to stop retrying.
        """
        self._client.retry = policy

    @contextmanager
    def retrying(self, policy: RetryPolicy | None) -> Iterator["CertiNextSession"]:
        """Use ``policy`` for reads inside a ``with`` block, then restore the previous one.

        Set it from the thread that starts any workers, before they start:
        the policy lives on the session, so every thread using the session
        sees it.

        Args:
            policy: The policy for the block, or None for no retries.

        Yields:
            This session.
        """
        previous = self._client.retry
        self._client.retry = policy
        try:
            yield self
        finally:
            self._client.retry = previous
