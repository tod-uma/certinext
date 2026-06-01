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

"""Tests for certinext.session.CertiNextSession and the certinext.session() factory."""

import certinext
from certinext.accounts import AccountAccessor
from certinext.catalog import CatalogAccessor
from certinext.domains import DomainAccessor
from certinext.ledger import LedgerAccessor
from certinext.orders import OrderAccessor
from certinext.session import CertiNextSession
from certinext.ssl_certificates import SslAccessor


class TestCertiNextSession:
    """CertiNextSession initialises correctly and mounts accessors."""

    def test_accounts_accessor_is_mounted(self):
        """session.accounts is an AccountAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.accounts, AccountAccessor)

    def test_catalog_accessor_is_mounted(self):
        """session.catalog is a CatalogAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.catalog, CatalogAccessor)

    def test_domain_accessor_is_mounted(self):
        """session.domain is a DomainAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.domain, DomainAccessor)

    def test_ledger_accessor_is_mounted(self):
        """session.ledger is a LedgerAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.ledger, LedgerAccessor)

    def test_orders_accessor_is_mounted(self):
        """session.orders is an OrderAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.orders, OrderAccessor)

    def test_ssl_accessor_is_mounted(self):
        """session.ssl is an SslAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.ssl, SslAccessor)

    def test_base_url_default(self):
        """The default base URL is https://us-api.certinext.io."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert sess._client.base_url == "https://us-api.certinext.io"

    def test_base_url_trailing_slash_stripped(self):
        """A trailing slash in base_url is stripped."""
        sess = CertiNextSession(
            base_url="https://us-api.certinext.io/",
            client_id="acct",
            client_secret="secret",
        )
        assert sess._client.base_url == "https://us-api.certinext.io"

    def test_custom_base_url(self):
        """A custom base_url is forwarded to the underlying client."""
        sess = CertiNextSession(
            base_url="https://eu-api.certinext.io",
            client_id="acct",
            client_secret="secret",
        )
        assert sess._client.base_url == "https://eu-api.certinext.io"


class TestSessionFactory:
    """certinext.session() factory returns a correctly configured CertiNextSession."""

    def test_returns_certinext_session(self):
        """session() returns a CertiNextSession instance."""
        sess = certinext.session(client_id="acct", client_secret="secret")
        assert isinstance(sess, CertiNextSession)

    def test_domain_accessor_available(self):
        """session().domain is a DomainAccessor."""
        sess = certinext.session(client_id="acct", client_secret="secret")
        assert isinstance(sess.domain, DomainAccessor)

    def test_orders_accessor_available(self):
        """session().orders is an OrderAccessor."""
        sess = certinext.session(client_id="acct", client_secret="secret")
        assert isinstance(sess.orders, OrderAccessor)

    def test_custom_urls_forwarded(self):
        """session() forwards custom base_url and token_url to the session."""
        sess = certinext.session(
            base_url="https://eu-api.certinext.io",
            token_url="https://eu-api.certinext.io/oauth/token",
            client_id="acct",
            client_secret="secret",
        )
        assert sess._client.base_url == "https://eu-api.certinext.io"

    def test_sandbox_true_uses_sandbox_base_url(self):
        """session(sandbox=True) defaults to the sandbox base URL, not production."""
        sess = certinext.session(client_id="acct", client_secret="secret", sandbox=True)
        assert sess._client.base_url == certinext.SANDBOX_BASE_URL
        assert sess._client.base_url != certinext.BASE_URL

    def test_sandbox_true_uses_sandbox_token_url(self):
        """session(sandbox=True) defaults to the sandbox token URL."""
        sess = certinext.session(client_id="acct", client_secret="secret", sandbox=True)
        assert "sandbox" in sess._client._auth.token_url

    def test_sandbox_false_uses_production_urls(self):
        """session(sandbox=False) uses production URLs (default behaviour)."""
        sess = certinext.session(client_id="acct", client_secret="secret", sandbox=False)
        assert sess._client.base_url == certinext.BASE_URL

    def test_explicit_url_overrides_sandbox_flag(self):
        """An explicit base_url takes precedence over sandbox=True."""
        custom = "https://custom-api.example.com"
        sess = certinext.session(
            base_url=custom, client_id="acct", client_secret="secret", sandbox=True
        )
        assert sess._client.base_url == custom

    def test_sandbox_flag_stored_on_session(self):
        """session.sandbox reflects the sandbox argument."""
        assert certinext.session(sandbox=True).sandbox is True
        assert certinext.session(sandbox=False).sandbox is False


class TestCertiNextSessionSandbox:
    """CertiNextSession.__init__ sandbox URL defaulting."""

    def test_sandbox_true_defaults_to_sandbox_base_url(self):
        """CertiNextSession(sandbox=True) uses sandbox base URL by default."""
        sess = CertiNextSession(client_id="acct", client_secret="secret", sandbox=True)
        assert sess._client.base_url == certinext.SANDBOX_BASE_URL

    def test_sandbox_false_defaults_to_production_base_url(self):
        """CertiNextSession(sandbox=False) uses production base URL by default."""
        sess = CertiNextSession(client_id="acct", client_secret="secret", sandbox=False)
        assert sess._client.base_url == certinext.BASE_URL

    def test_explicit_base_url_overrides_sandbox(self):
        """An explicit base_url overrides the sandbox=True default."""
        custom = "https://eu-api.certinext.io"
        sess = CertiNextSession(
            base_url=custom, client_id="acct", client_secret="secret", sandbox=True
        )
        assert sess._client.base_url == custom
