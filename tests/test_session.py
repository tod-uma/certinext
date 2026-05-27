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
from certinext.domains import DomainAccessor
from certinext.orders import OrderAccessor
from certinext.session import CertiNextSession


class TestCertiNextSession:
    """CertiNextSession initialises correctly and mounts accessors."""

    def test_domain_accessor_is_mounted(self):
        """session.domain is a DomainAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.domain, DomainAccessor)

    def test_orders_accessor_is_mounted(self):
        """session.orders is an OrderAccessor instance."""
        sess = CertiNextSession(client_id="acct", client_secret="secret")
        assert isinstance(sess.orders, OrderAccessor)

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
