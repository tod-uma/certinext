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

"""Integration tests against the CertiNext sandbox API.

These tests require sandbox credentials stored in the OS keychain under the
``sandbox`` profile.  Set them up once with::

    certinext-setup-keyring --sandbox

All tests are skipped automatically when credentials are not available, so
they are safe to run in CI environments that lack a keyring (they will simply
show as skipped).

Run the integration suite explicitly with::

    pytest -m integration
"""

import os

import pytest

import certinext
from certinext._keyring import keyring_get, keyring_service
from certinext.accounts import AccountInfo, Group, Organization
from certinext.catalog import ProductCategory
from certinext.domain_cert_count_cli import _build_rows
from certinext.domains import Domain
from certinext.ledger import LedgerRecord
from certinext.orders import OrderRecord
from certinext.ssl_certificates import SslOrder

# ---------------------------------------------------------------------------
# Session-scoped fixtures — authenticate and fetch once per pytest run
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_session() -> certinext.CertiNextSession:
    """Return a CertiNextSession pointed at the sandbox, or skip the test.

    Looks up credentials from the ``sandbox`` keyring profile.  If the profile
    is not found, all tests that depend on this fixture are skipped.
    """
    svc = keyring_service("certinext", "sandbox")
    client_id = keyring_get(svc, "CERTINEXT_CLIENT_ID") or os.environ.get("CERTINEXT_SANDBOX_CLIENT_ID")
    client_secret = keyring_get(svc, "CERTINEXT_CLIENT_SECRET") or os.environ.get("CERTINEXT_SANDBOX_CLIENT_SECRET")
    if not client_id or not client_secret:
        pytest.skip(
            "sandbox credentials not available — run: certinext-setup-keyring --sandbox "
            "or set CERTINEXT_SANDBOX_CLIENT_ID / CERTINEXT_SANDBOX_CLIENT_SECRET"
        )
    return certinext.session(
        base_url=certinext.SANDBOX_BASE_URL,
        token_url=certinext.SANDBOX_TOKEN_URL,
        client_id=client_id,
        client_secret=client_secret,
    )


@pytest.fixture(scope="session")
def sandbox_domains(sandbox_session: certinext.CertiNextSession) -> list[Domain]:
    """Fetch all sandbox domains once for the session."""
    return sandbox_session.domain.get_list()


@pytest.fixture(scope="session")
def sandbox_orders(sandbox_session: certinext.CertiNextSession) -> list[OrderRecord]:
    """Fetch all sandbox orders once for the session."""
    return sandbox_session.orders.get_list()


# ---------------------------------------------------------------------------
# Domains API
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSandboxDomains:
    """Integration tests for the Domains API against the sandbox."""

    def test_domain_list_is_non_empty(self, sandbox_domains: list[Domain]) -> None:
        """The sandbox has at least one registered domain."""
        assert len(sandbox_domains) > 0

    def test_domain_list_returns_domain_objects(self, sandbox_domains: list[Domain]) -> None:
        """Every item returned by get_list() is a Domain instance."""
        assert all(isinstance(d, Domain) for d in sandbox_domains)

    def test_every_domain_has_id_and_name(self, sandbox_domains: list[Domain]) -> None:
        """Every domain has a non-None id and name."""
        for d in sandbox_domains:
            assert d.id is not None, f"domain missing id: {d!r}"
            assert d.name is not None, f"domain missing name: {d!r}"

    def test_domain_status_values_are_known(self, sandbox_domains: list[Domain]) -> None:
        """Every domain's status is one of the documented valid values."""
        valid = {"ACTIVE", "INACTIVE", "EXPIRED", "REVOKED"}
        for d in sandbox_domains:
            assert d.status in valid, f"unexpected status {d.status!r} on {d.name}"

    def test_domain_dcv_status_values_are_known(self, sandbox_domains: list[Domain]) -> None:
        """Every domain's dcv_status is one of the documented valid values."""
        valid = {"VERIFIED", "PENDING", "REJECTED", "EXPIRED"}
        for d in sandbox_domains:
            assert d.dcv_status in valid, f"unexpected dcv_status {d.dcv_status!r} on {d.name}"

    def test_domain_get_by_id(self, sandbox_session: certinext.CertiNextSession, sandbox_domains: list[Domain]) -> None:
        """get() retrieves a domain by its ID and returns matching fields."""
        first = sandbox_domains[0]
        assert first.id is not None
        fetched = sandbox_session.domain.get(first.id)
        assert fetched.id == first.id
        assert fetched.name == first.name

    def test_domain_get_by_name(
        self, sandbox_session: certinext.CertiNextSession, sandbox_domains: list[Domain]
    ) -> None:
        """get() retrieves a domain by its FQDN."""
        # Use the first non-wildcard domain to avoid any edge-case with wildcard lookup.
        target = next((d for d in sandbox_domains if d.name and not d.name.startswith("*")), None)
        if target is None:
            pytest.skip("no non-wildcard domains in sandbox")
        assert target.name is not None
        fetched = sandbox_session.domain.get(target.name)
        assert fetched.name == target.name

    def test_get_pending_dcv_all_need_dcv(self, sandbox_session: certinext.CertiNextSession) -> None:
        """get_pending_dcv() returns only domains whose needs_dcv is True."""
        pending = sandbox_session.domain.get_pending_dcv()
        assert all(d.needs_dcv for d in pending)

    def test_to_row_returns_string_values(self, sandbox_domains: list[Domain]) -> None:
        """to_row() on a live domain returns a dict with string values."""
        row = sandbox_domains[0].to_row()
        assert all(isinstance(v, str) for v in row.values())


# ---------------------------------------------------------------------------
# Orders Report API
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSandboxOrders:
    """Integration tests for the Orders Report API against the sandbox."""

    def test_orders_list_returns_list(self, sandbox_orders: list[OrderRecord]) -> None:
        """get_list() returns a list of OrderRecord objects (may be empty)."""
        assert isinstance(sandbox_orders, list)
        assert all(isinstance(o, OrderRecord) for o in sandbox_orders)

    def test_orders_get_page_returns_list(self, sandbox_session: certinext.CertiNextSession) -> None:
        """get_page(page=1) returns a list without raising."""
        page = sandbox_session.orders.get_page(page=1)
        assert isinstance(page, list)

    def test_orders_status_filter_issued(self, sandbox_session: certinext.CertiNextSession) -> None:
        """get_list(status='issued') returns only records with certificate_status 'issued'."""
        orders = sandbox_session.orders.get_list(status="issued")
        for o in orders:
            assert o.certificate_status == "issued"

    def test_orders_status_filter_expired(self, sandbox_session: certinext.CertiNextSession) -> None:
        """get_list(status='expired') returns only records with certificate_status 'expired'."""
        orders = sandbox_session.orders.get_list(status="expired")
        for o in orders:
            assert o.certificate_status == "expired"

    def test_order_record_properties_accessible(self, sandbox_orders: list[OrderRecord]) -> None:
        """Accessing all OrderRecord properties on live data does not raise."""
        for o in sandbox_orders:
            _ = o.order_number
            _ = o.request_number
            _ = o.product_code
            _ = o.order_status
            _ = o.certificate_status
            _ = o.common_name
            _ = o.to_row()

    def test_to_row_returns_string_values(self, sandbox_orders: list[OrderRecord]) -> None:
        """to_row() returns a dict with all-string values on live order data."""
        for o in sandbox_orders:
            row = o.to_row()
            assert all(isinstance(v, str) for v in row.values())


# ---------------------------------------------------------------------------
# Domain cert count join
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSandboxDomainCertCount:
    """Integration tests for _build_rows against live sandbox data."""

    def test_build_rows_completes(self, sandbox_domains: list[Domain], sandbox_orders: list[OrderRecord]) -> None:
        """_build_rows() returns a list of dicts without raising."""
        rows = _build_rows(sandbox_domains, sandbox_orders)
        assert isinstance(rows, list)
        assert all("domain" in r and "certificates" in r for r in rows)

    def test_build_rows_condense_completes(
        self, sandbox_domains: list[Domain], sandbox_orders: list[OrderRecord]
    ) -> None:
        """_build_rows(condense=True) returns a list of dicts without raising."""
        rows = _build_rows(sandbox_domains, sandbox_orders, condense=True)
        assert isinstance(rows, list)
        assert all("domain" in r and "certificates" in r for r in rows)

    def test_every_registered_domain_in_rows(
        self, sandbox_domains: list[Domain], sandbox_orders: list[OrderRecord]
    ) -> None:
        """Every registered domain appears in the output rows."""
        rows = _build_rows(sandbox_domains, sandbox_orders)
        row_domains = {r["domain"] for r in rows if "not registered" not in r["domain"]}
        for d in sandbox_domains:
            assert d.name in row_domains, f"{d.name!r} missing from output rows"

    def test_condensed_rows_contain_only_apex_domains(
        self, sandbox_domains: list[Domain], sandbox_orders: list[OrderRecord]
    ) -> None:
        """With condense=True, no row domain is a registered subdomain of another row domain."""
        rows = _build_rows(sandbox_domains, sandbox_orders, condense=True)
        registered_names = {(d.name or "").lower() for d in sandbox_domains}
        apex_names = [r["domain"].lower() for r in rows if "not registered" not in r["domain"]]
        for name in apex_names:
            parents = [p for p in registered_names if name != p and name.endswith(f".{p}")]
            assert not parents, f"{name!r} has registered parent {parents[0]!r} — should not appear in condensed output"


# ---------------------------------------------------------------------------
# Accounts API
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_account_info(sandbox_session: certinext.CertiNextSession) -> AccountInfo:
    """Fetch current account info once for the session."""
    return sandbox_session.accounts.me()


@pytest.fixture(scope="session")
def sandbox_groups(sandbox_session: certinext.CertiNextSession) -> list[Group]:
    """Fetch sandbox billing groups once for the session."""
    return sandbox_session.accounts.list_groups()


@pytest.fixture(scope="session")
def sandbox_organizations(sandbox_session: certinext.CertiNextSession) -> list[Organization]:
    """Fetch sandbox organizations once for the session."""
    return sandbox_session.accounts.list_organizations()


@pytest.mark.integration
class TestSandboxAccounts:
    """Integration tests for the Accounts API against the sandbox."""

    def test_me_returns_account_info(self, sandbox_account_info: AccountInfo) -> None:
        """me() returns an AccountInfo instance."""
        assert isinstance(sandbox_account_info, AccountInfo)

    def test_account_has_number(self, sandbox_account_info: AccountInfo) -> None:
        """The sandbox account has a non-None account_number."""
        assert sandbox_account_info.account_number is not None

    def test_account_name_is_str_or_none(self, sandbox_account_info: AccountInfo) -> None:
        """account_name is a str when present, or None — not every account has one configured."""
        assert sandbox_account_info.account_name is None or isinstance(sandbox_account_info.account_name, str)

    def test_list_groups_returns_list(self, sandbox_groups: list[Group]) -> None:
        """list_groups() returns a list (may be empty)."""
        assert isinstance(sandbox_groups, list)

    def test_groups_are_group_objects(self, sandbox_groups: list[Group]) -> None:
        """Every item returned by list_groups() is a Group instance."""
        assert all(isinstance(g, Group) for g in sandbox_groups)

    def test_list_organizations_returns_list(self, sandbox_organizations: list[Organization]) -> None:
        """list_organizations() returns a list (may be empty)."""
        assert isinstance(sandbox_organizations, list)

    def test_organizations_are_organization_objects(self, sandbox_organizations: list[Organization]) -> None:
        """Every item returned by list_organizations() is an Organization instance."""
        assert all(isinstance(o, Organization) for o in sandbox_organizations)

    def test_get_organization_matches_listed(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_organizations: list[Organization],
    ) -> None:
        """get_organization() returns an org whose number matches the listed record."""
        if not sandbox_organizations:
            pytest.skip("no organizations in sandbox account")
        first = sandbox_organizations[0]
        if first.organization_number is None:
            pytest.skip("first organization has no number")
        fetched = sandbox_session.accounts.get_organization(first.organization_number)
        assert isinstance(fetched, Organization)
        assert fetched.organization_number == first.organization_number


# ---------------------------------------------------------------------------
# Catalog API
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_catalog(sandbox_session: certinext.CertiNextSession) -> list[ProductCategory]:
    """Fetch the product catalog once for the session."""
    return sandbox_session.catalog.list_products()


@pytest.mark.integration
class TestSandboxCatalog:
    """Integration tests for the Catalog API against the sandbox."""

    def test_list_products_returns_non_empty(self, sandbox_catalog: list[ProductCategory]) -> None:
        """list_products() returns at least one product category."""
        assert len(sandbox_catalog) > 0

    def test_products_have_codes_and_names(self, sandbox_catalog: list[ProductCategory]) -> None:
        """Every product has a product_code and product_name."""
        for category in sandbox_catalog:
            for product in category.products:
                assert product.product_code is not None, f"product missing code: {product!r}"
                assert product.product_name is not None, f"product missing name: {product!r}"

    def test_dv_product_present(self, sandbox_catalog: list[ProductCategory]) -> None:
        """The catalog includes at least one DV SSL product."""
        from certinext.ssl_certificates import _matches_variant
        products = [p for cat in sandbox_catalog for p in cat.products]
        dv = [p for p in products if p.product_name and _matches_variant(p.product_name, "DV", False, False)]
        assert len(dv) > 0, "expected at least one DV SSL product in catalog"

    def test_get_custom_fields_returns_list(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_catalog: list[ProductCategory],
    ) -> None:
        """get_custom_fields() returns a list for the first available product."""
        first_product = next(
            (p for cat in sandbox_catalog for p in cat.products if p.product_code),
            None,
        )
        if first_product is None or first_product.product_code is None:
            pytest.skip("no products with codes in catalog")
        fields = sandbox_session.catalog.get_custom_fields(first_product.product_code)
        assert isinstance(fields, list)


# ---------------------------------------------------------------------------
# Ledger API
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_ledger(sandbox_session: certinext.CertiNextSession) -> list[LedgerRecord]:
    """Fetch all sandbox ledger records once for the session."""
    return sandbox_session.ledger.get_list()


@pytest.mark.integration
class TestSandboxLedger:
    """Integration tests for the Ledger API against the sandbox."""

    def test_get_page_returns_list(self, sandbox_session: certinext.CertiNextSession) -> None:
        """get_page(page=1) returns a list without raising."""
        page = sandbox_session.ledger.get_page(page=1)
        assert isinstance(page, list)

    def test_get_list_returns_list(self, sandbox_ledger: list[LedgerRecord]) -> None:
        """get_list() returns a list of LedgerRecord objects (may be empty)."""
        assert isinstance(sandbox_ledger, list)
        assert all(isinstance(r, LedgerRecord) for r in sandbox_ledger)

    def test_ledger_record_properties_accessible(self, sandbox_ledger: list[LedgerRecord]) -> None:
        """Accessing all LedgerRecord properties on live data does not raise."""
        for r in sandbox_ledger:
            _ = r.transaction_date
            _ = r.description
            _ = r.order_number
            _ = r.transaction_type
            _ = r.debit
            _ = r.credit
            _ = r.balance

    def test_to_row_returns_string_values(self, sandbox_ledger: list[LedgerRecord]) -> None:
        """to_row() returns a dict with all-string values on live ledger data."""
        for r in sandbox_ledger:
            row = r.to_row()
            assert all(isinstance(v, str) for v in row.values())


# ---------------------------------------------------------------------------
# SSL Certificates API
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSandboxSsl:
    """Integration tests for the SSL Certificates API against the sandbox.

    All tests are read-only — no certificates are ordered. Existing orders
    from the sandbox Orders Report are used as test data for ``ssl.get()``.
    """

    def test_ssl_dv_product_resolvable(self, sandbox_session: certinext.CertiNextSession) -> None:
        """The catalog contains at least one DV SSL product that SslAccessor can resolve."""
        from certinext.ssl_certificates import _matches_variant
        categories = sandbox_session.catalog.list_products()
        products = [p for cat in categories for p in cat.products]
        dv = [p for p in products if p.product_name and _matches_variant(p.product_name, "DV", False, False)]
        assert len(dv) > 0, "no DV SSL product found in catalog"

    def test_get_ssl_order_by_order_number(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_orders: list[OrderRecord],
    ) -> None:
        """ssl.get() returns an SslOrder when called with an order_number from the orders report."""
        if not sandbox_orders:
            pytest.skip("no orders in sandbox")
        first = sandbox_orders[0]
        if first.order_number is None:
            pytest.skip("first order has no order_number")
        order = sandbox_session.ssl.get(first.order_number)
        assert isinstance(order, SslOrder)

    def test_ssl_order_properties_accessible(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_orders: list[OrderRecord],
    ) -> None:
        """Accessing all SslOrder properties on a live order does not raise."""
        if not sandbox_orders:
            pytest.skip("no orders in sandbox")
        first = sandbox_orders[0]
        if first.order_number is None:
            pytest.skip("first order has no order_number")
        order = sandbox_session.ssl.get(first.order_number)
        _ = order.order_id
        _ = order.request_id
        _ = order.status
        _ = order.domain
        _ = order.additional_domains
        _ = order.product_variant
        _ = order.created_at

    def test_ssl_order_status_is_known_value(
        self,
        sandbox_session: certinext.CertiNextSession,
        sandbox_orders: list[OrderRecord],
    ) -> None:
        """SslOrder.status is one of the documented SslOrderStatus values."""
        if not sandbox_orders:
            pytest.skip("no orders in sandbox")
        first = sandbox_orders[0]
        if first.order_number is None:
            pytest.skip("first order has no order_number")
        order = sandbox_session.ssl.get(first.order_number)
        valid = {
            "pending-dcv", "pending-organization-verification", "pending-csr",
            "pending-documents", "pending-agreement", "pending-approval",
            "issued", "revoked", "cancelled", "rejected", "expired", "unknown",
        }
        assert order.status is None or order.status in valid, f"unexpected status {order.status!r}"
