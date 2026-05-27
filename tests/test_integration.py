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
from certinext.domain_cert_count import _build_rows
from certinext.domains import Domain
from certinext.orders import OrderRecord

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

    def test_list_pending_dcv_all_need_dcv(self, sandbox_session: certinext.CertiNextSession) -> None:
        """list_pending_dcv() returns only domains whose needs_dcv is True."""
        pending = sandbox_session.domain.list_pending_dcv()
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
