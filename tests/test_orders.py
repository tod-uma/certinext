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

"""Tests for certinext.orders (OrderRecord, OrderAccessor) and domain_cert_count_cli._build_rows."""

from unittest.mock import MagicMock

import pytest

from certinext.client import CertiNextClient
from certinext.domain_cert_count_cli import _apex_domain, _build_rows, _match_domain
from certinext.domains import Domain
from certinext.orders import OrderAccessor, OrderRecord

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ORDER: dict = {
    "orderNumber": "ORD-001",
    "requestNumber": "REQ-001",
    "productCode": "OV_SSL",
    "orderStatus": "complete",
    "certificateStatus": "issued",
    "commonName": "maine.edu",
}

SAMPLE_ORDER_EXPIRED: dict = {
    "orderNumber": "ORD-002",
    "requestNumber": "REQ-002",
    "productCode": "DV_SSL",
    "orderStatus": "complete",
    "certificateStatus": "expired",
    "commonName": "sub.maine.edu",
}

SAMPLE_ORDER_NO_CN: dict = {
    "orderNumber": "ORD-003",
    "requestNumber": "REQ-003",
    "productCode": "DV_SSL",
    "orderStatus": "complete",
    "certificateStatus": "issued",
}

SAMPLE_ORDER_DOMAIN_FIELD: dict = {
    "orderNumber": "ORD-004",
    "requestNumber": "REQ-004",
    "productCode": "DV_SSL",
    "orderStatus": "complete",
    "certificateStatus": "issued",
    "domain": "example.edu",
}

SAMPLE_DOMAIN_DATA: dict = {
    "domainId": "dom-001",
    "domainName": "maine.edu",
    "organizationId": "org-001",
    "organizationName": "Example Org",
    "status": "ACTIVE",
    "dcvStatus": "VERIFIED",
    "createdAt": "2026-05-01T00:00:00Z",
}

SAMPLE_DOMAIN_DATA_2: dict = {
    "domainId": "dom-002",
    "domainName": "sub.maine.edu",
    "organizationId": "org-001",
    "organizationName": "Example Org",
    "status": "ACTIVE",
    "dcvStatus": "PENDING",
    "createdAt": "2026-05-01T00:00:00Z",
}

SAMPLE_DOMAIN_DATA_NOCERTS: dict = {
    "domainId": "dom-003",
    "domainName": "empty.maine.edu",
    "organizationId": "org-001",
    "organizationName": "Example Org",
    "status": "ACTIVE",
    "dcvStatus": "PENDING",
    "createdAt": "2026-05-01T00:00:00Z",
}


@pytest.fixture
def mock_client() -> MagicMock:
    """A MagicMock standing in for CertiNextClient."""
    return MagicMock(spec=CertiNextClient)


@pytest.fixture
def order() -> OrderRecord:
    """An OrderRecord from SAMPLE_ORDER."""
    return OrderRecord(dict(SAMPLE_ORDER))


@pytest.fixture
def accessor(mock_client: MagicMock) -> OrderAccessor:
    """An OrderAccessor backed by mock_client."""
    return OrderAccessor(mock_client)


# ---------------------------------------------------------------------------
# OrderRecord properties
# ---------------------------------------------------------------------------

class TestOrderRecordProperties:
    """Tests for OrderRecord field accessors."""

    def test_order_number(self, order: OrderRecord):
        """order_number maps to the orderNumber field."""
        assert order.order_number == "ORD-001"

    def test_request_number(self, order: OrderRecord):
        """request_number maps to the requestNumber field."""
        assert order.request_number == "REQ-001"

    def test_product_code(self, order: OrderRecord):
        """product_code maps to the productCode field."""
        assert order.product_code == "OV_SSL"

    def test_order_status(self, order: OrderRecord):
        """order_status maps to the orderStatus field."""
        assert order.order_status == "complete"

    def test_certificate_status(self, order: OrderRecord):
        """certificate_status maps to the certificateStatus field."""
        assert order.certificate_status == "issued"

    def test_common_name_from_common_name_field(self, order: OrderRecord):
        """common_name reads the commonName field when present."""
        assert order.common_name == "maine.edu"

    def test_common_name_from_domain_field(self):
        """common_name falls back to the domain field when commonName is absent."""
        rec = OrderRecord(dict(SAMPLE_ORDER_DOMAIN_FIELD))
        assert rec.common_name == "example.edu"

    def test_common_name_none_when_absent(self):
        """common_name returns None when no domain field is present."""
        rec = OrderRecord(dict(SAMPLE_ORDER_NO_CN))
        assert rec.common_name is None

    def test_as_dict_returns_raw_data(self, order: OrderRecord):
        """as_dict() returns the original raw data dict."""
        assert order.as_dict() == SAMPLE_ORDER

    def test_to_row_returns_string_values(self, order: OrderRecord):
        """to_row() returns a dict where all values are strings."""
        row = order.to_row()
        assert all(isinstance(v, str) for v in row.values())

    def test_to_row_includes_expected_keys(self, order: OrderRecord):
        """to_row() includes common_name, certificate_status, order_number, order_status, product_code."""
        row = order.to_row()
        assert set(row.keys()) == {"common_name", "certificate_status", "order_status", "order_number", "product_code"}

    def test_to_row_none_fields_become_empty_string(self):
        """to_row() converts None fields to empty strings."""
        rec = OrderRecord({})
        row = rec.to_row()
        assert all(v == "" for v in row.values())

    def test_repr_starts_with_class_name(self, order: OrderRecord):
        """repr() starts with OrderRecord(."""
        assert repr(order).startswith("OrderRecord(")

    def test_repr_includes_order_number(self, order: OrderRecord):
        """repr() includes the order number."""
        assert "ORD-001" in repr(order)


# ---------------------------------------------------------------------------
# OrderAccessor.get_page response parsing
# ---------------------------------------------------------------------------

class TestOrderAccessorGetPage:
    """Tests for OrderAccessor.get_page() response shape handling."""

    def test_list_response(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_page() handles a bare list response from the API."""
        mock_client.get.return_value = [SAMPLE_ORDER, SAMPLE_ORDER_EXPIRED]
        result = accessor.get_page(page=1)
        assert len(result) == 2
        assert all(isinstance(r, OrderRecord) for r in result)

    def test_dict_response_with_list_value(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_page() extracts the list from a wrapper dict response."""
        mock_client.get.return_value = {"orders": [SAMPLE_ORDER], "total": 1}
        result = accessor.get_page(page=1)
        assert len(result) == 1
        assert result[0].order_number == "ORD-001"

    def test_empty_response(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_page() returns an empty list for an empty list response."""
        mock_client.get.return_value = []
        result = accessor.get_page(page=1)
        assert result == []

    def test_status_param_forwarded(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_page() passes the status parameter to the API client."""
        mock_client.get.return_value = []
        accessor.get_page(page=1, size=50, status="issued")
        mock_client.get.assert_called_once()
        _, kwargs = mock_client.get.call_args
        assert kwargs["params"]["status"] == "issued"
        assert kwargs["params"]["page"] == 1
        assert kwargs["params"]["size"] == 50

    def test_no_status_param_when_none(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_page() omits the status key when status=None."""
        mock_client.get.return_value = []
        accessor.get_page()
        _, kwargs = mock_client.get.call_args
        assert "status" not in kwargs["params"]


# ---------------------------------------------------------------------------
# OrderAccessor.get_list pagination
# ---------------------------------------------------------------------------

class TestOrderAccessorGetList:
    """Tests for OrderAccessor.get_list() automatic pagination."""

    def test_single_page(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_list() returns all records when a single partial page is returned."""
        mock_client.get.return_value = [SAMPLE_ORDER, SAMPLE_ORDER_EXPIRED]
        result = accessor.get_list(page_size=100)
        assert len(result) == 2
        assert mock_client.get.call_count == 1

    def test_multi_page(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_list() fetches subsequent pages until a short page is returned."""
        full_page = [SAMPLE_ORDER] * 2
        last_page = [SAMPLE_ORDER_EXPIRED]
        mock_client.get.side_effect = [full_page, last_page]
        result = accessor.get_list(page_size=2)
        assert len(result) == 3
        assert mock_client.get.call_count == 2

    def test_empty_account(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_list() returns an empty list when the API returns no records."""
        mock_client.get.return_value = []
        result = accessor.get_list()
        assert result == []
        assert mock_client.get.call_count == 1

    def test_status_filter_forwarded(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_list() passes status filter to each page request."""
        mock_client.get.return_value = [SAMPLE_ORDER]
        accessor.get_list(status="expired")
        _, kwargs = mock_client.get.call_args
        assert kwargs["params"]["status"] == "expired"

    def test_exact_full_page_fetches_next(self, accessor: OrderAccessor, mock_client: MagicMock):
        """get_list() fetches the next page when the current page is exactly page_size."""
        full_page = [SAMPLE_ORDER] * 2
        empty_page: list = []
        mock_client.get.side_effect = [full_page, empty_page]
        result = accessor.get_list(page_size=2)
        assert len(result) == 2
        assert mock_client.get.call_count == 2


# ---------------------------------------------------------------------------
# _build_rows join logic
# ---------------------------------------------------------------------------

class TestBuildRows:
    """Tests for the domain/order join in domain_cert_count._build_rows."""

    def _domain(self, data: dict) -> Domain:
        return Domain(MagicMock(spec=CertiNextClient), data)

    def test_registered_domain_with_matching_order(self):
        """A registered domain with a matching order shows count 1."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        orders = [OrderRecord(dict(SAMPLE_ORDER))]
        rows = _build_rows(domains, orders)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "1"

    def test_registered_domain_no_orders_shows_zero(self):
        """A registered domain with no matching orders shows count 0."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA_NOCERTS)]
        orders: list[OrderRecord] = []
        rows = _build_rows(domains, orders)
        assert rows[0]["certificates"] == "0"

    def test_multiple_orders_same_domain(self):
        """Multiple orders for the same domain accumulate the count."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        orders = [OrderRecord(dict(SAMPLE_ORDER)), OrderRecord(dict(SAMPLE_ORDER))]
        rows = _build_rows(domains, orders)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "2"

    def test_orphaned_order_appended(self):
        """An order whose CN is not in the domain registry appears as 'not registered'."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        orphan = OrderRecord({"orderNumber": "ORD-999", "certificateStatus": "issued", "commonName": "orphan.edu"})
        rows = _build_rows(domains, [orphan])
        orphan_row = next((r for r in rows if "orphan.edu" in r["domain"]), None)
        assert orphan_row is not None
        assert "not registered" in orphan_row["domain"]
        assert orphan_row["certificates"] == "1"

    def test_order_without_common_name_ignored(self):
        """An order with no common_name is excluded from counts."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        orders = [OrderRecord(dict(SAMPLE_ORDER_NO_CN))]
        rows = _build_rows(domains, orders)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "0"

    def test_case_insensitive_matching(self):
        """Domain name matching is case-insensitive."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        order_upper = OrderRecord({**SAMPLE_ORDER, "commonName": "MAINE.EDU"})
        rows = _build_rows(domains, [order_upper])
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "1"

    def test_rows_sorted_alphabetically(self):
        """Registered domain rows are sorted alphabetically by name."""
        domains = [
            self._domain(SAMPLE_DOMAIN_DATA_NOCERTS),
            self._domain(SAMPLE_DOMAIN_DATA_2),
            self._domain(SAMPLE_DOMAIN_DATA),
        ]
        rows = _build_rows(domains, [])
        registered_names = [r["domain"] for r in rows if "not registered" not in r["domain"]]
        assert registered_names == sorted(registered_names)

    def test_empty_domain_list(self):
        """An empty domain list with no orders returns no rows."""
        rows = _build_rows([], [])
        assert rows == []

    def test_hostname_cert_matches_parent_domain(self):
        """A cert CN that is a hostname under a registered domain counts toward that domain."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]  # maine.edu
        order = OrderRecord({"orderNumber": "ORD-X", "certificateStatus": "issued", "commonName": "host.maine.edu"})
        rows = _build_rows(domains, [order])
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "1"

    def test_most_specific_domain_wins(self):
        """A hostname under a registered subdomain counts toward that subdomain, not the apex."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA), self._domain(SAMPLE_DOMAIN_DATA_2)]
        # SAMPLE_DOMAIN_DATA_2 is sub.maine.edu; cert CN is host.sub.maine.edu
        order = OrderRecord({"orderNumber": "ORD-X", "certificateStatus": "issued", "commonName": "host.sub.maine.edu"})
        rows = _build_rows(domains, [order])
        sub_row = next(r for r in rows if r["domain"] == "sub.maine.edu")
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert sub_row["certificates"] == "1"
        assert maine_row["certificates"] == "0"


# ---------------------------------------------------------------------------
# _match_domain helper
# ---------------------------------------------------------------------------

class TestMatchDomain:
    """Tests for _match_domain."""

    def test_exact_match(self):
        """Exact CN match returns the domain name."""
        assert _match_domain("maine.edu", {"maine.edu"}) == "maine.edu"

    def test_suffix_match(self):
        """A hostname under a registered domain returns that domain."""
        assert _match_domain("host.maine.edu", {"maine.edu"}) == "maine.edu"

    def test_most_specific_suffix_wins(self):
        """The longest (most specific) suffix match is returned."""
        assert _match_domain("host.noc.maine.edu", {"maine.edu", "noc.maine.edu"}) == "noc.maine.edu"

    def test_no_match_returns_none(self):
        """A CN with no registered suffix returns None."""
        assert _match_domain("orphan.edu", {"maine.edu"}) is None

    def test_partial_label_not_matched(self):
        """A domain whose name is a substring but not a proper suffix label is not matched."""
        # "emaine.edu" should NOT match "maine.edu"
        assert _match_domain("emaine.edu", {"maine.edu"}) is None

    def test_exact_beats_suffix(self):
        """Exact match is preferred over any suffix match."""
        assert _match_domain("noc.maine.edu", {"maine.edu", "noc.maine.edu"}) == "noc.maine.edu"


# ---------------------------------------------------------------------------
# _apex_domain helper
# ---------------------------------------------------------------------------

class TestApexDomain:
    """Tests for _apex_domain."""

    def test_apex_domain_is_itself(self):
        """A domain with no registered parent returns itself."""
        assert _apex_domain("maine.edu", {"maine.edu", "noc.maine.edu"}) == "maine.edu"

    def test_subdomain_resolves_to_apex(self):
        """A direct subdomain resolves to its apex."""
        assert _apex_domain("noc.maine.edu", {"maine.edu", "noc.maine.edu"}) == "maine.edu"

    def test_multi_level_resolves_to_apex(self):
        """A three-level registered hierarchy resolves all the way to the apex."""
        registered = {"maine.edu", "noc.maine.edu", "host.noc.maine.edu"}
        assert _apex_domain("host.noc.maine.edu", registered) == "maine.edu"

    def test_isolated_apex(self):
        """A domain with no other registered entries is its own apex."""
        assert _apex_domain("farmington.edu", {"farmington.edu"}) == "farmington.edu"


# ---------------------------------------------------------------------------
# _build_rows --condense
# ---------------------------------------------------------------------------

class TestBuildRowsCondense:
    """Tests for _build_rows with condense=True."""

    def _domain(self, data: dict) -> Domain:
        """Build a Domain fixture."""
        return Domain(MagicMock(spec=CertiNextClient), data)

    def test_condense_hides_subdomain_rows(self):
        """With condense=True, registered subdomains do not appear as rows."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA), self._domain(SAMPLE_DOMAIN_DATA_2)]
        rows = _build_rows(domains, [], condense=True)
        names = [r["domain"] for r in rows]
        assert "maine.edu" in names
        assert "sub.maine.edu" not in names

    def test_condense_rolls_up_direct_subdomain_certs(self):
        """Certs for a registered subdomain are counted under the apex when condensed."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA), self._domain(SAMPLE_DOMAIN_DATA_2)]
        orders = [OrderRecord(dict(SAMPLE_ORDER_EXPIRED))]  # CN = sub.maine.edu
        rows = _build_rows(domains, orders, condense=True)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "1"

    def test_condense_rolls_up_hostname_certs(self):
        """Certs for a hostname under a subdomain roll up to the apex."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA), self._domain(SAMPLE_DOMAIN_DATA_2)]
        order = OrderRecord({"orderNumber": "ORD-X", "certificateStatus": "issued", "commonName": "host.sub.maine.edu"})
        rows = _build_rows(domains, [order], condense=True)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "1"

    def test_condense_sums_all_subtree_certs(self):
        """Certs from multiple subdomains are all summed at the apex."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA), self._domain(SAMPLE_DOMAIN_DATA_2)]
        orders = [
            OrderRecord(dict(SAMPLE_ORDER)),           # CN = maine.edu (apex itself)
            OrderRecord(dict(SAMPLE_ORDER_EXPIRED)),   # CN = sub.maine.edu
        ]
        rows = _build_rows(domains, orders, condense=True)
        maine_row = next(r for r in rows if r["domain"] == "maine.edu")
        assert maine_row["certificates"] == "2"

    def test_condense_preserves_orphans(self):
        """Orphaned orders still appear as '(not registered)' even with condense=True."""
        domains = [self._domain(SAMPLE_DOMAIN_DATA)]
        orphan = OrderRecord({"orderNumber": "ORD-999", "certificateStatus": "issued", "commonName": "orphan.edu"})
        rows = _build_rows(domains, [orphan], condense=True)
        orphan_row = next((r for r in rows if "orphan.edu" in r["domain"]), None)
        assert orphan_row is not None
        assert "not registered" in orphan_row["domain"]

    def test_condense_sorted_alphabetically(self):
        """Condensed apex rows are sorted alphabetically."""
        domains = [
            self._domain(SAMPLE_DOMAIN_DATA_NOCERTS),  # empty.maine.edu — subdomain
            self._domain(SAMPLE_DOMAIN_DATA_2),         # sub.maine.edu — subdomain
            self._domain(SAMPLE_DOMAIN_DATA),           # maine.edu — apex
        ]
        rows = _build_rows(domains, [], condense=True)
        names = [r["domain"] for r in rows if "not registered" not in r["domain"]]
        assert names == sorted(names)
