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

"""Tests for certinext.domains.Domain and DomainAccessor."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from certinext.domains import DcvInfo, Domain, DomainAccessor
from tests.conftest import (
    FAR_FUTURE_VALID_TILL,
    PAST_VALID_TILL,
    SAMPLE_DOMAIN_DATA,
    SAMPLE_DOMAIN_DATA_2,
    SAMPLE_DOMAIN_DETAIL_DATA,
    SAMPLE_DCV_VERIFIED,
    SAMPLE_DCV_PENDING_WITH_TOKEN,
    SAMPLE_DCV_UNSET,
)


class TestDomainProperties:
    """Domain exposes all API fields as typed properties."""

    def test_id(self, domain: Domain):
        """id returns the domainId from the API response."""
        assert domain.id == SAMPLE_DOMAIN_DATA["domainId"]

    def test_name(self, domain: Domain):
        """name returns the domainName from the API response."""
        assert domain.name == SAMPLE_DOMAIN_DATA["domainName"]

    def test_organization_id(self, domain: Domain):
        """organization_id returns the organizationId from the API response."""
        assert domain.organization_id == SAMPLE_DOMAIN_DATA["organizationId"]

    def test_organization_name(self, domain: Domain):
        """organization_name returns the organizationName from the API response."""
        assert domain.organization_name == SAMPLE_DOMAIN_DATA["organizationName"]

    def test_status(self, domain: Domain):
        """status returns the status field from the API response."""
        assert domain.status == "ACTIVE"

    def test_dcv_status(self, domain: Domain):
        """dcv_status returns the dcvStatus field from the API response."""
        assert domain.dcv_status == "VERIFIED"

    def test_created_at_is_datetime(self, domain: Domain):
        """created_at returns a datetime object."""
        assert isinstance(domain.created_at, datetime)

    def test_created_at_value(self, domain: Domain):
        """created_at parses the ISO 8601 timestamp to a correct UTC datetime."""
        expected = datetime(2026, 5, 4, 21, 27, 14, tzinfo=timezone.utc)
        assert domain.created_at == expected

    def test_created_at_none_when_missing(self, mock_client: MagicMock):
        """created_at returns None when the createdAt field is absent."""
        d = Domain(mock_client, {"domainId": "abc"})
        assert d.created_at is None

    def test_name_setter(self, domain: Domain):
        """Setting name updates the local object without calling the API."""
        domain.name = "new.example.edu"
        assert domain.name == "new.example.edu"

    def test_dcv_expires_from_valid_till(self, mock_client: MagicMock):
        """dcv_expires reads validTill and returns a UTC-aware datetime."""
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DATA))
        exp = d.dcv_expires
        assert exp is not None
        assert exp == datetime(2099, 12, 31, 0, 0, 0, tzinfo=timezone.utc)

    def test_dcv_expires_none_when_missing(self, mock_client: MagicMock):
        """dcv_expires returns None when validTill is absent (e.g. PENDING domain)."""
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DATA_2))
        assert d.dcv_expires is None

    def test_verified_at_from_detail_response(self, mock_client: MagicMock):
        """verified_at reads verifiedAt from the detail-endpoint response shape."""
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DETAIL_DATA))
        vat = d.verified_at
        assert vat is not None
        assert vat == datetime(2026, 5, 29, 18, 59, 0, tzinfo=timezone.utc)

    def test_verified_at_none_when_missing(self, mock_client: MagicMock):
        """verified_at returns None when verifiedAt is absent (e.g. PENDING domain)."""
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DATA_2))
        assert d.verified_at is None

    def test_dcv_expires_soon_true_within_threshold(self, mock_client: MagicMock):
        """dcv_expires_soon returns True when expiry is within the given days."""
        # PAST_VALID_TILL is always in the past, so always within any positive threshold.
        d = Domain(mock_client, {"validTill": PAST_VALID_TILL})
        assert d.dcv_expires_soon(30) is True

    def test_dcv_expires_soon_false_far_future(self, mock_client: MagicMock):
        """dcv_expires_soon returns False when expiry is far in the future."""
        d = Domain(mock_client, {"validTill": FAR_FUTURE_VALID_TILL})
        assert d.dcv_expires_soon(30) is False

    def test_dcv_expires_soon_false_when_no_expiry(self, mock_client: MagicMock):
        """dcv_expires_soon returns False when dcv_expires is None."""
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DATA_2))
        assert d.dcv_expires_soon(30) is False

    def test_missing_fields_return_none(self, mock_client: MagicMock):
        """All properties return None when constructed with an empty dict."""
        d = Domain(mock_client, {})
        assert d.id is None
        assert d.name is None
        assert d.organization_id is None
        assert d.organization_name is None
        assert d.status is None
        assert d.dcv_status is None
        assert d.created_at is None
        assert d.dcv_expires is None
        assert d.verified_at is None


class TestDomainDunderMethods:
    """Domain.__str__ and __repr__ produce useful output."""

    def test_str_contains_name(self, domain: Domain):
        """str(domain) includes the domain name."""
        assert "umaine.edu" in str(domain)

    def test_str_contains_status(self, domain: Domain):
        """str(domain) includes the status."""
        assert "ACTIVE" in str(domain)

    def test_str_contains_dcv_status(self, domain: Domain):
        """str(domain) includes the DCV status."""
        assert "VERIFIED" in str(domain)

    def test_str_contains_organization(self, domain: Domain):
        """str(domain) includes the organization name."""
        assert "University of Maine System" in str(domain)

    def test_repr_contains_key_fields(self, domain: Domain):
        """repr(domain) starts with Domain( and shows name and status."""
        r = repr(domain)
        assert r.startswith("Domain(")
        assert "name=" in r
        assert "status=" in r

    def test_print_does_not_raise(self, domain: Domain):
        """print(domain) does not raise."""
        print(domain)


class TestDomainHelpers:
    """Domain.as_dict() and to_row() return the expected structures."""

    def test_as_dict_returns_raw_data(self, domain: Domain):
        """as_dict() returns the same dict that was passed to the constructor."""
        raw = dict(SAMPLE_DOMAIN_DATA)
        d = Domain(MagicMock(), raw)
        assert d.as_dict() is raw

    def test_to_row_keys(self, domain: Domain):
        """to_row() returns a dict with the expected column keys."""
        row = domain.to_row()
        assert set(row.keys()) == {"id", "name", "status", "dcv_status", "dcv_expires", "organization", "created_at"}

    def test_to_row_values_are_strings(self, domain: Domain):
        """to_row() returns only string values."""
        assert all(isinstance(v, str) for v in domain.to_row().values())

    def test_to_row_name(self, domain: Domain):
        """to_row()['name'] matches domain.name."""
        assert domain.to_row()["name"] == "umaine.edu"


class TestDomainNeedsDcv:
    """Domain.needs_dcv reflects whether a domain requires DCV verification."""

    def _domain(self, client: MagicMock, status: str, dcv_status: str) -> Domain:
        return Domain(client, {"domainId": "x", "status": status, "dcvStatus": dcv_status})

    def test_active_pending_needs_dcv(self, mock_client: MagicMock):
        """ACTIVE + PENDING → needs_dcv is True."""
        assert self._domain(mock_client, "ACTIVE", "PENDING").needs_dcv is True

    def test_active_verified_does_not_need_dcv(self, mock_client: MagicMock):
        """ACTIVE + VERIFIED → needs_dcv is False."""
        assert self._domain(mock_client, "ACTIVE", "VERIFIED").needs_dcv is False

    def test_inactive_pending_does_not_need_dcv(self, mock_client: MagicMock):
        """INACTIVE domain is excluded even if DCV status is PENDING."""
        assert self._domain(mock_client, "INACTIVE", "PENDING").needs_dcv is False

    def test_active_failed_needs_dcv(self, mock_client: MagicMock):
        """ACTIVE + FAILED → needs_dcv is True (any non-VERIFIED status counts)."""
        assert self._domain(mock_client, "ACTIVE", "FAILED").needs_dcv is True

    def test_sample_domain_data_does_not_need_dcv(self, domain: Domain):
        """The standard fixture (ACTIVE/VERIFIED) has needs_dcv False."""
        assert domain.needs_dcv is False

    def test_sample_domain_data_2_needs_dcv(self, mock_client: MagicMock):
        """SAMPLE_DOMAIN_DATA_2 (ACTIVE/PENDING) has needs_dcv True."""
        from tests.conftest import SAMPLE_DOMAIN_DATA_2
        d = Domain(mock_client, dict(SAMPLE_DOMAIN_DATA_2))
        assert d.needs_dcv is True

    def test_missing_status_does_not_need_dcv(self, mock_client: MagicMock):
        """Domain with no status field has needs_dcv False (None != 'ACTIVE')."""
        d = Domain(mock_client, {})
        assert d.needs_dcv is False


class TestDomainAPIMethods:
    """Domain API methods delegate to the underlying client with the correct paths."""

    def test_refresh_calls_get(self, domain: Domain, mock_client: MagicMock):
        """refresh() calls GET /domains/{id} and updates _data."""
        updated = dict(SAMPLE_DOMAIN_DATA)
        updated["status"] = "INACTIVE"
        mock_client.get.return_value = updated
        result = domain.refresh()
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}")
        assert result is domain
        assert domain.status == "INACTIVE"

    def test_deactivate_calls_post(self, domain: Domain, mock_client: MagicMock):
        """deactivate() calls POST /domains/{id}/deactivate."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        result = domain.deactivate()
        mock_client.post.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/deactivate")
        assert result is domain

    def test_get_dcv_calls_get(self, domain: Domain, mock_client: MagicMock):
        """get_dcv() calls GET /domains/{id}/dcv and returns a DcvInfo."""
        mock_client.get.return_value = dict(SAMPLE_DCV_PENDING_WITH_TOKEN)
        result = domain.get_dcv()
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv")
        assert isinstance(result, DcvInfo)
        assert result.method == "DNS-TXT"
        assert result.token == "9B2CA888948836F803ECEA19F0AAEE0B"
        assert result.host == ""

    def test_get_dcv_verified_domain_returns_method_no_token(self, domain: Domain, mock_client: MagicMock):
        """VERIFIED domain: GET /dcv returns the method but no token (challenge consumed)."""
        mock_client.get.return_value = dict(SAMPLE_DCV_VERIFIED)
        result = domain.get_dcv()
        assert result.method == "DNS-TXT"
        assert result.token == ""

    def test_get_dcv_unset_returns_empty_dcvinfo(self, domain: Domain, mock_client: MagicMock):
        """Freshly created domain with no DCV method: GET /dcv returns empty dict."""
        mock_client.get.return_value = dict(SAMPLE_DCV_UNSET)
        result = domain.get_dcv()
        assert result.method == ""
        assert result.token == ""

    def test_get_dcv_handles_fallback_dcvmethod_field(self, domain: Domain, mock_client: MagicMock):
        """get_dcv() also accepts the legacy dcvMethod field name."""
        mock_client.get.return_value = {"dcvMethod": "DNS-TXT", "txtToken": "abc123"}
        result = domain.get_dcv()
        assert result.method == "DNS-TXT"
        assert result.token == "abc123"

    def test_get_dcv_returns_empty_dcvinfo_on_bad_response(self, domain: Domain, mock_client: MagicMock):
        """get_dcv() returns a DcvInfo with empty strings when the API returns a non-dict."""
        mock_client.get.return_value = None
        result = domain.get_dcv()
        assert isinstance(result, DcvInfo)
        assert result.method == ""
        assert result.token == ""
        assert result.host == ""

    def test_reinitiate_dcv_calls_change_then_get(self, domain: Domain, mock_client: MagicMock):
        """reinitiate_dcv() calls change_dcv_method then get_dcv and returns fresh DcvInfo."""
        # First call is get_dcv() inside reinitiate_dcv to discover the current method
        mock_client.get.side_effect = [
            dict(SAMPLE_DCV_VERIFIED),           # get_dcv() → method=dns-txt, no token
            dict(SAMPLE_DCV_PENDING_WITH_TOKEN),  # get_dcv() after reset → fresh token
        ]
        mock_client.patch.return_value = dict(SAMPLE_DCV_PENDING_WITH_TOKEN)
        result = domain.reinitiate_dcv()
        assert result.method == "DNS-TXT"
        assert result.token == "9B2CA888948836F803ECEA19F0AAEE0B"
        mock_client.patch.assert_called_once_with(
            f"/api/certinext/v2/domains/{domain.id}/dcv/method",
            json={"dcvMethod": "dns-txt"},
        )

    def test_reinitiate_dcv_raises_when_method_unknown(self, domain: Domain, mock_client: MagicMock):
        """reinitiate_dcv() raises ValueError when the current DCV method cannot be determined."""
        mock_client.get.return_value = dict(SAMPLE_DCV_UNSET)
        with pytest.raises(ValueError, match="current method"):
            domain.reinitiate_dcv()

    def test_verify_calls_post(self, domain: Domain, mock_client: MagicMock):
        """verify() calls POST /domains/{id}/dcv/verify."""
        mock_client.post.return_value = {"status": "verified"}
        domain.verify()
        mock_client.post.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv/verify")

    def test_change_dcv_method_calls_patch_with_method(self, domain: Domain, mock_client: MagicMock):
        """change_dcv_method() calls PATCH /domains/{id}/dcv/method with dcvMethod in lowercase."""
        mock_client.patch.return_value = {"dcvMethod": "dns-txt"}
        domain.change_dcv_method("DNS-TXT")
        mock_client.patch.assert_called_once_with(
            f"/api/certinext/v2/domains/{domain.id}/dcv/method",
            json={"dcvMethod": "dns-txt"},
        )

    def test_last_dcv_attempt_calls_get(self, domain: Domain, mock_client: MagicMock):
        """last_dcv_attempt() calls GET /domains/{id}/dcv/attempts/last."""
        mock_client.get.return_value = {"attemptedAt": "2026-05-04T21:27:14Z"}
        domain.last_dcv_attempt()
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv/attempts/last")

    def test_dcv_attempt_history_calls_get(self, domain: Domain, mock_client: MagicMock):
        """dcv_attempt_history() calls GET /domains/{id}/dcv/attempts."""
        mock_client.get.return_value = []
        domain.dcv_attempt_history()
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv/attempts")


class TestDomainAccessorList:
    """DomainAccessor.list() returns Domain objects from the API response."""

    def test_returns_list_of_domain_objects(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() wraps each item in a Domain and returns a list."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        domains = accessor.get_list()
        assert len(domains) == 2
        assert all(isinstance(d, Domain) for d in domains)

    def test_handles_paginated_dict_response(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list handles responses where the domain list is nested inside a dict."""
        mock_client.get.return_value = {
            "total": 2,
            "domains": [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2],
        }
        domains = accessor.get_list()
        assert len(domains) == 2

    def test_passes_offset_and_limit(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() forwards offset and limit as query parameters."""
        mock_client.get.return_value = []
        accessor.get_list(offset=10, limit=5)
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params={"offset": 10, "limit": 5})

    def test_no_params_when_not_specified(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() passes params=None when offset and limit are not given."""
        mock_client.get.return_value = []
        accessor.get_list()
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params=None)

    def test_returns_empty_list_when_no_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list returns an empty list when the API returns an empty array."""
        mock_client.get.return_value = []
        assert accessor.get_list() == []

    def test_pattern_filters_by_exact_name(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=) returns only domains whose name fully matches the pattern."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_list(pattern="umaine\\.edu")
        assert len(result) == 1
        assert result[0].name == "umaine.edu"

    def test_pattern_alternation_matches_multiple(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=) with alternation returns all matching domains."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_list(pattern="umaine\\.edu|maine\\.edu")
        assert len(result) == 2

    def test_pattern_is_case_insensitive(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=) matches regardless of case."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA]
        result = accessor.get_list(pattern="UMAINE\\.EDU")
        assert len(result) == 1

    def test_pattern_no_match_returns_empty(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=) returns an empty list when no domains match."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        assert accessor.get_list(pattern="notfound\\.edu") == []

    def test_pattern_none_returns_all(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=None) returns all domains unfiltered."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        assert len(accessor.get_list(pattern=None)) == 2

    def test_pattern_wildcard_matches_subdomain(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(pattern=) supports regex wildcards for subdomain matching."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_list(pattern=r".*\.edu")
        assert len(result) == 2

    def test_search_passed_as_query_param(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(search=) forwards the value as the 'search' query parameter."""
        mock_client.get.return_value = []
        accessor.get_list(search="maine.edu")
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params={"search": "maine.edu"})

    def test_domain_status_passed_as_query_param(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(domain_status=) forwards the value as the 'domainStatus' query parameter."""
        mock_client.get.return_value = []
        accessor.get_list(domain_status="ACTIVE")
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params={"domainStatus": "ACTIVE"})

    def test_dcv_status_passed_as_query_param(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list(dcv_status=) forwards the value as the 'dcvStatus' query parameter."""
        mock_client.get.return_value = []
        accessor.get_list(dcv_status="PENDING")
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params={"dcvStatus": "PENDING"})

    def test_server_side_params_combined(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() can combine search, domain_status, and dcv_status in a single call."""
        mock_client.get.return_value = []
        accessor.get_list(search="maine", domain_status="ACTIVE", dcv_status="PENDING,REJECTED")
        mock_client.get.assert_called_once_with(
            "/api/certinext/v2/domains",
            params={"search": "maine", "domainStatus": "ACTIVE", "dcvStatus": "PENDING,REJECTED"},
        )


class TestDomainAccessorGetPendingDcv:
    """DomainAccessor.get_pending_dcv() returns only domains where needs_dcv is True."""

    def test_returns_only_pending_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() excludes already-verified domains."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_pending_dcv()
        assert len(result) == 1
        assert result[0].name == "maine.edu"

    def test_returns_empty_when_all_verified(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() returns an empty list when all domains are verified."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA]
        assert accessor.get_pending_dcv() == []

    def test_returns_all_when_all_pending(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() returns all domains when none are verified."""
        pending_data = dict(SAMPLE_DOMAIN_DATA, dcvStatus="PENDING")
        mock_client.get.return_value = [pending_data, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_pending_dcv()
        assert len(result) == 2

    def test_returns_empty_when_no_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() returns an empty list when there are no domains."""
        mock_client.get.return_value = []
        assert accessor.get_pending_dcv() == []

    def test_excludes_inactive_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() excludes INACTIVE domains even if DCV status is PENDING."""
        inactive = dict(SAMPLE_DOMAIN_DATA_2, status="INACTIVE")
        mock_client.get.return_value = [inactive]
        assert accessor.get_pending_dcv() == []

    def test_result_contains_domain_instances(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() returns Domain instances."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA_2]
        result = accessor.get_pending_dcv()
        assert all(isinstance(d, Domain) for d in result)

    def test_calls_list_with_no_server_side_filters(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get_pending_dcv() fetches all domains without server-side status filters.

        The API returns 400 when domainStatus and dcvStatus are combined, so
        filtering is done client-side via needs_dcv instead.
        """
        mock_client.get.return_value = []
        accessor.get_pending_dcv()
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params=None)


class TestDomainAccessorGet:
    """DomainAccessor.get() resolves domains by ID or by name."""

    def test_get_by_id_calls_endpoint_directly(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get with a domain ID calls the single-domain endpoint."""
        domain_id = SAMPLE_DOMAIN_DATA["domainId"]
        mock_client.get.return_value = dict(SAMPLE_DOMAIN_DATA)
        result = accessor.get(domain_id)
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain_id}")
        assert isinstance(result, Domain)

    def test_get_by_name_searches_list(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get by name calls list() and returns the matching domain."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.get("maine.edu")
        assert result.name == "maine.edu"

    def test_get_by_name_is_case_insensitive(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get by name matches regardless of case."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA]
        result = accessor.get("UMAINE.EDU")
        assert result.name == "umaine.edu"

    def test_get_by_name_raises_key_error_when_not_found(self, accessor: DomainAccessor, mock_client: MagicMock):
        """get by name raises KeyError when no domain matches."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA]
        with pytest.raises(KeyError, match="notfound.example.edu"):
            accessor.get("notfound.example.edu")


class TestDomainAccessorCreate:
    """DomainAccessor.create() posts a new domain and returns it."""

    def test_create_posts_name(self, accessor: DomainAccessor, mock_client: MagicMock):
        """create() POSTs the name to the domains endpoint."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.create("newdomain.example.edu")
        mock_client.post.assert_called_once_with(
            "/api/certinext/v2/domains",
            json={"name": "newdomain.example.edu"},
        )

    def test_create_returns_domain(self, accessor: DomainAccessor, mock_client: MagicMock):
        """create() returns a Domain instance."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        result = accessor.create("newdomain.example.edu")
        assert isinstance(result, Domain)

    def test_create_with_organization_id(self, accessor: DomainAccessor, mock_client: MagicMock):
        """create() includes organizationId in the POST body when organization_id is given."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.create("newdomain.example.edu", organization_id="org-123")
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"] == {"name": "newdomain.example.edu", "organizationId": "org-123"}

    def test_create_without_organization_id_omits_field(self, accessor: DomainAccessor, mock_client: MagicMock):
        """create() omits organizationId from the body when not given."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.create("newdomain.example.edu")
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"] == {"name": "newdomain.example.edu"}


class TestDomainAccessorDeactivate:
    """DomainAccessor.deactivate() posts to the deactivate endpoint by ID."""

    def test_deactivate_posts_to_correct_url(self, accessor: DomainAccessor, mock_client: MagicMock):
        """deactivate() POSTs to /domains/{domain_id}/deactivate."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.deactivate("dom-abc-123")
        mock_client.post.assert_called_once_with("/api/certinext/v2/domains/dom-abc-123/deactivate")

    def test_deactivate_returns_domain(self, accessor: DomainAccessor, mock_client: MagicMock):
        """deactivate() returns a Domain wrapping the API response."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        result = accessor.deactivate("dom-abc-123")
        assert isinstance(result, Domain)
