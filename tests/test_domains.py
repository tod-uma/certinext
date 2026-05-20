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
from tests.conftest import SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2


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
        """repr(domain) starts with Domain( and includes id, name, status, dcv_status."""
        r = repr(domain)
        assert r.startswith("Domain(")
        assert "id=" in r
        assert "name=" in r
        assert "status=" in r
        assert "dcv_status=" in r

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
        assert set(row.keys()) == {"id", "name", "status", "dcv_status", "organization", "created_at"}

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
        mock_client.get.return_value = {"dcvMethod": "DNS-TXT", "txtToken": "abc123"}
        result = domain.get_dcv()
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{domain.id}/dcv")
        assert isinstance(result, DcvInfo)
        assert result.method == "DNS-TXT"
        assert result.token == "abc123"
        assert result.host == ""

    def test_get_dcv_normalises_alternate_field_names(self, domain: Domain, mock_client: MagicMock):
        """get_dcv() handles the 'method'/'token'/'host' field name variants."""
        mock_client.get.return_value = {"method": "dns-txt", "token": "xyz", "host": ""}
        result = domain.get_dcv()
        assert result.method == "DNS-TXT"
        assert result.token == "xyz"
        assert result.host == ""

    def test_get_dcv_returns_empty_dcvinfo_on_bad_response(self, domain: Domain, mock_client: MagicMock):
        """get_dcv() returns a DcvInfo with empty strings when the API returns a non-dict."""
        mock_client.get.return_value = None
        result = domain.get_dcv()
        assert isinstance(result, DcvInfo)
        assert result.method == ""
        assert result.token == ""
        assert result.host == ""

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
        domains = accessor.list()
        assert len(domains) == 2
        assert all(isinstance(d, Domain) for d in domains)

    def test_handles_paginated_dict_response(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list handles responses where the domain list is nested inside a dict."""
        mock_client.get.return_value = {
            "total": 2,
            "domains": [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2],
        }
        domains = accessor.list()
        assert len(domains) == 2

    def test_passes_offset_and_limit(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() forwards offset and limit as query parameters."""
        mock_client.get.return_value = []
        accessor.list(offset=10, limit=5)
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params={"offset": 10, "limit": 5})

    def test_no_params_when_not_specified(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list() passes params=None when offset and limit are not given."""
        mock_client.get.return_value = []
        accessor.list()
        mock_client.get.assert_called_once_with("/api/certinext/v2/domains", params=None)

    def test_returns_empty_list_when_no_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list returns an empty list when the API returns an empty array."""
        mock_client.get.return_value = []
        assert accessor.list() == []


class TestDomainAccessorListPendingDcv:
    """DomainAccessor.list_pending_dcv() returns only domains where needs_dcv is True."""

    def test_returns_only_pending_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() excludes already-verified domains."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA, SAMPLE_DOMAIN_DATA_2]
        result = accessor.list_pending_dcv()
        assert len(result) == 1
        assert result[0].name == "maine.edu"

    def test_returns_empty_when_all_verified(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() returns an empty list when all domains are verified."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA]
        assert accessor.list_pending_dcv() == []

    def test_returns_all_when_all_pending(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() returns all domains when none are verified."""
        pending_data = dict(SAMPLE_DOMAIN_DATA, dcvStatus="PENDING")
        mock_client.get.return_value = [pending_data, SAMPLE_DOMAIN_DATA_2]
        result = accessor.list_pending_dcv()
        assert len(result) == 2

    def test_returns_empty_when_no_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() returns an empty list when there are no domains."""
        mock_client.get.return_value = []
        assert accessor.list_pending_dcv() == []

    def test_excludes_inactive_domains(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() excludes INACTIVE domains even if DCV status is PENDING."""
        inactive = dict(SAMPLE_DOMAIN_DATA_2, status="INACTIVE")
        mock_client.get.return_value = [inactive]
        assert accessor.list_pending_dcv() == []

    def test_result_contains_domain_instances(self, accessor: DomainAccessor, mock_client: MagicMock):
        """list_pending_dcv() returns Domain instances."""
        mock_client.get.return_value = [SAMPLE_DOMAIN_DATA_2]
        result = accessor.list_pending_dcv()
        assert all(isinstance(d, Domain) for d in result)


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

    def test_create_passes_extra_fields(self, accessor: DomainAccessor, mock_client: MagicMock):
        """create() includes extra keyword arguments in the POST body."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.create("newdomain.example.edu", organizationId="org-123")
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["organizationId"] == "org-123"
