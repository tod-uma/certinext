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

"""Tests that exercise the full 43-domain anonymized fixture list."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from certinext.domains import Domain, DomainAccessor


class TestDomainListFixture:
    """Structural and content tests over the full anonymized domain list."""

    def test_fixture_contains_43_domains(self, domains_list: list[Domain]):
        """The fixture list contains exactly 43 domains."""
        assert len(domains_list) == 43

    def test_all_entries_are_domain_instances(self, domains_list: list[Domain]):
        """Every item in the fixture list is a Domain object."""
        assert all(isinstance(d, Domain) for d in domains_list)

    def test_all_domains_have_ids(self, domains_list: list[Domain]):
        """Every domain has a non-empty id."""
        assert all(d.id for d in domains_list)

    def test_all_domain_ids_are_unique(self, domains_list: list[Domain]):
        """No two domains share the same id."""
        ids = [d.id for d in domains_list]
        assert len(ids) == len(set(ids))

    def test_all_domains_have_names(self, domains_list: list[Domain]):
        """Every domain has a non-empty name."""
        assert all(d.name for d in domains_list)

    def test_all_domain_names_are_unique(self, domains_list: list[Domain]):
        """No two domains share the same name."""
        names = [d.name for d in domains_list]
        assert len(names) == len(set(names))

    def test_all_domains_are_active(self, domains_list: list[Domain]):
        """Every domain in the fixture has status ACTIVE."""
        assert all(d.status == "ACTIVE" for d in domains_list)

    def test_exactly_one_verified_domain(self, domains_list: list[Domain]):
        """Exactly one domain has dcvStatus VERIFIED."""
        verified = [d for d in domains_list if d.dcv_status == "VERIFIED"]
        assert len(verified) == 1

    def test_verified_domain_is_example_edu(self, domains_list: list[Domain]):
        """The VERIFIED domain is example.edu."""
        verified = next(d for d in domains_list if d.dcv_status == "VERIFIED")
        assert verified.name == "example.edu"

    def test_remaining_domains_are_pending(self, domains_list: list[Domain]):
        """All domains except the verified one have dcvStatus PENDING."""
        pending = [d for d in domains_list if d.dcv_status == "PENDING"]
        assert len(pending) == 42

    def test_all_domains_have_created_at(self, domains_list: list[Domain]):
        """Every domain has a non-None created_at datetime."""
        assert all(d.created_at is not None for d in domains_list)

    def test_all_created_at_are_utc(self, domains_list: list[Domain]):
        """Every created_at datetime is timezone-aware UTC."""
        for d in domains_list:
            assert d.created_at is not None
            assert d.created_at.tzinfo is not None
            assert d.created_at.utcoffset().total_seconds() == 0  # type: ignore[union-attr]

    def test_all_created_at_same_date(self, domains_list: list[Domain]):
        """All fixture domains share the same creation timestamp."""
        expected = datetime(2026, 5, 4, 21, 27, 14, tzinfo=timezone.utc)
        assert all(d.created_at == expected for d in domains_list)

    def test_all_domains_belong_to_same_org(self, domains_list: list[Domain]):
        """All domains belong to Example University System."""
        assert all(d.organization_name == "Example University System" for d in domains_list)

    def test_all_domains_share_org_id(self, domains_list: list[Domain]):
        """All domains share the same organization_id."""
        org_ids = {d.organization_id for d in domains_list}
        assert len(org_ids) == 1

    def test_to_row_for_every_domain(self, domains_list: list[Domain]):
        """to_row() succeeds for every domain and returns string values."""
        for d in domains_list:
            row = d.to_row()
            assert all(isinstance(v, str) for v in row.values())

    def test_str_for_every_domain(self, domains_list: list[Domain]):
        """str() succeeds for every domain and includes the domain name."""
        for d in domains_list:
            text = str(d)
            assert d.name is not None and d.name in text

    def test_repr_for_every_domain(self, domains_list: list[Domain]):
        """repr() succeeds for every domain."""
        for d in domains_list:
            assert repr(d).startswith("Domain(")


class TestDomainAccessorWithFullList:
    """Tests for DomainAccessor using the full fixture list as the API response."""

    def test_list_returns_all_43_domains(
        self, accessor: DomainAccessor, mock_client: MagicMock, domains_list_data: list[dict]
    ):
        """DomainAccessor.get_list() returns all 43 Domain objects from a full list response."""
        mock_client.get.return_value = domains_list_data
        result = accessor.get_list()
        assert len(result) == 43
        assert all(isinstance(d, Domain) for d in result)

    def test_get_by_name_finds_verified_domain(
        self, accessor: DomainAccessor, mock_client: MagicMock, domains_list_data: list[dict]
    ):
        """get('example.edu') finds the single VERIFIED domain in the full list."""
        mock_client.get.return_value = domains_list_data
        result = accessor.get("example.edu")
        assert result.name == "example.edu"
        assert result.dcv_status == "VERIFIED"

    def test_get_by_name_finds_subdomain(
        self, accessor: DomainAccessor, mock_client: MagicMock, domains_list_data: list[dict]
    ):
        """get() correctly resolves a subdomain from the full list."""
        mock_client.get.return_value = domains_list_data
        result = accessor.get("library.example.edu")
        assert result.name == "library.example.edu"

    def test_get_raises_for_unknown_name(
        self, accessor: DomainAccessor, mock_client: MagicMock, domains_list_data: list[dict]
    ):
        """get() raises KeyError when the name is not present in the full list."""
        mock_client.get.return_value = domains_list_data
        with pytest.raises(KeyError):
            accessor.get("notareal.example.edu")
