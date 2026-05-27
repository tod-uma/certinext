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

"""Tests for certinext.accounts: AccountInfo, Group, Organization, AccountAccessor."""

from unittest.mock import MagicMock

from certinext.accounts import AccountAccessor, AccountInfo, Group, Organization
from certinext.client import CertiNextClient

_ME_URL = "/api/certinext/v2/auth/me"
_GROUPS_URL = "/api/certinext/v2/groups"
_ORGS_URL = "/api/certinext/v2/organizations"


def _make_client() -> tuple[CertiNextClient, MagicMock]:
    """Return a CertiNextClient with auth and HTTP session mocked out."""
    client = CertiNextClient(
        base_url="https://us-api.certinext.io",
        token_url="https://us-api.certinext.io/oauth/token",
        client_id="test",
        client_secret="secret",
    )
    client._auth = MagicMock()
    client._auth.get_token.return_value = "test-token"
    mock_session = MagicMock()
    client._session = mock_session  # type: ignore[assignment]
    return client, mock_session


def _ok_response(payload: object) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    resp.content = b"{}"
    return resp


# ---------------------------------------------------------------------------
# AccountInfo
# ---------------------------------------------------------------------------

class TestAccountInfo:
    """AccountInfo exposes expected properties."""

    def test_account_number(self):
        """account_number reads accountNumber from the raw data dict."""
        info = AccountInfo({"accountNumber": "12345"})
        assert info.account_number == "12345"

    def test_account_name(self):
        """account_name reads accountName from the raw data dict."""
        info = AccountInfo({"accountName": "University of Maine System"})
        assert info.account_name == "University of Maine System"

    def test_account_type(self):
        """account_type reads accountType from the raw data dict."""
        info = AccountInfo({"accountType": "ENTERPRISE"})
        assert info.account_type == "ENTERPRISE"

    def test_missing_fields_return_none(self):
        """Missing fields return None, not KeyError."""
        info = AccountInfo({})
        assert info.account_number is None
        assert info.account_name is None
        assert info.account_type is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        data = {"accountNumber": "X", "extra": "field"}
        info = AccountInfo(data)
        assert info.as_dict() is data

    def test_repr_contains_key_fields(self):
        """repr() includes account_number and account_name."""
        info = AccountInfo({"accountNumber": "99", "accountName": "Test Org"})
        r = repr(info)
        assert "99" in r
        assert "Test Org" in r


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------

class TestGroup:
    """Group exposes expected properties."""

    def test_group_number(self):
        """group_number reads groupNumber from the raw data dict."""
        group = Group({"groupNumber": "grp-001", "groupName": "IT"})
        assert group.group_number == "grp-001"

    def test_group_name(self):
        """group_name reads groupName from the raw data dict."""
        group = Group({"groupNumber": "grp-001", "groupName": "IT"})
        assert group.group_name == "IT"

    def test_missing_fields_return_none(self):
        """Missing fields return None."""
        group = Group({})
        assert group.group_number is None
        assert group.group_name is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        data = {"groupNumber": "g1"}
        group = Group(data)
        assert group.as_dict() is data

    def test_repr_contains_group_number(self):
        """repr() includes the group number."""
        group = Group({"groupNumber": "grp-42"})
        assert "grp-42" in repr(group)


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------

class TestOrganization:
    """Organization exposes expected properties."""

    _ORG_DATA = {
        "organizationNumber": "ORG-001",
        "organizationName": "University of Maine System",
        "organizationLocality": "Bangor",
        "organizationCountryCode": "US",
        "organizationPostalCode": "04401",
        "organizationStatusId": "1",
        "isPreVettingOrg": "1",
    }

    def test_organization_number(self):
        """organization_number reads organizationNumber."""
        org = Organization(self._ORG_DATA)
        assert org.organization_number == "ORG-001"

    def test_organization_name(self):
        """organization_name reads organizationName."""
        org = Organization(self._ORG_DATA)
        assert org.organization_name == "University of Maine System"

    def test_locality(self):
        """locality reads organizationLocality."""
        org = Organization(self._ORG_DATA)
        assert org.locality == "Bangor"

    def test_country_code(self):
        """country_code reads organizationCountryCode."""
        org = Organization(self._ORG_DATA)
        assert org.country_code == "US"

    def test_postal_code(self):
        """postal_code reads organizationPostalCode."""
        org = Organization(self._ORG_DATA)
        assert org.postal_code == "04401"

    def test_status_id(self):
        """status_id reads organizationStatusId."""
        org = Organization(self._ORG_DATA)
        assert org.status_id == "1"

    def test_is_pre_vetting_org(self):
        """is_pre_vetting_org reads isPreVettingOrg."""
        org = Organization(self._ORG_DATA)
        assert org.is_pre_vetting_org == "1"

    def test_missing_fields_return_none(self):
        """Missing fields return None."""
        org = Organization({})
        assert org.organization_number is None
        assert org.organization_name is None
        assert org.locality is None
        assert org.country_code is None
        assert org.postal_code is None
        assert org.status_id is None
        assert org.is_pre_vetting_org is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the raw dict passed at construction."""
        org = Organization(self._ORG_DATA)
        assert org.as_dict() is self._ORG_DATA

    def test_repr_contains_number_and_name(self):
        """repr() includes organization_number and organization_name."""
        org = Organization(self._ORG_DATA)
        r = repr(org)
        assert "ORG-001" in r
        assert "University of Maine System" in r


# ---------------------------------------------------------------------------
# AccountAccessor.me
# ---------------------------------------------------------------------------

class TestAccountAccessorMe:
    """AccountAccessor.me() calls the auth/me endpoint."""

    def test_calls_me_endpoint(self):
        """me() GETs /api/certinext/v2/auth/me."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(
            {"accountNumber": "42", "accountName": "Test", "accountType": "ENTERPRISE"}
        )
        accessor = AccountAccessor(client)
        accessor.me()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(_ME_URL)

    def test_returns_account_info(self):
        """me() returns an AccountInfo instance."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(
            {"accountNumber": "42", "accountName": "Test"}
        )
        accessor = AccountAccessor(client)
        result = accessor.me()
        assert isinstance(result, AccountInfo)
        assert result.account_number == "42"

    def test_handles_empty_response(self):
        """me() returns AccountInfo with None properties when response is empty."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({})
        accessor = AccountAccessor(client)
        result = accessor.me()
        assert result.account_number is None


# ---------------------------------------------------------------------------
# AccountAccessor.list_groups
# ---------------------------------------------------------------------------

class TestAccountAccessorListGroups:
    """AccountAccessor.list_groups() returns Group objects."""

    def test_calls_groups_endpoint(self):
        """list_groups() GETs /api/certinext/v2/groups."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"groups": []})
        accessor = AccountAccessor(client)
        accessor.list_groups()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(_GROUPS_URL)

    def test_returns_groups_from_wrapped_response(self):
        """list_groups() unwraps the 'groups' array from a dict response."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({
            "groups": [
                {"groupNumber": "g1", "groupName": "IT"},
                {"groupNumber": "g2", "groupName": "Finance"},
            ]
        })
        accessor = AccountAccessor(client)
        groups = accessor.list_groups()
        assert len(groups) == 2
        assert all(isinstance(g, Group) for g in groups)
        assert groups[0].group_number == "g1"
        assert groups[1].group_name == "Finance"

    def test_returns_groups_from_list_response(self):
        """list_groups() handles a bare list response."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(
            [{"groupNumber": "g1", "groupName": "IT"}]
        )
        accessor = AccountAccessor(client)
        groups = accessor.list_groups()
        assert len(groups) == 1
        assert groups[0].group_number == "g1"

    def test_returns_empty_list_when_no_groups(self):
        """list_groups() returns [] when the groups array is empty."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"groups": []})
        accessor = AccountAccessor(client)
        assert accessor.list_groups() == []


# ---------------------------------------------------------------------------
# AccountAccessor.list_organizations
# ---------------------------------------------------------------------------

class TestAccountAccessorListOrganizations:
    """AccountAccessor.list_organizations() returns Organization objects."""

    _ORG_PAYLOAD = {
        "organizations": [
            {
                "organizationNumber": "ORG-001",
                "organizationName": "Univ of Maine",
                "organizationLocality": "Orono",
                "organizationCountryCode": "US",
                "organizationPostalCode": "04469",
                "organizationStatusId": "1",
                "isPreVettingOrg": "1",
            }
        ]
    }

    def test_calls_organizations_endpoint(self):
        """list_organizations() GETs /api/certinext/v2/organizations."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(self._ORG_PAYLOAD)
        accessor = AccountAccessor(client)
        accessor.list_organizations()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(_ORGS_URL)

    def test_returns_organizations_from_wrapped_response(self):
        """list_organizations() unwraps the 'organizations' array."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(self._ORG_PAYLOAD)
        accessor = AccountAccessor(client)
        orgs = accessor.list_organizations()
        assert len(orgs) == 1
        assert isinstance(orgs[0], Organization)
        assert orgs[0].organization_number == "ORG-001"

    def test_returns_empty_list_when_no_orgs(self):
        """list_organizations() returns [] when organizations array is empty."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"organizations": []})
        accessor = AccountAccessor(client)
        assert accessor.list_organizations() == []

    def test_returns_organizations_from_list_response(self):
        """list_organizations() handles a bare list response."""
        client, mock_session = _make_client()
        orgs_data = self._ORG_PAYLOAD["organizations"]
        mock_session.get.return_value = _ok_response(orgs_data)
        accessor = AccountAccessor(client)
        orgs = accessor.list_organizations()
        assert len(orgs) == 1


# ---------------------------------------------------------------------------
# AccountAccessor.get_organization
# ---------------------------------------------------------------------------

class TestAccountAccessorGetOrganization:
    """AccountAccessor.get_organization() fetches a single organization by ID."""

    def test_calls_organization_by_id_endpoint(self):
        """get_organization() GETs /organizations/{id}."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"organizationNumber": "ORG-001"})
        accessor = AccountAccessor(client)
        accessor.get_organization("ORG-001")
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_ORGS_URL}/ORG-001")

    def test_returns_organization_instance(self):
        """get_organization() returns an Organization."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"organizationNumber": "ORG-001"})
        accessor = AccountAccessor(client)
        org = accessor.get_organization("ORG-001")
        assert isinstance(org, Organization)
        assert org.organization_number == "ORG-001"
