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

"""Shared fixtures for the certinext test suite."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from certinext.client import CertiNextClient
from certinext.domains import Domain, DomainAccessor

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


# Two sentinel dates used across fixtures:
#   FAR_FUTURE_VALID_TILL  — reliably "not expiring soon" for centuries
#   PAST_VALID_TILL        — reliably already-expired for any future test run
FAR_FUTURE_VALID_TILL = "2099-12-31T00:00:00Z"
PAST_VALID_TILL = "2020-01-01T00:00:00Z"

# List-endpoint response shape. validTill is present for VERIFIED domains;
# absent for PENDING/EXPIRED. organizationId is present in the list response
# but omitted from the detail response (see SAMPLE_DOMAIN_DETAIL_DATA below).
SAMPLE_DOMAIN_DATA = {
    "domainId": "vuxwZgEXWWFXQQWC-3zElI5VlhinKlE8xyYJqfeYNtFE0SAP",
    "domainName": "umaine.edu",
    "organizationId": "FIEUvE_VbBgefXTlqmcE5nr8rN0VxcTA7k8GrMA11hbPIZG-",
    "organizationName": "University of Maine System",
    "status": "ACTIVE",
    "dcvStatus": "VERIFIED",
    "validTill": FAR_FUTURE_VALID_TILL,
    "createdAt": "2026-05-04T21:27:14Z",
}

# Detail-endpoint response shape (after refresh()). Differences from the list
# response: organizationId is absent; dcv sub-object and verifiedAt are present.
SAMPLE_DOMAIN_DETAIL_DATA = {
    "domainId": "vuxwZgEXWWFXQQWC-3zElI5VlhinKlE8xyYJqfeYNtFE0SAP",
    "domainName": "umaine.edu",
    "organizationName": "University of Maine System",
    "status": "ACTIVE",
    "dcvStatus": "VERIFIED",
    "dcv": {"method": "dns-txt"},
    "validTill": FAR_FUTURE_VALID_TILL,
    "createdAt": "2026-05-04T21:27:14Z",
    "verifiedAt": "2026-05-29T18:59:00Z",
}

SAMPLE_DOMAIN_DATA_2 = {
    "domainId": "oj2GiHLqpmRZglKoImTK8qmpQAsV5ixqRi4-jwvLprmD6xoK",
    "domainName": "maine.edu",
    "organizationId": "FIEUvE_VbBgefXTlqmcE5nr8rN0VxcTA7k8GrMA11hbPIZG-",
    "organizationName": "University of Maine System",
    "status": "ACTIVE",
    "dcvStatus": "PENDING",
    "createdAt": "2026-05-04T21:27:14Z",
}

# Real GET /domains/{id}/dcv response shapes observed from the sandbox API.
# VERIFIED domain: returns the method but no token (challenge has been consumed).
SAMPLE_DCV_VERIFIED = {"method": "dns-txt"}
# PENDING domain with an active challenge: method + txtToken (hex token value).
SAMPLE_DCV_PENDING_WITH_TOKEN = {"method": "dns-txt", "txtToken": "9B2CA888948836F803ECEA19F0AAEE0B"}
# PENDING domain with no method set yet (freshly created, never had change_dcv_method called).
SAMPLE_DCV_UNSET = {}

TOKEN_RESPONSE = {
    "access_token": "test-bearer-token-abc123",
    "token_type": "Bearer",
    "expires_in": 3600,
}


@pytest.fixture
def mock_client() -> MagicMock:
    """A MagicMock standing in for CertiNextClient."""
    return MagicMock(spec=CertiNextClient)


@pytest.fixture
def domain(mock_client: MagicMock) -> Domain:
    """A Domain instance backed by mock_client and SAMPLE_DOMAIN_DATA."""
    return Domain(mock_client, dict(SAMPLE_DOMAIN_DATA))


@pytest.fixture
def accessor(mock_client: MagicMock) -> DomainAccessor:
    """A DomainAccessor instance backed by mock_client."""
    return DomainAccessor(mock_client)


@pytest.fixture
def bad_domain_data() -> list[dict]:
    """List of malformed/incomplete domain dicts loaded from the bad-data fixture file."""
    return json.loads((_FIXTURES_DIR / "bad_domain_data.json").read_text())


@pytest.fixture
def domains_list_data() -> list[dict]:
    """Raw list of 43 anonymized domain dicts loaded from the fixture file."""
    return json.loads((_FIXTURES_DIR / "domains_list.json").read_text())


@pytest.fixture
def domains_list(mock_client: MagicMock, domains_list_data: list[dict]) -> list[Domain]:
    """43 Domain objects built from the anonymized fixture data."""
    return [Domain(mock_client, item) for item in domains_list_data]
