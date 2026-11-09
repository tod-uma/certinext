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

"""SSL.com issuance support: org CA validation, order coverage pre-flight, catalog CA map.

The org payloads follow the shape captured from the sandbox on 2026-11-09
(GET only). Every name, number, phone, email and ID is a placeholder; the
status, level and date values are the real ones, since they carry no PII.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from certinext.accounts import AccountAccessor, OrgCaValidation
from certinext.catalog import CatalogAccessor
from certinext.domains import Domain, DomainAccessor
from certinext.models.accounts import Organization
from certinext.models.catalog import ProductCategory
from tests.conftest import SAMPLE_DOMAIN_DATA

_CA_VALIDATIONS: dict[str, Any] = {
    "sslcom": {
        "ev": {"usable": False, "validTill": "", "status": "NOT_SUBMITTED"},
        "ov": {"usable": True, "validTill": "2027-12-05 20:08:05", "status": "VALIDATED"},
        "status": "VALIDATED",
    }
}

ORG_ROW: dict[str, Any] = {
    "isPreVettingOrg": "1",
    "organizationName": "Example Org",
    "organizationNumber": "1000001",
    "organizationLocality": "Town",
    "organizationCountryCode": "US",
    "organizationPostalCode": "00000",
    "caValidations": _CA_VALIDATIONS,
    "validationFor": "1",
    "organizationStatusId": "1",
}

SSLCOM_VALIDATION: dict[str, Any] = {
    "caName": "SSL.com",
    "lastError": "",
    "organizationNumber": "1000001",
    "readiness": {
        "current": {
            "contactTitle": "",
            "registrationNumber": "REG-PLACEHOLDER",
            "contactName": "Placeholder Person",
            "businessCategoryId": "",
            "organizationPhone": "+10000000000",
        },
        "softMissing": [],
        "evMissing": ["Business category", "Contact designation"],
        "ready": True,
        "evReady": False,
        "missing": [],
    },
    "lastSyncedAt": "2026-11-09 08:00:00",
    "enabled": True,
    "subscriberAgreementAccepted": True,
    "externalOrgId": "00000000-0000-0000-0000-000000000000",
    "defaultLevels": ["OV"],
    "contact": {
        "companyNumber": "REG-PLACEHOLDER", "name": "Placeholder Person", "title": "", "email": "x@example.invalid",
    },
    "submittedAt": "2026-11-04 19:00:00",
    "ca": "sslcom",
    "validatedAt": "2026-11-04 20:08:05",
    "levels": [{"usable": True, "validTill": "2027-12-05 20:08:05", "level": "OV", "status": "VALIDATED"}],
    "status": "VALIDATED",
}


@pytest.fixture
def client() -> MagicMock:
    """A MagicMock standing in for CertiNextClient."""
    return MagicMock()


# --- org CA validation -------------------------------------------------------


class TestOrgCaValidationModel:
    """OrgCaValidation parses the captured shape and keeps PII out of fields."""

    def test_fields_and_readiness(self) -> None:
        """Status, levels, defaults and the readiness lists are exposed."""
        v = OrgCaValidation.model_validate(SSLCOM_VALIDATION)
        assert v.status == "VALIDATED"
        assert v.ca == "sslcom"
        assert v.enabled is True and v.subscriber_agreement_accepted is True
        assert v.default_levels == ["OV"]
        assert v.ready is True and v.ev_ready is False
        assert v.missing == [] and v.ev_missing == ["Business category", "Contact designation"]
        assert v.usable("ov") and not v.usable("EV")
        lvl = v.level("OV")
        assert lvl is not None and lvl.valid_till == datetime(2027, 12, 5, 20, 8, 5)

    def test_timestamps_stay_naive(self) -> None:
        """The wire carries no offset and its zone is unconfirmed, so no zone is invented."""
        v = OrgCaValidation.model_validate(SSLCOM_VALIDATION)
        assert v.validated_at is not None and v.validated_at.tzinfo is None

    def test_contact_pii_is_not_a_field(self) -> None:
        """Contact and readiness.current are reachable only through as_dict()."""
        v = OrgCaValidation.model_validate(SSLCOM_VALIDATION)
        assert "contact" not in type(v).model_fields
        assert "Placeholder Person" not in repr(v)
        assert v.as_dict()["contact"]["name"] == "Placeholder Person"

    @pytest.mark.parametrize("render", [repr, str, lambda m: str(m.model_dump()), lambda m: m.model_dump_json()])
    def test_contact_pii_not_serialized(self, render: Any) -> None:
        """No standard rendering carries contact or readiness.current values (Codex review of b63a312)."""
        out = render(OrgCaValidation.model_validate(SSLCOM_VALIDATION))
        for value in ("Placeholder Person", "x@example.invalid", "+10000000000", "REG-PLACEHOLDER"):
            assert value not in out

    def test_lenient_on_junk(self) -> None:
        """Missing blocks and junk level rows degrade instead of raising (ADR 0005)."""
        v = OrgCaValidation.model_validate({"levels": ["junk", {"level": "OV"}], "readiness": "x"})
        assert [lvl.level for lvl in v.levels] == ["OV"]
        assert v.ready is None and v.missing == []
        assert not v.usable("OV")


class TestOrganizationCaLevels:
    """Organization.ca_levels reads caValidations without an extra request when present."""

    def test_from_list_row(self, client: MagicMock) -> None:
        """The list row already carries the block, so no detail GET is made."""
        org = Organization.from_payload(ORG_ROW, client=client)
        levels = {lvl.level: lvl for lvl in org.ca_levels("ssl.com")}
        assert set(levels) == {"OV", "EV"}
        assert levels["OV"].usable and levels["OV"].status == "VALIDATED"
        assert levels["EV"].status == "NOT_SUBMITTED" and levels["EV"].valid_till is None
        client.get.assert_not_called()

    def test_fetches_detail_when_absent(self, client: MagicMock) -> None:
        """A row without the block lazy-loads the detail once."""
        row = {k: v for k, v in ORG_ROW.items() if k != "caValidations"}
        client.get.return_value = {"caValidations": _CA_VALIDATIONS}
        org = Organization.from_payload(row, client=client)
        assert len(org.ca_levels()) == 2
        client.get.assert_called_once()

    def test_unknown_ca_is_empty(self) -> None:
        """A CA the account has no block for returns no levels."""
        org = Organization.from_payload(ORG_ROW, detail_loaded=True)
        assert org.ca_levels("NEWCA") == []


class TestAccountAccessorCaValidation:
    """The accessor's org-list filters and ca-validations endpoints."""

    def test_list_organizations_filters(self, client: MagicMock) -> None:
        """Filters map to the documented query params, upper/lower-cased as the API spells them."""
        client.get.return_value = {"organizations": [ORG_ROW]}
        orgs = AccountAccessor(client).list_organizations(validated_by="sslcom", product_variant="OV", group_number="7")
        assert client.get.call_args.kwargs["params"] == {
            "validatedBy": "SSLCOM", "productVariant": "ov", "groupNumber": "7",
        }
        assert orgs[0].organization_number == "1000001"

    def test_list_organizations_no_filters(self, client: MagicMock) -> None:
        """Without filters no params are sent, as before."""
        client.get.return_value = {"organizations": []}
        AccountAccessor(client).list_organizations()
        assert client.get.call_args.kwargs["params"] is None

    def test_get_uses_lowercase_path(self, client: MagicMock) -> None:
        """The CA is sent as the lower-case path segment the API uses."""
        client.get.return_value = SSLCOM_VALIDATION
        v = AccountAccessor(client).get_ca_validation("1000001", ca="SSL.com")
        assert client.get.call_args.args[0] == "/api/certinext/v2/organizations/1000001/ca-validations/sslcom"
        assert v.status == "VALIDATED"

    def test_sync_posts(self, client: MagicMock) -> None:
        """sync is a POST to .../sync and parses the same body."""
        client.post.return_value = SSLCOM_VALIDATION
        AccountAccessor(client).sync_ca_validation("1000001")
        assert client.post.call_args.args[0].endswith("/ca-validations/sslcom/sync")

    def test_submit_requires_explicit_agreement(self, client: MagicMock) -> None:
        """Without subscriber_agreement_accepted=True nothing is sent."""
        acc = AccountAccessor(client)
        with pytest.raises(ValueError, match="subscriber_agreement_accepted=True"):
            acc.submit_ca_validation("1000001", subscriber_agreement_accepted=False)
        with pytest.raises(ValueError):
            acc.submit_ca_validation("1000001", subscriber_agreement_accepted="yes")  # type: ignore[arg-type]
        client.post.assert_not_called()

    def test_submit_body(self, client: MagicMock) -> None:
        """Levels are upper-cased; only the optional fields given are sent."""
        client.post.return_value = SSLCOM_VALIDATION
        AccountAccessor(client).submit_ca_validation(
            "1000001", subscriber_agreement_accepted=True, levels=["ov", "ev"], contact_title="Director",
        )
        assert client.post.call_args.kwargs["json"] == {
            "subscriberAgreementAccepted": True,
            "levels": ["OV", "EV"],
            "contactTitle": "Director",
        }

    def test_submit_default_levels(self, client: MagicMock) -> None:
        """No levels sends an empty list, which the API reads as the org's defaults."""
        client.post.return_value = SSLCOM_VALIDATION
        AccountAccessor(client).submit_ca_validation("1000001", subscriber_agreement_accepted=True)
        assert client.post.call_args.kwargs["json"]["levels"] == []


# --- coverage pre-flight -----------------------------------------------------


def _dom(name: str, ca: str | None = "SSLCOM", **over: Any) -> Domain:
    """Build a detached Domain row.

    Args:
        name: The domain name.
        ca: The wire ``validatedBy``; ``None`` omits it (emSign).
        **over: Wire fields to override.

    Returns:
        The Domain.
    """
    row: dict[str, Any] = dict(SAMPLE_DOMAIN_DATA, domainName=name, domainId=f"id-{name}-{ca}")
    if ca is not None:
        row["validatedBy"] = ca
    row.update(over)
    return Domain.from_payload(None, row)


class TestFindCovering:
    """DomainAccessor.find_covering: the closest live, verified record of the right CA."""

    def test_parent_covers_subdomain_and_wildcard(self, client: MagicMock) -> None:
        """A parent covers its subdomains and a wildcard under it; the closest wins."""
        domains = [_dom("maine.edu"), _dom("its.maine.edu")]
        acc = DomainAccessor(client)
        hit = acc.find_covering("www.its.maine.edu", "sslcom", domains)
        assert hit is not None and hit.name == "its.maine.edu"
        hit = acc.find_covering("*.maine.edu", "SSLCOM", domains)
        assert hit is not None and hit.name == "maine.edu"
        assert acc.find_covering("MAINE.EDU.", "SSLCOM", domains) is not None

    def test_label_boundary(self, client: MagicMock) -> None:
        """notmaine.edu is not under maine.edu."""
        assert DomainAccessor(client).find_covering("notmaine.edu", "SSLCOM", [_dom("maine.edu")]) is None

    @pytest.mark.parametrize(
        "row",
        [
            _dom("maine.edu", ca=None),  # emSign record does not cover for SSL.com
            _dom("maine.edu", status="INACTIVE"),
            _dom("maine.edu", dcvStatus="PENDING"),
            _dom("maine.edu", validTill=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat()),
        ],
        ids=["other-ca", "inactive", "unverified", "expired"],
    )
    def test_rejected_records(self, client: MagicMock, row: Domain) -> None:
        """Wrong CA, inactive, unverified and expired records never cover."""
        assert DomainAccessor(client).find_covering("www.maine.edu", "SSLCOM", [row]) is None

    @pytest.mark.parametrize(
        ("valid_till", "covers"),
        [("2099-12-31 00:00:00", True), ("2000-01-01 00:00:00", False)],
        ids=["future", "past"],
    )
    def test_offset_free_valid_till(self, client: MagicMock, valid_till: str, covers: bool) -> None:
        """An offset-free validTill is read as UTC instead of raising on comparison (Codex review of b63a312)."""
        row = _dom("maine.edu", validTill=valid_till)
        assert row.dcv_expires is not None and row.dcv_expires.tzinfo is not None
        assert (DomainAccessor(client).find_covering("www.maine.edu", "SSLCOM", [row]) is not None) is covers

    def test_emsign_ca(self, client: MagicMock) -> None:
        """The same rule works for emSign records (no validatedBy)."""
        assert DomainAccessor(client).find_covering("a.maine.edu", "EMSIGN", [_dom("maine.edu", ca=None)]) is not None

    def test_fetches_when_no_list(self, client: MagicMock) -> None:
        """Without a list it fetches the CA's records with the server-side filter."""
        client.get.return_value = [dict(SAMPLE_DOMAIN_DATA, domainName="maine.edu", validatedBy="SSLCOM")]
        assert DomainAccessor(client).find_covering("x.maine.edu", "sslcom") is not None
        assert client.get.call_args.kwargs["params"]["validatedBy"] == "SSLCOM"


class TestUncoveredNames:
    """DomainAccessor.uncovered_names: one fetch, input order, de-duplicated."""

    def test_reports_only_uncovered(self, client: MagicMock) -> None:
        """Covered names drop out; each uncovered name is listed once, in order."""
        client.get.return_value = [dict(SAMPLE_DOMAIN_DATA, domainName="maine.edu", validatedBy="SSLCOM")]
        names = ["www.maine.edu", "example.org", "*.maine.edu", "EXAMPLE.org", "other.net"]
        assert DomainAccessor(client).uncovered_names(names, "SSLCOM") == ["example.org", "other.net"]
        assert client.get.call_count == 1


# --- catalog CA map -----------------------------------------------------------


class TestCatalogCa:
    """Category name → CA, with no "everything else is emSign" fallback."""

    @pytest.mark.parametrize(
        ("name", "ca"),
        [
            ("SSL/TLS Certificates", "EMSIGN"),
            ("ssl/tls certificates", "EMSIGN"),
            ("SSL.com", "SSLCOM"),
            ("SSLCOM", "SSLCOM"),
            ("Private PKI Products", "UNKNOWN"),
            ("Some New CA", "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
    )
    def test_category_ca(self, name: str | None, ca: str) -> None:
        """Known names map; anything else is UNKNOWN, never emSign."""
        assert ProductCategory.model_validate({"categoryName": name}).ca == ca

    def test_ca_by_product_code(self, client: MagicMock) -> None:
        """One catalog read yields a code → CA map; a code under two CAs is UNKNOWN, not first-wins."""
        client.get.return_value = {
            "products": [
                {"categoryName": "SSL/TLS Certificates", "products": [{"productCode": "823"}, {"productCode": "955"}]},
                {"categoryName": "SSL.com", "products": [{"productCode": "1011"}, {"productCode": "823"}, {}]},
                {"categoryName": "Private PKI Products", "products": [{"productCode": "900"}]},
            ]
        }
        assert CatalogAccessor(client).ca_by_product_code() == {
            "823": "UNKNOWN", "955": "EMSIGN", "1011": "SSLCOM", "900": "UNKNOWN",
        }

    def test_repeat_within_one_ca_keeps_ca(self, client: MagicMock) -> None:
        """A code listed twice under the same CA's categories is not ambiguous."""
        client.get.return_value = {
            "products": [
                {"categoryName": "SSL.com", "products": [{"productCode": "1011"}]},
                {"categoryName": "SSLCOM", "products": [{"productCode": "1011"}]},
            ]
        }
        assert CatalogAccessor(client).ca_by_product_code() == {"1011": "SSLCOM"}
