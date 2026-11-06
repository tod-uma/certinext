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

"""Multi-CA domain support (GitLab #38): SSL.com today, more CAs planned by the vendor.

The SSL.com DCV payload below is the real sandbox response captured on
2026-11-05 for an SSL.com-validated domain, with the account URI and the
challenge values replaced by placeholders. The design rule under test:
emSign is the only CA with the rotating-token model, so everything branches
on "is emSign?" and any other CA -- including one this library has never
seen -- takes the record/options path and is refused by the emSign-only
write methods.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from structlog.testing import capture_logs

from certinext.domains import DcvInfo, Domain, DomainAccessor
from tests.conftest import SAMPLE_DOMAIN_DATA

_ACCOUNT_URI = "ssl.com; accounturi=https://api.example.invalid/api/v1/teams/TEAM-ID"
_TOKEN = "PLACEHOLDER-TOKEN"

SSLCOM_DCV: dict[str, Any] = {
    "method": "dns-persist",
    "tokenExpiry": "2026-12-05T19:13:44Z",
    "recordName": "_validation-persist.example.edu",
    "recordValue": _ACCOUNT_URI,
    "optionId": "opt-persist",
    "options": [
        {
            "optionId": "opt-txt",
            "method": "dns-txt",
            "brMethod": "3.2.2.4.7",
            "recordName": "_pki-validation.example.edu",
            "recordValue": _TOKEN,
            "coversName": "example.edu",
            "exactName": True,
            "expiresAt": "2026-12-05T19:13:44Z",
        },
        {
            "optionId": "opt-cname",
            "method": "dns-cname",
            "brMethod": "3.2.2.4.7",
            "recordName": f"_{_TOKEN}.example.edu",
            "recordValue": "dcv.ssl.com",
            "coversName": "example.edu",
            "exactName": True,
            "expiresAt": "2026-12-05T19:13:44Z",
        },
        {
            "optionId": "opt-persist",
            "method": "dns-persist",
            "brMethod": "3.2.2.4.22",
            "recordName": "_validation-persist.example.edu",
            "recordValue": _ACCOUNT_URI,
            "coversName": "example.edu",
            "exactName": True,
            "expiresAt": "2026-12-05T19:13:44Z",
        },
    ],
    "validatedBy": "SSLCOM",
    "caStatus": "VALIDATED",
}


def _domain(client: MagicMock, **overrides: Any) -> Domain:
    """Build a client-attached Domain from SAMPLE_DOMAIN_DATA plus overrides.

    Args:
        client: The mocked HTTP client to attach.
        **overrides: Wire keys to set on the payload.

    Returns:
        The Domain instance.
    """
    return Domain.from_payload(client, dict(SAMPLE_DOMAIN_DATA, **overrides))


class TestDcvInfoMultiCa:
    """DcvInfo.from_wire models non-emSign payloads without touching token/host."""

    def test_sslcom_payload_fields(self) -> None:
        """Record fields, options and CA are parsed from the real SSL.com shape."""
        info = DcvInfo.from_wire(SSLCOM_DCV)
        assert info.ca == "SSLCOM"
        assert not info.is_emsign
        assert info.method == "DNS-PERSIST"
        assert info.ca_status == "VALIDATED"
        assert info.record_name == "_validation-persist.example.edu"
        assert info.record_value == _ACCOUNT_URI
        assert info.option_id == "opt-persist"
        assert [o.method for o in info.options] == ["DNS-TXT", "DNS-CNAME", "DNS-PERSIST"]
        assert info.options[0].record_name == "_pki-validation.example.edu"
        assert info.options[0].expires_at is not None
        selected = info.selected_option
        assert selected is not None and selected.br_method == "3.2.2.4.22"

    def test_sslcom_token_and_host_stay_empty(self) -> None:
        """token/host are NOT back-filled: record_name is an FQDN, not a host prefix."""
        info = DcvInfo.from_wire(SSLCOM_DCV)
        assert info.token == ""
        assert info.host == ""

    def test_emsign_payload_unchanged(self) -> None:
        """An emSign payload (no validatedBy) keeps the token model and empty record fields."""
        info = DcvInfo.from_wire({"method": "dns-txt", "txtToken": "abc"})
        assert info.ca == "EMSIGN"
        assert info.is_emsign
        assert info.token == "abc"
        assert info.record_name == ""
        assert info.options == []
        assert info.selected_option is None

    def test_unknown_future_ca_is_not_emsign(self) -> None:
        """A CA the library has never seen is passed through and is not treated as emSign."""
        info = DcvInfo.from_wire({"method": "dns-txt", "validatedBy": "newca", "recordValue": "v"})
        assert info.ca == "NEWCA"
        assert not info.is_emsign

    def test_malformed_options_are_skipped(self) -> None:
        """Non-dict entries in options are ignored rather than raising."""
        info = DcvInfo.from_wire({"validatedBy": "SSLCOM", "options": ["junk", None, {"optionId": "x"}]})
        assert [o.option_id for o in info.options] == ["x"]


class TestDomainMultiCa:
    """Domain exposes the CA and refuses emSign-only writes for every other CA."""

    def test_ca_defaults_to_emsign_when_absent(self, mock_client: MagicMock) -> None:
        """No validatedBy on the wire means emSign."""
        d = _domain(mock_client)
        assert d.validated_by is None
        assert d.ca == "EMSIGN"
        assert d.is_emsign

    def test_ca_from_list_row(self, mock_client: MagicMock) -> None:
        """validatedBy on a list row populates validated_by / ca."""
        d = _domain(mock_client, validatedBy="SSLCOM")
        assert d.ca == "SSLCOM"
        assert not d.is_emsign
        assert d.to_row()["validated_by"] == "SSLCOM"

    @pytest.mark.parametrize("ca", ["SSLCOM", "SOME-FUTURE-CA"])
    def test_change_dcv_method_refuses_non_emsign(self, mock_client: MagicMock, ca: str) -> None:
        """change_dcv_method() fails closed for SSL.com and for CAs not yet known."""
        d = _domain(mock_client, validatedBy=ca)
        with pytest.raises(ValueError, match=f"validated by {ca}"):
            d.change_dcv_method("DNS-TXT")
        mock_client.patch.assert_not_called()

    def test_reinitiate_dcv_refuses_when_row_says_sslcom(self, mock_client: MagicMock) -> None:
        """reinitiate_dcv() refuses based on the Domain row's CA."""
        d = _domain(mock_client, validatedBy="SSLCOM")
        mock_client.get.return_value = dict(SSLCOM_DCV)
        with pytest.raises(ValueError, match="reinitiate_dcv"):
            d.reinitiate_dcv()
        mock_client.patch.assert_not_called()

    def test_reinitiate_dcv_refuses_when_only_dcv_payload_says_sslcom(self, mock_client: MagicMock) -> None:
        """A Domain row lacking validatedBy is still caught by the fresh DCV payload."""
        d = _domain(mock_client)
        mock_client.get.return_value = dict(SSLCOM_DCV)
        with pytest.raises(ValueError, match="validated by SSLCOM"):
            d.reinitiate_dcv()
        mock_client.patch.assert_not_called()

    def test_change_dcv_method_refuses_when_only_dcv_payload_says_sslcom(self, mock_client: MagicMock) -> None:
        """A stale/incomplete row (no validatedBy) is caught by the fresh DCV read before the PATCH."""
        d = _domain(mock_client)
        mock_client.get.return_value = dict(SSLCOM_DCV)
        with pytest.raises(ValueError, match="validated by SSLCOM"):
            d.change_dcv_method("DNS-TXT")
        mock_client.patch.assert_not_called()

    def test_change_dcv_method_emsign_reads_then_patches(self, mock_client: MagicMock) -> None:
        """For emSign the guard reads /dcv once, then sends the PATCH."""
        d = _domain(mock_client)
        mock_client.get.return_value = {"method": "dns-txt", "txtToken": "abc"}
        d.change_dcv_method("HTTP-URL")
        mock_client.get.assert_called_once_with(f"/api/certinext/v2/domains/{d.id}/dcv")
        mock_client.patch.assert_called_once_with(
            f"/api/certinext/v2/domains/{d.id}/dcv/method", json={"dcvMethod": "http-url"}
        )

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_validated_by_is_unknown_not_emsign(self, mock_client: MagicMock, blank: str) -> None:
        """A present-but-blank validatedBy is malformed: not emSign, and writes fail closed."""
        d = _domain(mock_client, validatedBy=blank)
        assert d.ca == "UNKNOWN"
        assert not d.is_emsign
        info = DcvInfo.from_wire({"method": "dns-txt", "validatedBy": blank})
        assert info.ca == "UNKNOWN"
        assert not info.is_emsign
        with pytest.raises(ValueError, match="validated by UNKNOWN"):
            d.change_dcv_method("DNS-TXT")
        mock_client.patch.assert_not_called()

    def test_null_validated_by_means_emsign(self, mock_client: MagicMock) -> None:
        """JSON null is treated like an absent key (emSign), so emSign writes keep working."""
        d = _domain(mock_client, validatedBy=None)
        assert d.is_emsign
        assert DcvInfo.from_wire({"method": "dns-txt", "validatedBy": None}).is_emsign

    def test_get_dcv_no_unknown_method_warning_for_sslcom(self, mock_client: MagicMock) -> None:
        """dns-persist on an SSL.com domain is modelled, so get_dcv() does not warn."""
        d = _domain(mock_client, validatedBy="SSLCOM")
        mock_client.get.return_value = dict(SSLCOM_DCV)
        with capture_logs() as logs:
            d.get_dcv()
        assert not [e for e in logs if e["log_level"] == "warning"]

    def test_verify_with_option_id_sends_body(self, mock_client: MagicMock, domain: Domain) -> None:
        """verify(option_id=...) posts the optionId body."""
        mock_client.post.return_value = {"status": "VERIFIED"}
        domain.verify(option_id="opt-txt")
        mock_client.post.assert_called_once_with(
            f"/api/certinext/v2/domains/{domain.id}/dcv/verify", json={"optionId": "opt-txt"}
        )


class TestAccessorMultiCa:
    """DomainAccessor: CA filter, CA on create, and one-name-per-CA lookups."""

    def _rows(self) -> list[dict[str, Any]]:
        """Return list rows holding maine.edu once per CA plus an unrelated domain.

        Returns:
            Raw list rows.
        """
        emsign = dict(SAMPLE_DOMAIN_DATA, domainId="id-em", domainName="maine.edu")
        sslcom = dict(emsign, domainId="id-ssl", validatedBy="SSLCOM")
        other = dict(SAMPLE_DOMAIN_DATA, domainId="id-x", domainName="umaine.edu")
        return [emsign, sslcom, other]

    def test_get_list_validated_by_sends_param_and_filters_client_side(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ) -> None:
        """validated_by is sent upper-cased, and rows of other CAs are dropped even if the server ignores it."""
        mock_client.get.return_value = self._rows()  # server ignored the filter
        result = accessor.get_list(offset=0, limit=50, validated_by="sslcom")
        assert mock_client.get.call_args.kwargs["params"]["validatedBy"] == "SSLCOM"
        assert [d.id for d in result] == ["id-ssl"]

    def test_get_list_validated_by_emsign_matches_absent_key(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ) -> None:
        """EMSIGN selects rows without validatedBy."""
        mock_client.get.return_value = self._rows()
        result = accessor.get_list(offset=0, limit=50, validated_by="EMSIGN")
        assert sorted(d.id or "" for d in result) == ["id-em", "id-x"]

    def test_get_by_name_prefers_emsign_and_warns(self, accessor: DomainAccessor, mock_client: MagicMock) -> None:
        """Two records for one name without validated_by: emSign is returned with a warning."""
        mock_client.get.return_value = self._rows()
        with capture_logs() as logs:
            d = accessor.get("maine.edu")
        assert d.id == "id-em"
        warning = next(e for e in logs if e["log_level"] == "warning")
        assert warning["cas"] == ["EMSIGN", "SSLCOM"]

    def test_get_by_name_with_validated_by(self, accessor: DomainAccessor, mock_client: MagicMock) -> None:
        """validated_by picks the record of that CA."""
        mock_client.get.return_value = self._rows()
        assert accessor.get("maine.edu", validated_by="SSLCOM").id == "id-ssl"

    def test_get_by_name_ambiguous_without_emsign_raises(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ) -> None:
        """Several non-emSign records for one name: refuse to guess."""
        rows = [
            dict(SAMPLE_DOMAIN_DATA, domainId="a", domainName="maine.edu", validatedBy="SSLCOM"),
            dict(SAMPLE_DOMAIN_DATA, domainId="b", domainName="maine.edu", validatedBy="NEWCA"),
        ]
        mock_client.get.return_value = rows
        with pytest.raises(ValueError, match="validated_by="):
            accessor.get("maine.edu")

    def test_get_by_name_missing_for_ca_raises_keyerror(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ) -> None:
        """No record of the requested CA: KeyError naming the CA."""
        mock_client.get.return_value = [self._rows()[0]]
        with pytest.raises(KeyError, match="SSLCOM"):
            accessor.get("maine.edu", validated_by="SSLCOM")

    def test_get_list_keeps_id_less_rows_of_different_cas(
        self, accessor: DomainAccessor, mock_client: MagicMock
    ) -> None:
        """Rows missing domainId are de-duplicated by CA + name, not by name alone."""
        rows = [{k: v for k, v in r.items() if k != "domainId"} for r in self._rows()]
        mock_client.get.return_value = rows
        result = accessor.get_list()
        assert sorted((d.name or "", d.ca) for d in result) == [
            ("maine.edu", "EMSIGN"),
            ("maine.edu", "SSLCOM"),
            ("umaine.edu", "EMSIGN"),
        ]

    def test_boundary_refetch_full_page_warns(
        self, accessor: DomainAccessor, mock_client: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exact-match re-fetch that fills a page is flagged as possibly incomplete."""
        monkeypatch.setattr("certinext.domains._LIST_PAGE_SIZE", 2)
        emsign, sslcom, _ = self._rows()
        mock_client.get.side_effect = [[emsign, sslcom], [], [emsign, sslcom]]
        with capture_logs() as logs:
            result = accessor.get_list()
        assert sorted(d.id or "" for d in result) == ["id-em", "id-ssl"]
        assert any("exact-match boundary re-fetch" in e["event"] for e in logs)

    def test_create_sends_ca(self, accessor: DomainAccessor, mock_client: MagicMock) -> None:
        """create(ca=...) sends the upper-cased CA in the body."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA, validatedBy="SSLCOM")
        d = accessor.create("maine.edu", dcv_method="dns-persist", ca="sslcom")
        assert mock_client.post.call_args.kwargs["json"]["ca"] == "SSLCOM"
        assert d.ca == "SSLCOM"

    def test_create_omits_ca_by_default(self, accessor: DomainAccessor, mock_client: MagicMock) -> None:
        """Without ca the body has no ca key (the account decides)."""
        mock_client.post.return_value = dict(SAMPLE_DOMAIN_DATA)
        accessor.create("maine.edu")
        assert "ca" not in mock_client.post.call_args.kwargs["json"]
