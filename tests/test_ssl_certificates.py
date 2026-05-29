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

"""Tests for certinext.ssl_certificates: DcvChallenge, CertificateDownload, SslOrder, SslAccessor."""

from unittest.mock import MagicMock

import pytest

from certinext.client import CertiNextClient
from certinext.ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    SslAccessor,
    SslOrder,
)

_SSL_BASE = "/api/certinext/v2/ssl-certificates"


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


def _ok_bytes_response(content: bytes) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.content = content
    return resp


_ORDER_DATA = {
    "orderId": "ORDER-001",
    "requestId": "REQ-001",
    "status": "pending-dcv",
    "productVariant": "dv",
    "domain": "example.com",
    "additionalDomains": ["www.example.com"],
    "createdAt": "2026-05-27T12:00:00Z",
}


# ---------------------------------------------------------------------------
# DcvChallenge
# ---------------------------------------------------------------------------

class TestDcvChallenge:
    """DcvChallenge exposes expected properties with field name aliasing."""

    def test_domain(self):
        """domain reads 'domain' field."""
        c = DcvChallenge({"domain": "example.com", "method": "DNS-TXT"})
        assert c.domain == "example.com"

    def test_domain_falls_back_to_domain_name(self):
        """domain falls back to 'domainName'."""
        c = DcvChallenge({"domainName": "example.com"})
        assert c.domain == "example.com"

    def test_method_is_uppercase(self):
        """method is returned in upper case."""
        c = DcvChallenge({"method": "dns-txt"})
        assert c.method == "DNS-TXT"

    def test_method_reads_dcv_method(self):
        """method reads 'dcvMethod' when 'method' is absent."""
        c = DcvChallenge({"dcvMethod": "HTTP-URL"})
        assert c.method == "HTTP-URL"

    def test_token_reads_txt_token(self):
        """token reads txtToken."""
        c = DcvChallenge({"txtToken": "abc123"})
        assert c.token == "abc123"

    def test_token_reads_file_token(self):
        """token falls back to fileToken."""
        c = DcvChallenge({"fileToken": "xyz789"})
        assert c.token == "xyz789"

    def test_token_reads_dns_contents(self):
        """token falls back to dnsContents."""
        c = DcvChallenge({"dnsContents": "token-value"})
        assert c.token == "token-value"

    def test_host_reads_dns_host(self):
        """host reads dnsHost."""
        c = DcvChallenge({"dnsHost": "_emudhra-challenge.example.com"})
        assert c.host == "_emudhra-challenge.example.com"

    def test_value_aliases_token(self):
        """value returns the same as token when no explicit 'value' field."""
        c = DcvChallenge({"txtToken": "mytoken"})
        assert c.value == c.token

    def test_value_reads_direct_value_field(self):
        """value reads 'value' directly when present."""
        c = DcvChallenge({"value": "direct-value"})
        assert c.value == "direct-value"

    def test_missing_fields_return_none(self):
        """Missing fields return None."""
        c = DcvChallenge({})
        assert c.domain is None
        assert c.method is None
        assert c.token is None
        assert c.host is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        data = {"domain": "example.com"}
        c = DcvChallenge(data)
        assert c.as_dict() is data

    def test_repr_contains_domain_method_host(self):
        """repr() includes domain, method, and host."""
        c = DcvChallenge({"domain": "example.com", "method": "DNS-TXT", "dnsHost": "_h.example.com"})
        r = repr(c)
        assert "example.com" in r
        assert "DNS-TXT" in r


# ---------------------------------------------------------------------------
# CertificateDownload
# ---------------------------------------------------------------------------

class TestCertificateDownload:
    """CertificateDownload exposes expected properties."""

    _DATA = {
        "orderId": "ORDER-001",
        "serialNumber": "1234ABCD",
        "subject": "CN=example.com",
        "issuer": "CN=CertiNext CA",
        "notBefore": "2026-05-27T00:00:00Z",
        "notAfter": "2027-05-27T00:00:00Z",
        "certificatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "chainPem": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"],
    }

    def test_order_id(self):
        """order_id reads orderId."""
        cert = CertificateDownload(self._DATA)
        assert cert.order_id == "ORDER-001"

    def test_serial_number(self):
        """serial_number reads serialNumber."""
        cert = CertificateDownload(self._DATA)
        assert cert.serial_number == "1234ABCD"

    def test_subject(self):
        """subject reads subject."""
        cert = CertificateDownload(self._DATA)
        assert cert.subject == "CN=example.com"

    def test_issuer(self):
        """issuer reads issuer."""
        cert = CertificateDownload(self._DATA)
        assert cert.issuer == "CN=CertiNext CA"

    def test_not_before(self):
        """not_before reads notBefore."""
        cert = CertificateDownload(self._DATA)
        assert cert.not_before == "2026-05-27T00:00:00Z"

    def test_not_after(self):
        """not_after reads notAfter."""
        cert = CertificateDownload(self._DATA)
        assert cert.not_after == "2027-05-27T00:00:00Z"

    def test_certificate_pem(self):
        """certificate_pem reads certificatePem."""
        cert = CertificateDownload(self._DATA)
        assert cert.certificate_pem is not None
        assert cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_chain_pem_returns_list(self):
        """chain_pem reads chainPem as a list."""
        cert = CertificateDownload(self._DATA)
        assert len(cert.chain_pem) == 1

    def test_chain_pem_empty_when_missing(self):
        """chain_pem returns [] when chainPem is absent."""
        cert = CertificateDownload({})
        assert cert.chain_pem == []

    def test_missing_fields_return_none(self):
        """Missing fields return None."""
        cert = CertificateDownload({})
        assert cert.order_id is None
        assert cert.serial_number is None
        assert cert.certificate_pem is None

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        cert = CertificateDownload(self._DATA)
        assert cert.as_dict() is self._DATA

    def test_repr_contains_order_and_dates(self):
        """repr() includes order_id, serial_number, and not_after."""
        cert = CertificateDownload(self._DATA)
        r = repr(cert)
        assert "ORDER-001" in r
        assert "1234ABCD" in r


# ---------------------------------------------------------------------------
# SslOrder — properties
# ---------------------------------------------------------------------------

class TestSslOrderProperties:
    """SslOrder exposes expected properties."""

    def test_order_id(self):
        """order_id reads orderId."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.order_id == "ORDER-001"

    def test_request_id(self):
        """request_id reads requestId."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.request_id == "REQ-001"

    def test_status(self):
        """status reads status."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.status == "pending-dcv"

    def test_product_variant(self):
        """product_variant reads productVariant."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.product_variant == "dv"

    def test_domain(self):
        """domain reads domain."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.domain == "example.com"

    def test_additional_domains(self):
        """additional_domains reads additionalDomains."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.additional_domains == ["www.example.com"]

    def test_additional_domains_empty_when_missing(self):
        """additional_domains returns [] when the field is absent."""
        order = SslOrder(MagicMock(), {})
        assert order.additional_domains == []

    def test_created_at(self):
        """created_at reads createdAt."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.created_at == "2026-05-27T12:00:00Z"

    def test_as_dict_returns_raw_data(self):
        """as_dict() returns the exact dict passed at construction."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        assert order.as_dict() is _ORDER_DATA

    def test_repr_contains_key_fields(self):
        """repr() includes order_id, domain, and status."""
        order = SslOrder(MagicMock(), _ORDER_DATA)
        r = repr(order)
        assert "ORDER-001" in r
        assert "example.com" in r
        assert "pending-dcv" in r


# ---------------------------------------------------------------------------
# SslOrder — lifecycle API methods
# ---------------------------------------------------------------------------

class TestSslOrderLifecycleMethods:
    """SslOrder lifecycle methods call the correct API endpoints."""

    def _make_order(self) -> tuple[SslOrder, MagicMock]:
        client, mock_session = _make_client()
        order = SslOrder(client, _ORDER_DATA)
        return order, mock_session

    def test_refresh_calls_get_on_order_id(self):
        """refresh() GETs /ssl-certificates/{orderId}."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"orderId": "ORDER-001", "status": "issued"})
        order.refresh()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001")

    def test_refresh_updates_data(self):
        """refresh() updates the order's internal data dict."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"orderId": "ORDER-001", "status": "issued"})
        result = order.refresh()
        assert order.status == "issued"
        assert result is order

    def test_get_dcv_calls_dcv_endpoint(self):
        """get_dcv() GETs /ssl-certificates/{orderId}/dcv."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"challenges": []})
        order.get_dcv()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/dcv")

    def test_get_dcv_returns_list_of_challenges(self):
        """get_dcv() returns a list of DcvChallenge objects."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({
            "challenges": [
                {"domain": "example.com", "method": "DNS-TXT", "txtToken": "abc"},
            ]
        })
        challenges = order.get_dcv()
        assert len(challenges) == 1
        assert isinstance(challenges[0], DcvChallenge)
        assert challenges[0].domain == "example.com"

    def test_get_dcv_handles_bare_list_response(self):
        """get_dcv() handles a bare list response."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response(
            [{"domain": "example.com", "method": "HTTP-URL"}]
        )
        challenges = order.get_dcv()
        assert len(challenges) == 1

    def test_verify_dcv_posts_to_dcv_verify(self):
        """verify_dcv() POSTs to /ssl-certificates/{orderId}/dcv/verify."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({"status": "ok"})
        order.verify_dcv()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/dcv/verify")

    def test_submit_csr_puts_to_csr_endpoint(self):
        """submit_csr() PUTs to /ssl-certificates/{orderId}/csr with the CSR body."""
        order, mock_session = self._make_order()
        mock_session.put.return_value = _ok_response({})
        order.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\n...")
        url = mock_session.put.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/csr")
        _, kwargs = mock_session.put.call_args
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_accept_agreement_posts_to_agreement_endpoint(self):
        """accept_agreement() POSTs to /ssl-certificates/{orderId}/agreement with signer info."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.accept_agreement("John Doe", "Portland, ME")
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/agreement")
        _, kwargs = mock_session.post.call_args
        agreement = kwargs["json"]["agreement"]
        assert agreement["signerName"] == "John Doe"
        assert agreement["signerPlace"] == "Portland, ME"
        assert agreement["accepted"] is True

    def test_download_certificate_gets_certificate_endpoint(self):
        """download_certificate() GETs /ssl-certificates/{orderId}/certificate."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({
            "orderId": "ORDER-001", "certificatePem": "-----BEGIN CERTIFICATE-----\n..."
        })
        cert = order.download_certificate()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/certificate")
        assert isinstance(cert, CertificateDownload)

    def test_download_certificate_pem_uses_pem_accept_header(self):
        """download_certificate_pem() requests application/x-pem-file."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_bytes_response(b"-----BEGIN CERTIFICATE-----\n...")
        result = order.download_certificate_pem()
        _, kwargs = mock_session.get.call_args
        assert kwargs["headers"]["Accept"] == "application/x-pem-file"
        assert isinstance(result, str)
        assert result.startswith("-----BEGIN CERTIFICATE-----")

    def test_download_certificate_der_uses_der_accept_header(self):
        """download_certificate_der() requests application/pkix-cert."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_bytes_response(b"\x30\x82\x01\x02")
        result = order.download_certificate_der()
        _, kwargs = mock_session.get.call_args
        assert kwargs["headers"]["Accept"] == "application/pkix-cert"
        assert isinstance(result, bytes)

    def test_cancel_posts_to_cancel_endpoint(self):
        """cancel() POSTs to /ssl-certificates/{orderId}/cancel."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.cancel()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/cancel")

    def test_reject_posts_to_reject_endpoint(self):
        """reject() POSTs to /ssl-certificates/{orderId}/reject."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reject()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/reject")

    def test_revoke_posts_to_revoke_endpoint(self):
        """revoke() POSTs to /ssl-certificates/{orderId}/revoke."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.revoke()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/revoke")

    def test_revoke_with_reason_includes_reason_in_body(self):
        """revoke(reason=...) includes the reason in the request body."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.revoke(reason="keyCompromise")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["reason"] == "keyCompromise"

    def test_revoke_without_reason_sends_none_body(self):
        """revoke() with no reason sends json=None."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.revoke()
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"] is None


class TestSslOrderReissue:
    """SslOrder.reissue() validates mode and sends the correct body."""

    def _make_order(self) -> tuple[SslOrder, MagicMock]:
        client, mock_session = _make_client()
        order = SslOrder(client, _ORDER_DATA)
        return order, mock_session

    def test_reissue_rekey_posts_with_csr(self):
        """reissue('rekey', csr=...) includes mode and csr in the body."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reissue("rekey", csr="-----BEGIN CERTIFICATE REQUEST-----\n...")
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/reissue")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["mode"] == "rekey"
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_reissue_update_sans_posts_with_additional_domains(self):
        """reissue('update-sans', additional_domains=...) includes the domain list."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reissue("update-sans", additional_domains=["api.example.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["mode"] == "update-sans"
        assert kwargs["json"]["additionalDomains"] == ["api.example.com"]

    def test_reissue_rekey_without_csr_raises(self):
        """reissue('rekey') without csr raises ValueError."""
        order, _ = self._make_order()
        with pytest.raises(ValueError, match="csr is required"):
            order.reissue("rekey")

    def test_reissue_update_sans_without_domains_raises(self):
        """reissue('update-sans') without additional_domains raises ValueError."""
        order, _ = self._make_order()
        with pytest.raises(ValueError, match="additional_domains is required"):
            order.reissue("update-sans")


# ---------------------------------------------------------------------------
# SslAccessor — _build_body
# ---------------------------------------------------------------------------

class TestSslAccessorBuildBody:
    """SslAccessor._build_body produces the correct nested request structure."""

    def test_dv_body_structure(self):
        """DV body has productVariant, certificate.domain, subscription.validityYears, requestor."""
        body = SslAccessor._build_body(
            "dv", "example.com", 1,
            "John Doe", "john@example.com", "+12075551234", "IT Admin",
        )
        assert body["productVariant"] == "dv"
        assert body["certificate"]["domain"] == "example.com"
        assert body["subscription"]["validityYears"] == 1
        assert body["requestor"]["name"] == "John Doe"
        assert body["requestor"]["email"] == "john@example.com"
        assert body["requestor"]["phone"] == "+12075551234"
        assert body["requestor"]["designation"] == "IT Admin"
        assert "organization" not in body

    def test_additional_domains_in_certificate(self):
        """additional_domains appear inside the certificate sub-object."""
        body = SslAccessor._build_body(
            "dv", "example.com", 1, "", "", "", "",
            additional_domains=["www.example.com"],
        )
        assert body["certificate"]["additionalDomains"] == ["www.example.com"]

    def test_organization_included_for_ov(self):
        """OV body includes organization.organizationNumber and preVetted=True."""
        body = SslAccessor._build_body(
            "ov", "example.com", 1, "", "", "", "",
            organization_id="ORG-001",
        )
        assert body["organization"]["organizationNumber"] == "ORG-001"
        assert body["organization"]["preVetted"] is True

    def test_no_additional_domains_when_none(self):
        """'additionalDomains' key absent when additional_domains is None."""
        body = SslAccessor._build_body("dv", "example.com", 1, "", "", "", "")
        assert "additionalDomains" not in body["certificate"]

    def test_validity_years_passed_through(self):
        """validity_years is placed in subscription.validityYears."""
        body = SslAccessor._build_body("dv", "example.com", 3, "", "", "", "")
        assert body["subscription"]["validityYears"] == 3


# ---------------------------------------------------------------------------
# SslAccessor — create methods
# ---------------------------------------------------------------------------

class TestSslAccessorCreateMethods:
    """SslAccessor create_* methods POST to /ssl-certificates with productVariant."""

    def _make_accessor(self) -> tuple[SslAccessor, MagicMock]:
        client, mock_session = _make_client()
        accessor = SslAccessor(client)
        return accessor, mock_session

    def _assert_create(self, mock_session: MagicMock, product_variant: str) -> None:
        url = mock_session.post.call_args[0][0]
        assert url.endswith(_SSL_BASE), f"Expected URL ending with {_SSL_BASE!r}, got {url!r}"
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["productVariant"] == product_variant

    def test_create_dv_posts_to_ssl_certificates(self):
        """create_dv() POSTs to /ssl-certificates with productVariant='dv'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        self._assert_create(mock_session, "dv")

    def test_create_dv_includes_domain_in_certificate_body(self):
        """create_dv() puts domain inside the nested certificate object."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", validity_years=2)
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["certificate"]["domain"] == "example.com"
        assert kwargs["json"]["subscription"]["validityYears"] == 2

    def test_create_dv_wildcard_uses_dv_wildcard_variant(self):
        """create_dv_wildcard() uses productVariant='dv-wildcard'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard("*.example.com")
        self._assert_create(mock_session, "dv-wildcard")

    def test_create_dv_ucc_uses_dv_ucc_variant(self):
        """create_dv_ucc() uses productVariant='dv-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["example.com", "www.example.com"])
        self._assert_create(mock_session, "dv-ucc")

    def test_create_dv_wildcard_ucc_uses_dv_wildcard_ucc_variant(self):
        """create_dv_wildcard_ucc() uses productVariant='dv-wildcard-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard_ucc(["*.example.com"])
        self._assert_create(mock_session, "dv-wildcard-ucc")

    def test_create_ov_uses_ov_variant_and_includes_org(self):
        """create_ov() uses productVariant='ov' and includes organization in body."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ov")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["organization"]["organizationNumber"] == "ORG-001"
        assert kwargs["json"]["organization"]["preVetted"] is True

    def test_create_ov_wildcard_uses_ov_wildcard_variant(self):
        """create_ov_wildcard() uses productVariant='ov-wildcard'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard("*.example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ov-wildcard")

    def test_create_ov_ucc_uses_ov_ucc_variant(self):
        """create_ov_ucc() uses productVariant='ov-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ov-ucc")

    def test_create_ov_wildcard_ucc_uses_ov_wildcard_ucc_variant(self):
        """create_ov_wildcard_ucc() uses productVariant='ov-wildcard-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard_ucc(["*.example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ov-wildcard-ucc")

    def test_create_ev_uses_ev_variant(self):
        """create_ev() uses productVariant='ev'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ev")

    def test_create_ev_ucc_uses_ev_ucc_variant(self):
        """create_ev_ucc() uses productVariant='ev-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ev-ucc")

    def test_create_dv_returns_ssl_order(self):
        """create_dv() returns an SslOrder instance."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        order = accessor.create_dv("example.com")
        assert isinstance(order, SslOrder)
        assert order.order_id == "ORDER-001"

    def test_create_dv_includes_requestor_in_body(self):
        """create_dv() includes all requestor fields in the body."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv(
            "example.com",
            requestor_name="John Doe",
            requestor_email="john@example.com",
            requestor_phone="+12075551234",
            requestor_designation="IT Admin",
        )
        _, kwargs = mock_session.post.call_args
        req = kwargs["json"]["requestor"]
        assert req["name"] == "John Doe"
        assert req["email"] == "john@example.com"
        assert req["phone"] == "+12075551234"
        assert req["designation"] == "IT Admin"

    def test_create_dv_includes_additional_domains_in_certificate(self):
        """create_dv() includes additionalDomains inside the certificate object."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", additional_domains=["www.example.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["certificate"]["additionalDomains"] == ["www.example.com"]

    def test_create_dv_ucc_splits_domains_into_domain_and_additional(self):
        """create_dv_ucc() puts the first domain as 'domain', rest as 'additionalDomains'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["a.com", "b.com", "c.com"])
        _, kwargs = mock_session.post.call_args
        cert = kwargs["json"]["certificate"]
        assert cert["domain"] == "a.com"
        assert cert["additionalDomains"] == ["b.com", "c.com"]

    def test_create_dv_ucc_empty_domains_raises(self):
        """create_dv_ucc() raises ValueError when domains list is empty."""
        accessor, _ = self._make_accessor()
        with pytest.raises(ValueError, match="domains must not be empty"):
            accessor.create_dv_ucc([])

    def test_dv_body_has_no_organization_key(self):
        """create_dv() body does not include an 'organization' key."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        _, kwargs = mock_session.post.call_args
        assert "organization" not in kwargs["json"]

    def test_no_x_product_code_header(self):
        """create_dv() does not send an X-Product-Code header."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        _, kwargs = mock_session.post.call_args
        headers = kwargs.get("headers", {})
        assert "X-Product-Code" not in headers


# ---------------------------------------------------------------------------
# SslAccessor.get
# ---------------------------------------------------------------------------

class TestSslAccessorGet:
    """SslAccessor.get() fetches an existing order by ID."""

    def test_get_calls_ssl_order_endpoint(self):
        """get() GETs /ssl-certificates/{orderId}."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(_ORDER_DATA)
        accessor = SslAccessor(client)
        accessor.get("ORDER-001")
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001")

    def test_get_returns_ssl_order(self):
        """get() returns an SslOrder instance."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(_ORDER_DATA)
        accessor = SslAccessor(client)
        order = accessor.get("ORDER-001")
        assert isinstance(order, SslOrder)
        assert order.domain == "example.com"

    def test_get_raises_value_error_on_list_response(self):
        """get() raises ValueError when the API returns a list instead of a dict."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([_ORDER_DATA])
        accessor = SslAccessor(client)
        with pytest.raises(ValueError, match="Unexpected response type"):
            accessor.get("ORDER-001")
