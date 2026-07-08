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

from unittest.mock import MagicMock, patch

import pytest

from certinext.client import CertiNextClient
from certinext.exceptions import CertiNextAPIError, CertiNextTimeoutError
from certinext.ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    OrderWorkflow,
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
    client._session = mock_session
    return client, mock_session


def _ok_response(payload: object) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.is_error = False
    resp.json.return_value = payload
    resp.content = b"{}"
    return resp


def _ok_bytes_response(content: bytes) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.is_error = False
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
    "tags": ["foo", "bar"],
    "remarks": "some note",
}


# ---------------------------------------------------------------------------
# DcvChallenge
# ---------------------------------------------------------------------------

class TestDcvChallenge:
    """DcvChallenge exposes expected properties with field name aliasing."""

    def test_domain(self) -> None:
        """domain reads 'domain' field."""
        c = DcvChallenge.model_validate({"domain": "example.com", "method": "DNS-TXT"})
        assert c.domain == "example.com"

    def test_domain_falls_back_to_domain_name(self) -> None:
        """domain falls back to 'domainName'."""
        c = DcvChallenge.model_validate({"domainName": "example.com"})
        assert c.domain == "example.com"

    def test_method_is_uppercase(self) -> None:
        """method is returned in upper case."""
        c = DcvChallenge.model_validate({"method": "dns-txt"})
        assert c.method == "DNS-TXT"

    def test_method_reads_dcv_method(self) -> None:
        """method reads 'dcvMethod' when 'method' is absent."""
        c = DcvChallenge.model_validate({"dcvMethod": "HTTP-URL"})
        assert c.method == "HTTP-URL"

    def test_token_reads_txt_token(self) -> None:
        """token reads txtToken."""
        c = DcvChallenge.model_validate({"txtToken": "abc123"})
        assert c.token == "abc123"

    def test_token_reads_file_token(self) -> None:
        """token falls back to fileToken."""
        c = DcvChallenge.model_validate({"fileToken": "xyz789"})
        assert c.token == "xyz789"

    def test_token_reads_dns_contents(self) -> None:
        """token falls back to dnsContents."""
        c = DcvChallenge.model_validate({"dnsContents": "token-value"})
        assert c.token == "token-value"

    def test_host_reads_dns_host(self) -> None:
        """host reads dnsHost."""
        c = DcvChallenge.model_validate({"dnsHost": "_emudhra-challenge.example.com"})
        assert c.host == "_emudhra-challenge.example.com"

    def test_value_aliases_token(self) -> None:
        """value returns the same as token when no explicit 'value' field."""
        c = DcvChallenge.model_validate({"txtToken": "mytoken"})
        assert c.value == c.token

    def test_value_reads_direct_value_field(self) -> None:
        """value reads 'value' directly when present."""
        c = DcvChallenge.model_validate({"value": "direct-value"})
        assert c.value == "direct-value"

    def test_missing_fields_return_none(self) -> None:
        """Missing fields return None."""
        c = DcvChallenge.model_validate({})
        assert c.domain is None
        assert c.method is None
        assert c.token is None
        assert c.host is None

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        data = {"domain": "example.com"}
        c = DcvChallenge.model_validate(data)
        assert c.as_dict() is data

    def test_repr_contains_domain_method_host(self) -> None:
        """repr() includes domain, method, and host."""
        c = DcvChallenge.model_validate({"domain": "example.com", "method": "DNS-TXT", "dnsHost": "_h.example.com"})
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

    def test_order_id(self) -> None:
        """order_id reads orderId."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.order_id == "ORDER-001"

    def test_serial_number(self) -> None:
        """serial_number reads serialNumber."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.serial_number == "1234ABCD"

    def test_subject(self) -> None:
        """subject reads subject."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.subject == "CN=example.com"

    def test_issuer(self) -> None:
        """issuer reads issuer."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.issuer == "CN=CertiNext CA"

    def test_not_before(self) -> None:
        """not_before reads notBefore."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.not_before == "2026-05-27T00:00:00Z"

    def test_not_after(self) -> None:
        """not_after reads notAfter."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.not_after == "2027-05-27T00:00:00Z"

    def test_certificate_pem(self) -> None:
        """certificate_pem reads certificatePem."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.certificate_pem is not None
        assert cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_chain_pem_returns_list(self) -> None:
        """chain_pem reads chainPem as a list."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert len(cert.chain_pem) == 1

    def test_chain_pem_empty_when_missing(self) -> None:
        """chain_pem returns [] when chainPem is absent."""
        cert = CertificateDownload.model_validate({})
        assert cert.chain_pem == []

    def test_missing_fields_return_none(self) -> None:
        """Missing fields return None."""
        cert = CertificateDownload.model_validate({})
        assert cert.order_id is None
        assert cert.serial_number is None
        assert cert.certificate_pem is None

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        cert = CertificateDownload.model_validate(self._DATA)
        assert cert.as_dict() is self._DATA

    def test_repr_contains_order_and_dates(self) -> None:
        """repr() includes order_id, serial_number, and not_after."""
        cert = CertificateDownload.model_validate(self._DATA)
        r = repr(cert)
        assert "ORDER-001" in r
        assert "1234ABCD" in r


# ---------------------------------------------------------------------------
# SslOrder — properties
# ---------------------------------------------------------------------------

class TestSslOrderProperties:
    """SslOrder exposes expected properties."""

    def test_order_id(self) -> None:
        """order_id reads orderId."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.order_id == "ORDER-001"

    def test_request_id(self) -> None:
        """request_id reads requestId."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.request_id == "REQ-001"

    def test_status(self) -> None:
        """status reads status."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.status == "pending-dcv"

    def test_product_variant(self) -> None:
        """product_variant reads productVariant."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.product_variant == "dv"

    def test_domain(self) -> None:
        """domain reads domain."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.domain == "example.com"

    def test_additional_domains(self) -> None:
        """additional_domains reads additionalDomains."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.additional_domains == ["www.example.com"]

    def test_additional_domains_empty_when_missing(self) -> None:
        """additional_domains returns [] when the field is absent."""
        order = SslOrder.from_payload(MagicMock(), {})
        assert order.additional_domains == []

    def test_created_at(self) -> None:
        """created_at reads createdAt."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.created_at == "2026-05-27T12:00:00Z"

    def test_tags(self) -> None:
        """tags reads the tags list."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.tags == ["foo", "bar"]

    def test_tags_empty_when_missing(self) -> None:
        """tags returns [] when the field is absent."""
        order = SslOrder.from_payload(MagicMock(), {})
        assert order.tags == []

    def test_remarks(self) -> None:
        """remarks reads the remarks string."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.remarks == "some note"

    def test_remarks_none_when_missing(self) -> None:
        """remarks returns None when the field is absent."""
        order = SslOrder.from_payload(MagicMock(), {})
        assert order.remarks is None

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
        assert order.as_dict() is _ORDER_DATA

    def test_repr_contains_key_fields(self) -> None:
        """repr() includes order_id, domain, and status."""
        order = SslOrder.from_payload(MagicMock(), _ORDER_DATA)
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
        order = SslOrder.from_payload(client, _ORDER_DATA)
        return order, mock_session

    def test_refresh_calls_get_on_order_id(self) -> None:
        """refresh() GETs /ssl-certificates/{orderId}."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"orderId": "ORDER-001", "status": "issued"})
        order.refresh()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001")

    def test_refresh_updates_data(self) -> None:
        """refresh() updates the order's internal data dict."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"orderId": "ORDER-001", "status": "issued"})
        result = order.refresh()
        assert order.status == "issued"
        assert result is order

    def test_get_dcv_calls_dcv_endpoint(self) -> None:
        """get_dcv() GETs /ssl-certificates/{orderId}/dcv."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({"challenges": []})
        order.get_dcv()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/dcv")

    def test_get_dcv_returns_list_of_challenges(self) -> None:
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

    def test_get_dcv_handles_bare_list_response(self) -> None:
        """get_dcv() handles a bare list response."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response(
            [{"domain": "example.com", "method": "HTTP-URL"}]
        )
        challenges = order.get_dcv()
        assert len(challenges) == 1

    def test_verify_dcv_posts_to_dcv_verify(self) -> None:
        """verify_dcv() POSTs to /ssl-certificates/{orderId}/dcv/verify with domain and method."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({"status": "ok"})
        order.verify_dcv("example.com", "DNS-TXT")
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/dcv/verify")
        body = mock_session.post.call_args[1]["json"]
        assert body == {"domain": "example.com", "method": "DNS-TXT"}

    def test_submit_csr_puts_to_csr_endpoint(self) -> None:
        """submit_csr() PUTs to /ssl-certificates/{orderId}/csr with the CSR body."""
        order, mock_session = self._make_order()
        mock_session.put.return_value = _ok_response({})
        order.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\n...")
        url = mock_session.put.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/csr")
        _, kwargs = mock_session.put.call_args
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_accept_agreement_posts_to_agreement_endpoint(self) -> None:
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

    def test_download_certificate_gets_certificate_endpoint(self) -> None:
        """download_certificate() GETs /ssl-certificates/{orderId}/certificate."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_response({
            "orderId": "ORDER-001", "certificatePem": "-----BEGIN CERTIFICATE-----\n..."
        })
        cert = order.download_certificate()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/certificate")
        assert isinstance(cert, CertificateDownload)

    def test_download_certificate_pem_uses_pem_accept_header(self) -> None:
        """download_certificate_pem() requests application/x-pem-file."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_bytes_response(b"-----BEGIN CERTIFICATE-----\n...")
        result = order.download_certificate_pem()
        _, kwargs = mock_session.get.call_args
        assert kwargs["headers"]["Accept"] == "application/x-pem-file"
        assert isinstance(result, str)
        assert result.startswith("-----BEGIN CERTIFICATE-----")

    def test_download_certificate_der_uses_der_accept_header(self) -> None:
        """download_certificate_der() requests application/pkix-cert."""
        order, mock_session = self._make_order()
        mock_session.get.return_value = _ok_bytes_response(b"\x30\x82\x01\x02")
        result = order.download_certificate_der()
        _, kwargs = mock_session.get.call_args
        assert kwargs["headers"]["Accept"] == "application/pkix-cert"
        assert isinstance(result, bytes)

    def test_cancel_posts_to_cancel_endpoint(self) -> None:
        """cancel() POSTs to /ssl-certificates/{orderId}/cancel."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.cancel()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/cancel")

    def test_reject_posts_to_reject_endpoint(self) -> None:
        """reject() POSTs to /ssl-certificates/{orderId}/reject."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reject()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/reject")

    def test_revoke_posts_to_revoke_endpoint(self) -> None:
        """revoke() POSTs to /ssl-certificates/{orderId}/revoke."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.revoke()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/revoke")

    def test_revoke_with_reason_includes_reason_in_body(self) -> None:
        """revoke(reason=...) includes the reason in the request body."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.revoke(reason="keyCompromise")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["reason"] == "keyCompromise"

    def test_revoke_without_reason_sends_none_body(self) -> None:
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
        order = SslOrder.from_payload(client, _ORDER_DATA)
        return order, mock_session

    def test_reissue_rekey_posts_with_csr(self) -> None:
        """reissue('rekey', csr=...) includes mode and csr in the body."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reissue("rekey", csr="-----BEGIN CERTIFICATE REQUEST-----\n...")
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/reissue")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["mode"] == "rekey"
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_reissue_update_sans_posts_with_additional_domains(self) -> None:
        """reissue('update-sans', additional_domains=...) includes the domain list."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reissue("update-sans", additional_domains=["api.example.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["mode"] == "update-sans"
        assert kwargs["json"]["additionalDomains"] == ["api.example.com"]

    def test_reissue_rekey_without_csr_raises(self) -> None:
        """reissue('rekey') without csr raises ValueError."""
        order, _ = self._make_order()
        with pytest.raises(ValueError, match="csr is required"):
            order.reissue("rekey")

    def test_reissue_update_sans_without_domains_raises(self) -> None:
        """reissue('update-sans') without additional_domains raises ValueError."""
        order, _ = self._make_order()
        with pytest.raises(ValueError, match="additional_domains is required"):
            order.reissue("update-sans")


# ---------------------------------------------------------------------------
# SslAccessor — _build_body
# ---------------------------------------------------------------------------

class TestSslAccessorBuildBody:
    """SslAccessor._build_body produces the correct nested request structure."""

    def test_dv_body_structure(self) -> None:
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

    def test_additional_domains_in_certificate(self) -> None:
        """additional_domains appear inside the certificate sub-object."""
        body = SslAccessor._build_body(
            "dv", "example.com", 1, "", "", "", "",
            additional_domains=["www.example.com"],
        )
        assert body["certificate"]["additionalDomains"] == ["www.example.com"]

    def test_organization_included_for_ov(self) -> None:
        """OV body includes organization.organizationNumber and preVetted=True."""
        body = SslAccessor._build_body(
            "ov", "example.com", 1, "", "", "", "",
            organization_id="ORG-001",
        )
        assert body["organization"]["organizationNumber"] == "ORG-001"
        assert body["organization"]["preVetted"] is True

    def test_no_additional_domains_when_none(self) -> None:
        """'additionalDomains' key absent when additional_domains is None."""
        body = SslAccessor._build_body("dv", "example.com", 1, "", "", "", "")
        assert "additionalDomains" not in body["certificate"]

    def test_validity_years_passed_through(self) -> None:
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

    def test_create_dv_posts_to_ssl_certificates(self) -> None:
        """create_dv() POSTs to /ssl-certificates with productVariant='dv'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        self._assert_create(mock_session, "dv")

    def test_create_dv_includes_domain_in_certificate_body(self) -> None:
        """create_dv() puts domain inside the nested certificate object."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", validity_years=2)
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["certificate"]["domain"] == "example.com"
        assert kwargs["json"]["subscription"]["validityYears"] == 2

    def test_create_dv_sends_product_code_header(self) -> None:
        """create_dv(product_code=...) sends the X-Product-Code header."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", product_code="842")
        _, kwargs = mock_session.post.call_args
        assert kwargs["headers"]["X-Product-Code"] == "842"

    def test_create_dv_omits_product_code_header_by_default(self) -> None:
        """create_dv() without a product code sends no X-Product-Code header."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        _, kwargs = mock_session.post.call_args
        assert "X-Product-Code" not in kwargs["headers"]

    def test_create_ov_sends_product_code_header(self) -> None:
        """create_ov(product_code=...) sends the X-Product-Code header."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov("example.com", "12345", product_code="1057")
        _, kwargs = mock_session.post.call_args
        assert kwargs["headers"]["X-Product-Code"] == "1057"

    def test_create_dv_wildcard_uses_dv_wildcard_variant(self) -> None:
        """create_dv_wildcard() uses productVariant='dv-wildcard'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard("*.example.com")
        self._assert_create(mock_session, "dv-wildcard")

    def test_create_dv_ucc_uses_dv_ucc_variant(self) -> None:
        """create_dv_ucc() uses productVariant='dv-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["example.com", "www.example.com"])
        self._assert_create(mock_session, "dv-ucc")

    def test_create_dv_wildcard_ucc_uses_dv_wildcard_ucc_variant(self) -> None:
        """create_dv_wildcard_ucc() uses productVariant='dv-wildcard-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard_ucc(["*.example.com"])
        self._assert_create(mock_session, "dv-wildcard-ucc")

    def test_create_ov_uses_ov_variant_and_includes_org(self) -> None:
        """create_ov() uses productVariant='ov' and includes organization in body."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ov")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["organization"]["organizationNumber"] == "ORG-001"
        assert kwargs["json"]["organization"]["preVetted"] is True

    def test_create_ov_wildcard_uses_ov_wildcard_variant(self) -> None:
        """create_ov_wildcard() uses productVariant='ov-wildcard'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard("*.example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ov-wildcard")

    def test_create_ov_ucc_uses_ov_ucc_variant(self) -> None:
        """create_ov_ucc() uses productVariant='ov-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ov-ucc")

    def test_create_ov_wildcard_ucc_uses_ov_wildcard_ucc_variant(self) -> None:
        """create_ov_wildcard_ucc() uses productVariant='ov-wildcard-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard_ucc(["*.example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ov-wildcard-ucc")

    def test_create_ev_uses_ev_variant(self) -> None:
        """create_ev() uses productVariant='ev'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, "ev")

    def test_create_ev_ucc_uses_ev_ucc_variant(self) -> None:
        """create_ev_ucc() uses productVariant='ev-ucc'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, "ev-ucc")

    def test_create_dv_returns_ssl_order(self) -> None:
        """create_dv() returns an SslOrder instance."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        order = accessor.create_dv("example.com")
        assert isinstance(order, SslOrder)
        assert order.order_id == "ORDER-001"

    def test_create_dv_includes_requestor_in_body(self) -> None:
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

    def test_create_dv_includes_additional_domains_in_certificate(self) -> None:
        """create_dv() includes additionalDomains inside the certificate object."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", additional_domains=["www.example.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["certificate"]["additionalDomains"] == ["www.example.com"]

    def test_create_dv_ucc_splits_domains_into_domain_and_additional(self) -> None:
        """create_dv_ucc() puts the first domain as 'domain', rest as 'additionalDomains'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["a.com", "b.com", "c.com"])
        _, kwargs = mock_session.post.call_args
        cert = kwargs["json"]["certificate"]
        assert cert["domain"] == "a.com"
        assert cert["additionalDomains"] == ["b.com", "c.com"]

    def test_create_dv_ucc_empty_domains_raises(self) -> None:
        """create_dv_ucc() raises ValueError when domains list is empty."""
        accessor, _ = self._make_accessor()
        with pytest.raises(ValueError, match="domains must not be empty"):
            accessor.create_dv_ucc([])

    def test_dv_body_has_no_organization_key(self) -> None:
        """create_dv() body does not include an 'organization' key."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        _, kwargs = mock_session.post.call_args
        assert "organization" not in kwargs["json"]

    def test_no_x_product_code_header(self) -> None:
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

    def test_get_calls_ssl_order_endpoint(self) -> None:
        """get() GETs /ssl-certificates/{orderId}."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(_ORDER_DATA)
        accessor = SslAccessor(client)
        accessor.get("ORDER-001")
        url = mock_session.get.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001")

    def test_get_returns_ssl_order(self) -> None:
        """get() returns an SslOrder instance."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(_ORDER_DATA)
        accessor = SslAccessor(client)
        order = accessor.get("ORDER-001")
        assert isinstance(order, SslOrder)
        assert order.domain == "example.com"

    def test_get_raises_value_error_on_list_response(self) -> None:
        """get() raises ValueError when the API returns a list instead of a dict."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([_ORDER_DATA])
        accessor = SslAccessor(client)
        with pytest.raises(ValueError, match="Unexpected response type"):
            accessor.get("ORDER-001")


# ---------------------------------------------------------------------------
# OrderWorkflow
# ---------------------------------------------------------------------------

def _make_workflow(status: str = "pending-approval") -> tuple[OrderWorkflow, SslOrder, MagicMock]:
    """Return an (OrderWorkflow, SslOrder, mock_session) triple."""
    client, mock_session = _make_client()
    order = SslOrder.from_payload(client, {**_ORDER_DATA, "status": status})
    wf = OrderWorkflow(order, signer_name="Jane Doe", signer_place="Portland, ME")
    return wf, order, mock_session


def _refresh_response(status: str) -> MagicMock:
    """Mock GET response that returns an order with the given status."""
    return _ok_response({**_ORDER_DATA, "status": status})


class TestOrderWorkflowProperties:
    """OrderWorkflow exposes order state through properties."""

    def test_status_passthrough(self) -> None:
        """status returns the underlying order's status."""
        wf, _, _ = _make_workflow("pending-approval")
        assert wf.status == "pending-approval"

    def test_is_terminal_false_for_pending(self) -> None:
        """is_terminal is False for non-terminal statuses."""
        wf, _, _ = _make_workflow("pending-approval")
        assert not wf.is_terminal

    def test_is_terminal_true_for_issued(self) -> None:
        """is_terminal is True for 'issued'."""
        wf, _, _ = _make_workflow("issued")
        assert wf.is_terminal

    def test_is_terminal_true_for_cancelled(self) -> None:
        """is_terminal is True for 'cancelled'."""
        wf, _, _ = _make_workflow("cancelled")
        assert wf.is_terminal

    def test_is_complete_true_only_for_issued(self) -> None:
        """is_complete is True only when status is 'issued'."""
        wf_issued, _, _ = _make_workflow("issued")
        wf_cancelled, _, _ = _make_workflow("cancelled")
        assert wf_issued.is_complete
        assert not wf_cancelled.is_complete

    def test_order_property_returns_ssl_order(self) -> None:
        """order property returns the underlying SslOrder."""
        wf, order, _ = _make_workflow()
        assert wf.order is order


class TestOrderWorkflowOn:
    """OrderWorkflow.on() registers handlers and returns self for chaining."""

    def test_on_returns_self(self) -> None:
        """on() returns self for method chaining."""
        wf, _, _ = _make_workflow()
        result = wf.on("status_change", lambda *a: None)
        assert result is wf

    def test_multiple_handlers_for_same_event(self) -> None:
        """Multiple handlers for the same event are all called."""
        wf, _, _ = _make_workflow()
        calls = []
        wf.on("poll", lambda o: calls.append("first"))
        wf.on("poll", lambda o: calls.append("second"))
        wf._emit("poll", wf.order)
        assert calls == ["first", "second"]


class TestOrderWorkflowSubmitCsr:
    """OrderWorkflow.submit_csr() attempts CSR submission."""

    def test_returns_false_for_empty_csr(self) -> None:
        """submit_csr returns False without calling the API when csr is empty."""
        wf, _, mock_session = _make_workflow("pending-csr")
        result = wf.submit_csr("")
        assert result is False
        mock_session.put.assert_not_called()

    def test_returns_false_on_422(self) -> None:
        """submit_csr returns False (not needed) on a 422 response."""
        wf, _, mock_session = _make_workflow("pending-approval")
        resp_422 = MagicMock()
        resp_422.status_code = 422
        resp_422.is_error = True
        resp_422.json.return_value = {}
        resp_422.content = b"{}"

        with patch.object(wf.order, "submit_csr", side_effect=CertiNextAPIError(422, {})):
            result = wf.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----")
        assert result is False

    def test_propagates_non_422_errors(self) -> None:
        """submit_csr re-raises errors other than 422."""
        wf, _, _ = _make_workflow()
        with patch.object(wf.order, "submit_csr", side_effect=CertiNextAPIError(500, {"detail": "server error"})):
            with pytest.raises(CertiNextAPIError):
                wf.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----")

    def test_returns_false_for_terminal_without_force(self) -> None:
        """submit_csr skips silently when order is terminal and force=False."""
        wf, _, mock_session = _make_workflow("issued")
        result = wf.submit_csr("some-csr")
        assert result is False


class TestOrderWorkflowAdvance:
    """OrderWorkflow.advance() drives the state machine one step."""

    def test_returns_complete_for_issued(self) -> None:
        """advance() returns 'complete' when order is already issued."""
        wf, _, mock_session = _make_workflow("issued")
        mock_session.get.return_value = _refresh_response("issued")
        result = wf.advance()
        assert result == "complete"

    def test_returns_complete_for_cancelled(self) -> None:
        """advance() returns 'complete' for any terminal status."""
        wf, _, mock_session = _make_workflow("cancelled")
        mock_session.get.return_value = _refresh_response("cancelled")
        result = wf.advance()
        assert result == "complete"

    def test_returns_waiting_for_pending_approval(self) -> None:
        """advance() returns 'waiting' when status is pending-approval."""
        wf, _, mock_session = _make_workflow("pending-approval")
        mock_session.get.return_value = _refresh_response("pending-approval")
        result = wf.advance()
        assert result == "waiting"

    def test_accepts_agreement_when_pending_agreement(self) -> None:
        """advance() calls accept_agreement when status is pending-agreement."""
        wf, _, mock_session = _make_workflow("pending-agreement")
        mock_session.get.return_value = _refresh_response("pending-agreement")
        mock_session.post.return_value = _ok_response({})
        result = wf.advance()
        assert result == "accepted-agreement"
        post_url = mock_session.post.call_args[0][0]
        assert "agreement" in post_url

    def test_submits_csr_when_pending_csr(self) -> None:
        """advance() submits the CSR when status is pending-csr."""
        wf, _, mock_session = _make_workflow("pending-csr")
        mock_session.get.return_value = _refresh_response("pending-csr")
        mock_session.put.return_value = _ok_response({})
        result = wf.advance(csr="-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----")
        assert result == "submitted-csr"

    def test_raises_when_pending_csr_without_csr(self) -> None:
        """advance() raises ValueError when pending-csr and no CSR provided."""
        wf, _, mock_session = _make_workflow("pending-csr")
        mock_session.get.return_value = _refresh_response("pending-csr")
        with pytest.raises(ValueError, match="pending-csr"):
            wf.advance()

    def test_fires_status_change_event(self) -> None:
        """advance() fires 'status_change' when the status changes."""
        wf, _, mock_session = _make_workflow("pending-approval")
        mock_session.get.return_value = _refresh_response("issued")
        events: list[tuple[str | None, str | None]] = []
        wf.on("status_change", lambda old, new: events.append((old, new)))
        wf.advance()
        assert ("pending-approval", "issued") in events

    def test_fires_issued_event_when_issued(self) -> None:
        """advance() fires 'issued' when the order reaches issued status."""
        wf, _, mock_session = _make_workflow("pending-approval")
        mock_session.get.return_value = _refresh_response("issued")
        fired: list[SslOrder] = []
        wf.on("issued", lambda o: fired.append(o))
        wf.advance()
        assert len(fired) == 1

    def test_fires_poll_event_while_waiting(self) -> None:
        """advance() fires 'poll' when in a non-actionable pending state."""
        wf, _, mock_session = _make_workflow("pending-approval")
        mock_session.get.return_value = _refresh_response("pending-approval")
        polls: list[object] = []
        wf.on("poll", lambda o: polls.append(o))
        wf.advance()
        assert len(polls) == 1

    def test_fires_dcv_available_when_pending_dcv(self) -> None:
        """advance() fires 'dcv_available' with challenge list when pending-dcv."""
        wf, _, mock_session = _make_workflow("pending-dcv")
        challenge_data = {"domain": "example.com", "dcvMethod": "DNS-TXT",
                          "dnsHost": "_certinext.example.com", "txtToken": "abc123"}
        mock_session.get.side_effect = [
            _refresh_response("pending-dcv"),   # refresh()
            _ok_response({"challenges": [challenge_data]}),  # get_dcv()
            _refresh_response("pending-dcv"),   # refresh() after verify
        ]
        mock_session.post.return_value = _ok_response({})
        dcv_events: list[list[DcvChallenge]] = []
        wf.on("dcv_available", lambda cs: dcv_events.append(cs))
        wf.advance()
        assert len(dcv_events) == 1
        assert dcv_events[0][0].domain == "example.com"


class TestOrderWorkflowDownload:
    """OrderWorkflow.download() fetches the PEM and retries on 422."""

    def test_returns_pem_on_success(self) -> None:
        """download() returns the PEM string from the first attempt."""
        wf, _, mock_session = _make_workflow("issued")
        cert = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
        mock_session.get.return_value = _ok_bytes_response(cert)
        pem = wf.download()
        assert pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_retries_on_422_then_succeeds(self) -> None:
        """download() retries when the first attempt returns 422."""
        wf, _, mock_session = _make_workflow("issued")
        resp_422 = MagicMock()
        resp_422.status_code = 422
        resp_422.is_error = True

        cert_bytes = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
        call_count = 0

        def side_effect() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise CertiNextAPIError(422, {"detail": "EMS-1165"})
            return cert_bytes.decode()

        with patch.object(wf.order, "download_certificate_pem", side_effect=side_effect):
            with patch("certinext.ssl_certificates.time") as mock_time:
                mock_time.monotonic.return_value = 0
                mock_time.sleep.return_value = None
                pem = wf.download(retry_delay=0)

        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert call_count == 2

    def test_raises_after_all_retries_exhausted(self) -> None:
        """download() raises CertiNextAPIError after all retries fail."""
        wf, _, _ = _make_workflow("issued")
        with patch.object(wf.order, "download_certificate_pem",
                          side_effect=CertiNextAPIError(422, {})):
            with patch("certinext.ssl_certificates.time"):
                with pytest.raises(CertiNextAPIError):
                    wf.download(retries=2, retry_delay=0)


class TestOrderWorkflowRun:
    """OrderWorkflow.run() drives the full workflow."""

    def test_raises_timeout_error_when_poll_times_out(self) -> None:
        """run() raises CertiNextTimeoutError when the order doesn't issue in time."""
        wf, _, mock_session = _make_workflow("pending-approval")
        mock_session.get.return_value = _refresh_response("pending-approval")
        with patch("certinext.ssl_certificates.time") as mock_time:
            mock_time.monotonic.side_effect = [0, 0, 400]  # deadline exceeded
            mock_time.sleep.return_value = None
            with pytest.raises(CertiNextTimeoutError) as exc_info:
                wf.run(wait=300)
        assert exc_info.value.order_id == "ORDER-001"
        assert exc_info.value.wait == 300

    def test_timeout_error_is_also_builtin_timeout_error(self) -> None:
        """CertiNextTimeoutError is catchable as the built-in TimeoutError."""
        err = CertiNextTimeoutError("ORDER-001", 300)
        assert isinstance(err, TimeoutError)

    def test_submit_csr_called_with_force(self) -> None:
        """run() calls submit_csr(force=True) before polling."""
        wf, _, mock_session = _make_workflow("issued")
        mock_session.get.return_value = _refresh_response("issued")
        mock_session.get.side_effect = [
            _refresh_response("issued"),
        ]
        cert_pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
        with patch.object(wf, "submit_csr", return_value=False) as mock_submit:
            with patch.object(wf, "poll", return_value=True):
                with patch.object(wf, "download", return_value=cert_pem):
                    wf.run(csr="some-csr", wait=10)
        mock_submit.assert_called_once_with("some-csr", force=True)


class TestOrderWorkflowFromCsr:
    """OrderWorkflow.from_csr() fills signer_place from the CSR subject."""

    def test_explicit_signer_place_not_overridden(self) -> None:
        """from_csr does not override signer_place when explicitly provided."""
        _, order, _ = _make_workflow()
        wf = OrderWorkflow.from_csr(order, "fake-pem", signer_name="X",
                                     signer_place="Custom Place")
        assert wf._signer_place == "Custom Place"

    def test_falls_back_gracefully_on_import_error(self) -> None:
        """from_csr returns a workflow with empty signer_place when cryptography is absent."""
        _, order, _ = _make_workflow()
        with patch("certinext.csr.parse_csr", side_effect=ImportError("no crypto")):
            wf = OrderWorkflow.from_csr(order, "fake-pem", signer_name="X")
        assert wf._signer_place == ""

    def test_populates_signer_place_from_csr(self) -> None:
        """from_csr derives signer_place from locality/state when not supplied."""
        from certinext.csr import CsrInfo
        _, order, _ = _make_workflow()
        fake_info = CsrInfo(common_name="x", email=None, locality="Orono",
                            state="Maine", organization=None)
        with patch("certinext.csr.parse_csr", return_value=fake_info):
            wf = OrderWorkflow.from_csr(order, "fake-pem", signer_name="X")
        assert wf._signer_place == "Orono, Maine"


# ---------------------------------------------------------------------------
# CertificateDownload.as_pem_chain
# ---------------------------------------------------------------------------

_LEAF = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
_INT1 = "-----BEGIN CERTIFICATE-----\nINT1\n-----END CERTIFICATE-----"
_INT2 = "-----BEGIN CERTIFICATE-----\nINT2\n-----END CERTIFICATE-----"


class TestCertificateDownloadAsPemChain:
    """as_pem_chain() builds a leaf-first fullchain with a single trailing newline."""

    def test_leaf_first_order(self) -> None:
        """Chain is end-entity cert followed by intermediates, in order."""
        cert = CertificateDownload.model_validate({"certificatePem": _LEAF, "chainPem": [_INT1, _INT2]})
        chain = cert.as_pem_chain()
        assert chain == f"{_LEAF}\n{_INT1}\n{_INT2}\n"
        assert chain.index("LEAF") < chain.index("INT1") < chain.index("INT2")

    def test_single_trailing_newline(self) -> None:
        """Trailing/embedded whitespace is normalised to one final newline."""
        cert = CertificateDownload.model_validate({"certificatePem": _LEAF + "\n\n", "chainPem": [_INT1 + "\n"]})
        chain = cert.as_pem_chain()
        assert chain == f"{_LEAF}\n{_INT1}\n"
        assert chain.endswith("\n")
        assert not chain.endswith("\n\n")

    def test_leaf_only_when_no_chain(self) -> None:
        """With no intermediates the chain is just the leaf plus a newline."""
        cert = CertificateDownload.model_validate({"certificatePem": _LEAF})
        assert cert.as_pem_chain() == f"{_LEAF}\n"

    def test_empty_when_no_certificate(self) -> None:
        """Returns an empty string when there is no certificate at all."""
        assert CertificateDownload.model_validate({}).as_pem_chain() == ""


# ---------------------------------------------------------------------------
# SslAccessor.create — product dispatcher
# ---------------------------------------------------------------------------

class TestSslAccessorCreateDispatch:
    """create() routes to create_dv/ov/ev by product and validates org id."""

    def _make_accessor(self) -> tuple[SslAccessor, MagicMock]:
        client, mock_session = _make_client()
        return SslAccessor(client), mock_session

    def test_dv_dispatch(self) -> None:
        """create('dv', ...) POSTs a dv order."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create("dv", "example.com")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["productVariant"] == "dv"

    def test_dv_is_case_insensitive(self) -> None:
        """Product matching ignores case and surrounding whitespace."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create(" DV ", "example.com")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["productVariant"] == "dv"

    def test_dv_forwards_kwargs(self) -> None:
        """Extra kwargs are forwarded to the underlying create_* method."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create("dv", "example.com", validity_years=2,
                        additional_domains=["www.example.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["subscription"]["validityYears"] == 2
        assert "www.example.com" in kwargs["json"]["certificate"]["additionalDomains"]

    def test_ov_dispatch_includes_org(self) -> None:
        """create('ov', ..., organization_id=...) POSTs an ov order with the org."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create("ov", "example.com", organization_id="ORG-001")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["productVariant"] == "ov"
        assert kwargs["json"]["organization"]["organizationNumber"] == "ORG-001"

    def test_ev_dispatch(self) -> None:
        """create('ev', ..., organization_id=...) POSTs an ev order."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create("ev", "example.com", organization_id="ORG-001")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["productVariant"] == "ev"

    def test_ov_without_org_raises(self) -> None:
        """create('ov', ...) without organization_id raises ValueError."""
        accessor, _ = self._make_accessor()
        with pytest.raises(ValueError, match="organization_id is required"):
            accessor.create("ov", "example.com")

    def test_ev_without_org_raises(self) -> None:
        """create('ev', ...) without organization_id raises ValueError."""
        accessor, _ = self._make_accessor()
        with pytest.raises(ValueError, match="organization_id is required"):
            accessor.create("ev", "example.com")

    def test_unknown_product_raises(self) -> None:
        """An unrecognised product raises ValueError."""
        accessor, _ = self._make_accessor()
        with pytest.raises(ValueError, match="Unknown product"):
            accessor.create("xv", "example.com")


# ---------------------------------------------------------------------------
# OrderWorkflow.download_chain
# ---------------------------------------------------------------------------

class TestOrderWorkflowDownloadChain:
    """download_chain() returns a normalised fullchain, retrying on 422."""

    def test_returns_fullchain(self) -> None:
        """download_chain() returns the leaf-first chain from the JSON download."""
        wf, _, _ = _make_workflow("issued")
        download = CertificateDownload.model_validate({"certificatePem": _LEAF, "chainPem": [_INT1]})
        with patch.object(wf.order, "download_certificate", return_value=download):
            chain = wf.download_chain()
        assert chain == f"{_LEAF}\n{_INT1}\n"

    def test_retries_on_422_then_succeeds(self) -> None:
        """download_chain() retries when the first attempt returns 422."""
        wf, _, _ = _make_workflow("issued")
        download = CertificateDownload.model_validate({"certificatePem": _LEAF, "chainPem": []})
        call_count = 0

        def side_effect() -> CertificateDownload:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise CertiNextAPIError(422, {"detail": "not ready"})
            return download

        with patch.object(wf.order, "download_certificate", side_effect=side_effect):
            with patch("certinext.ssl_certificates.time"):
                chain = wf.download_chain(retry_delay=0)

        assert chain == f"{_LEAF}\n"
        assert call_count == 2

    def test_raises_after_all_retries_exhausted(self) -> None:
        """download_chain() raises CertiNextAPIError after all retries fail."""
        wf, _, _ = _make_workflow("issued")
        with patch.object(wf.order, "download_certificate",
                          side_effect=CertiNextAPIError(422, {})):
            with patch("certinext.ssl_certificates.time"):
                with pytest.raises(CertiNextAPIError):
                    wf.download_chain(retries=2, retry_delay=0)


# ---------------------------------------------------------------------------
# OrderWorkflow.from_order_id
# ---------------------------------------------------------------------------

class TestOrderWorkflowFromOrderId:
    """from_order_id() resumes a workflow from a persisted order id."""

    def test_fetches_and_wraps_order(self) -> None:
        """from_order_id() fetches via session.ssl.get and wraps the result."""
        client, _ = _make_client()
        order = SslOrder.from_payload(client, _ORDER_DATA)
        session = MagicMock()
        session.ssl.get.return_value = order
        wf = OrderWorkflow.from_order_id(
            session, "ORDER-001", signer_name="Jane Doe", signer_place="Portland, ME"
        )
        session.ssl.get.assert_called_once_with("ORDER-001")
        assert wf.order is order
        assert wf._signer_name == "Jane Doe"
        assert wf._signer_place == "Portland, ME"
