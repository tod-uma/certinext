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

from certinext.catalog import ProductCategory
from certinext.client import CertiNextClient
from certinext.ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    SslAccessor,
    SslOrder,
    _matches_variant,
)

_SSL_BASE = "/api/certinext/v2/ssl"


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


# Catalog fixture used to pre-populate SslAccessor._catalog_cache in tests
_CATALOG_FIXTURE: list[ProductCategory] = [
    ProductCategory({
        "categoryName": "SSL/TLS Certificates",
        "categoryID": "3",
        "currencyType": "USD",
        "products": [
            {"productCode": "842", "productName": "DV SSL Certificate"},
            {"productCode": "843", "productName": "DV Wildcard SSL Certificate"},
            {"productCode": "844", "productName": "DV UCC Certificate"},
            {"productCode": "845", "productName": "DV Wildcard UCC Certificate"},
            {"productCode": "846", "productName": "OV SSL Certificate"},
            {"productCode": "847", "productName": "OV Wildcard SSL Certificate"},
            {"productCode": "848", "productName": "OV UCC Certificate"},
            {"productCode": "849", "productName": "OV Wildcard UCC Certificate"},
            {"productCode": "850", "productName": "EV SSL Certificate"},
            {"productCode": "851", "productName": "EV UCC Certificate"},
        ],
    })
]

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
# _matches_variant
# ---------------------------------------------------------------------------

class TestMatchesVariant:
    """_matches_variant correctly identifies SSL product variants by name."""

    def test_dv_ssl_matches_dv_not_wildcard_not_ucc(self):
        """'DV SSL Certificate' matches DV non-wildcard non-UCC."""
        assert _matches_variant("DV SSL Certificate", "DV", wildcard=False, ucc=False)

    def test_dv_wildcard_matches_wildcard(self):
        """'DV Wildcard SSL Certificate' matches DV wildcard non-UCC."""
        assert _matches_variant("DV Wildcard SSL Certificate", "DV", wildcard=True, ucc=False)

    def test_dv_ucc_matches_ucc(self):
        """'DV UCC Certificate' matches DV non-wildcard UCC."""
        assert _matches_variant("DV UCC Certificate", "DV", wildcard=False, ucc=True)

    def test_dv_wildcard_ucc_matches_both(self):
        """'DV Wildcard UCC Certificate' matches DV wildcard UCC."""
        assert _matches_variant("DV Wildcard UCC Certificate", "DV", wildcard=True, ucc=True)

    def test_ov_ssl_matches_ov(self):
        """'OV SSL Certificate' matches OV non-wildcard non-UCC."""
        assert _matches_variant("OV SSL Certificate", "OV", wildcard=False, ucc=False)

    def test_ev_ssl_matches_ev(self):
        """'EV SSL Certificate' matches EV non-wildcard non-UCC."""
        assert _matches_variant("EV SSL Certificate", "EV", wildcard=False, ucc=False)

    def test_ev_ucc_matches_ev_ucc(self):
        """'EV UCC Certificate' matches EV non-wildcard UCC."""
        assert _matches_variant("EV UCC Certificate", "EV", wildcard=False, ucc=True)

    def test_dv_wildcard_does_not_match_dv_ssl(self):
        """'DV Wildcard SSL Certificate' does NOT match DV non-wildcard."""
        assert not _matches_variant("DV Wildcard SSL Certificate", "DV", wildcard=False, ucc=False)

    def test_dv_ssl_does_not_match_wildcard(self):
        """'DV SSL Certificate' does NOT match DV wildcard."""
        assert not _matches_variant("DV SSL Certificate", "DV", wildcard=True, ucc=False)

    def test_dv_ucc_does_not_match_wildcard_ucc(self):
        """'DV UCC Certificate' does NOT match DV wildcard UCC."""
        assert not _matches_variant("DV UCC Certificate", "DV", wildcard=True, ucc=True)

    def test_ov_does_not_match_dv_query(self):
        """'OV SSL Certificate' does NOT match DV."""
        assert not _matches_variant("OV SSL Certificate", "DV", wildcard=False, ucc=False)

    def test_case_insensitive_matching(self):
        """Matching is case-insensitive (product names come from the API as mixed case)."""
        assert _matches_variant("dv ssl certificate", "DV", wildcard=False, ucc=False)
        assert _matches_variant("DV WILDCARD SSL CERTIFICATE", "dv", wildcard=True, ucc=False)


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
        """refresh() GETs /ssl/{orderId}."""
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
        """get_dcv() GETs /ssl/{orderId}/dcv."""
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
        """verify_dcv() POSTs to /ssl/{orderId}/dcv/verify."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({"status": "ok"})
        order.verify_dcv()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/dcv/verify")

    def test_submit_csr_puts_to_csr_endpoint(self):
        """submit_csr() PUTs to /ssl/{orderId}/csr with the CSR body."""
        order, mock_session = self._make_order()
        mock_session.put.return_value = _ok_response({})
        order.submit_csr("-----BEGIN CERTIFICATE REQUEST-----\n...")
        url = mock_session.put.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/csr")
        _, kwargs = mock_session.put.call_args
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_accept_agreement_posts_to_agreement_endpoint(self):
        """accept_agreement() POSTs to /ssl/{orderId}/agreement."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.accept_agreement()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/agreement")

    def test_download_certificate_gets_certificate_endpoint(self):
        """download_certificate() GETs /ssl/{orderId}/certificate."""
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
        """cancel() POSTs to /ssl/{orderId}/cancel."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.cancel()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/cancel")

    def test_reject_posts_to_reject_endpoint(self):
        """reject() POSTs to /ssl/{orderId}/reject."""
        order, mock_session = self._make_order()
        mock_session.post.return_value = _ok_response({})
        order.reject()
        url = mock_session.post.call_args[0][0]
        assert url.endswith(f"{_SSL_BASE}/ORDER-001/reject")

    def test_revoke_posts_to_revoke_endpoint(self):
        """revoke() POSTs to /ssl/{orderId}/revoke."""
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
# SslAccessor — product code resolution
# ---------------------------------------------------------------------------

class TestSslAccessorProductCodeResolution:
    """SslAccessor._get_product_code resolves codes from the catalog."""

    def _make_accessor(self) -> SslAccessor:
        client, _ = _make_client()
        accessor = SslAccessor(client)
        accessor._catalog_cache = _CATALOG_FIXTURE
        return accessor

    def test_resolves_dv_ssl(self):
        """_get_product_code('DV', wildcard=False, ucc=False) → 842."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("DV", wildcard=False, ucc=False) == "842"

    def test_resolves_dv_wildcard(self):
        """_get_product_code('DV', wildcard=True, ucc=False) → 843."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("DV", wildcard=True, ucc=False) == "843"

    def test_resolves_dv_ucc(self):
        """_get_product_code('DV', wildcard=False, ucc=True) → 844."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("DV", wildcard=False, ucc=True) == "844"

    def test_resolves_dv_wildcard_ucc(self):
        """_get_product_code('DV', wildcard=True, ucc=True) → 845."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("DV", wildcard=True, ucc=True) == "845"

    def test_resolves_ov_ssl(self):
        """_get_product_code('OV', wildcard=False, ucc=False) → 846."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("OV", wildcard=False, ucc=False) == "846"

    def test_resolves_ov_wildcard(self):
        """_get_product_code('OV', wildcard=True, ucc=False) → 847."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("OV", wildcard=True, ucc=False) == "847"

    def test_resolves_ov_ucc(self):
        """_get_product_code('OV', wildcard=False, ucc=True) → 848."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("OV", wildcard=False, ucc=True) == "848"

    def test_resolves_ov_wildcard_ucc(self):
        """_get_product_code('OV', wildcard=True, ucc=True) → 849."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("OV", wildcard=True, ucc=True) == "849"

    def test_resolves_ev_ssl(self):
        """_get_product_code('EV', wildcard=False, ucc=False) → 850."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("EV", wildcard=False, ucc=False) == "850"

    def test_resolves_ev_ucc(self):
        """_get_product_code('EV', wildcard=False, ucc=True) → 851."""
        accessor = self._make_accessor()
        assert accessor._get_product_code("EV", wildcard=False, ucc=True) == "851"

    def test_raises_lookup_error_when_product_missing(self):
        """_get_product_code raises LookupError when no matching product exists."""
        client, _ = _make_client()
        accessor = SslAccessor(client)
        accessor._catalog_cache = []  # empty catalog
        with pytest.raises(LookupError, match="No.*product found in catalog"):
            accessor._get_product_code("DV", wildcard=False, ucc=False)

    def test_lookup_error_message_lists_available_products(self):
        """The LookupError message includes available product names."""
        client, _ = _make_client()
        accessor = SslAccessor(client)
        accessor._catalog_cache = [
            ProductCategory({
                "products": [{"productCode": "850", "productName": "EV SSL Certificate"}]
            })
        ]
        with pytest.raises(LookupError, match="EV SSL Certificate"):
            accessor._get_product_code("DV", wildcard=False, ucc=False)


class TestSslAccessorCatalogCaching:
    """SslAccessor._load_catalog caches the result after the first call."""

    def test_catalog_loaded_lazily_on_first_create(self):
        """Catalog is not fetched until a create_* method is called."""
        client, mock_session = _make_client()
        accessor = SslAccessor(client)
        assert accessor._catalog_cache is None

    def test_catalog_cached_after_load(self):
        """_load_catalog() stores the result in _catalog_cache."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({
            "products": [{"categoryName": "SSL", "products": [
                {"productCode": "842", "productName": "DV SSL Certificate"}
            ]}]
        })
        accessor = SslAccessor(client)
        accessor._load_catalog()
        assert accessor._catalog_cache is not None
        # Second call must not make another HTTP request
        accessor._load_catalog()
        assert mock_session.get.call_count == 1


# ---------------------------------------------------------------------------
# SslAccessor — create methods
# ---------------------------------------------------------------------------

class TestSslAccessorCreateMethods:
    """SslAccessor create_* methods post to the correct endpoints with product codes."""

    def _make_accessor(self) -> tuple[SslAccessor, MagicMock]:
        client, mock_session = _make_client()
        accessor = SslAccessor(client)
        accessor._catalog_cache = _CATALOG_FIXTURE
        return accessor, mock_session

    def _assert_create(self, mock_session: MagicMock, path_suffix: str, product_code: str) -> None:
        url = mock_session.post.call_args[0][0]
        assert url.endswith(path_suffix), f"Expected URL ending with {path_suffix!r}, got {url!r}"
        _, kwargs = mock_session.post.call_args
        assert kwargs["headers"].get("X-Product-Code") == product_code

    def test_create_dv_posts_to_dv_with_code_842(self):
        """create_dv() POSTs to /ssl/dv with X-Product-Code: 842."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com")
        self._assert_create(mock_session, f"{_SSL_BASE}/dv", "842")

    def test_create_dv_includes_domain_in_body(self):
        """create_dv() includes the domain in the request body."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", validity=730)
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["domain"] == "example.com"
        assert kwargs["json"]["validity"] == 730

    def test_create_dv_wildcard_posts_to_dv_wildcard_with_code_843(self):
        """create_dv_wildcard() POSTs to /ssl/dv/wildcard with X-Product-Code: 843."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard("*.example.com")
        self._assert_create(mock_session, f"{_SSL_BASE}/dv/wildcard", "843")

    def test_create_dv_ucc_posts_to_dv_ucc_with_code_844(self):
        """create_dv_ucc() POSTs to /ssl/dv/ucc with X-Product-Code: 844."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["example.com", "www.example.com"])
        self._assert_create(mock_session, f"{_SSL_BASE}/dv/ucc", "844")

    def test_create_dv_wildcard_ucc_posts_with_code_845(self):
        """create_dv_wildcard_ucc() uses code 845."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_wildcard_ucc(["*.example.com"])
        self._assert_create(mock_session, f"{_SSL_BASE}/dv/wildcard-ucc", "845")

    def test_create_ov_posts_with_code_846_and_org_id(self):
        """create_ov() uses code 846 and includes organizationId in the body."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ov", "846")
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["organizationId"] == "ORG-001"

    def test_create_ov_wildcard_posts_with_code_847(self):
        """create_ov_wildcard() uses code 847."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard("*.example.com", organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ov/wildcard", "847")

    def test_create_ov_ucc_posts_with_code_848(self):
        """create_ov_ucc() uses code 848."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ov/ucc", "848")

    def test_create_ov_wildcard_ucc_posts_with_code_849(self):
        """create_ov_wildcard_ucc() uses code 849."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ov_wildcard_ucc(["*.example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ov/wildcard-ucc", "849")

    def test_create_ev_posts_with_code_850(self):
        """create_ev() uses code 850."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev("example.com", organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ev", "850")

    def test_create_ev_ucc_posts_with_code_851(self):
        """create_ev_ucc() uses code 851."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_ev_ucc(["example.com"], organization_id="ORG-001")
        self._assert_create(mock_session, f"{_SSL_BASE}/ev/ucc", "851")

    def test_create_dv_returns_ssl_order(self):
        """create_dv() returns an SslOrder instance."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        order = accessor.create_dv("example.com")
        assert isinstance(order, SslOrder)
        assert order.order_id == "ORDER-001"

    def test_create_dv_optional_csr_included_in_body(self):
        """create_dv() includes csr in the body when provided."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv("example.com", csr="-----BEGIN CERTIFICATE REQUEST-----\n...")
        _, kwargs = mock_session.post.call_args
        assert "-----BEGIN CERTIFICATE REQUEST-----" in kwargs["json"]["csr"]

    def test_create_ucc_uses_domains_not_domain(self):
        """create_dv_ucc() sends 'domains' (plural) in the body, not 'domain'."""
        accessor, mock_session = self._make_accessor()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        accessor.create_dv_ucc(["a.com", "b.com"])
        _, kwargs = mock_session.post.call_args
        assert kwargs["json"]["domains"] == ["a.com", "b.com"]
        assert "domain" not in kwargs["json"]


# ---------------------------------------------------------------------------
# SslAccessor.get
# ---------------------------------------------------------------------------

class TestSslAccessorGet:
    """SslAccessor.get() fetches an existing order by ID."""

    def test_get_calls_ssl_order_endpoint(self):
        """get() GETs /ssl/{orderId}."""
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
