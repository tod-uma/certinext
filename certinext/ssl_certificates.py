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

"""SSL/TLS Certificates API: full certificate lifecycle.

Covers all ten creation variants (DV, OV, EV; single-domain, wildcard, UCC,
and wildcard-UCC), order tracking, DCV challenges, CSR submission, agreement
acceptance, certificate download, cancellation, rejection, revocation, and
reissue.

Product codes are resolved at runtime from
:meth:`certinext.catalog.CatalogAccessor.list_products` and cached per
:class:`SslAccessor` instance, so they always reflect the current account's
enabled products rather than hardcoded values.
"""

import re
from typing import TYPE_CHECKING, Any, Literal

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

if TYPE_CHECKING:
    from .catalog import ProductCategory

_SSL_BASE = "/api/certinext/v2/ssl"

SslOrderStatus = Literal[
    "pending-dcv",
    "pending-organization-verification",
    "pending-csr",
    "pending-documents",
    "pending-agreement",
    "pending-approval",
    "issued",
    "revoked",
    "cancelled",
    "rejected",
    "expired",
    "unknown",
]
"""Valid ``status`` values returned by :attr:`SslOrder.status`."""

ReissueMode = Literal["rekey", "update-sans"]
"""Valid reissue modes accepted by :meth:`SslOrder.reissue`."""


def _matches_variant(product_name: str, validation_type: str, wildcard: bool, ucc: bool) -> bool:
    """Return True if a catalog product name matches the requested SSL variant.

    Matches by splitting the product name on word boundaries and checking that:
    - the validation type (DV, OV, EV) is present as a whole word
    - the presence/absence of "WILDCARD" and "UCC" tokens matches the flags

    Args:
        product_name: Product name string from the catalog (e.g. "DV SSL Certificate").
        validation_type: Uppercase validation type: ``"DV"``, ``"OV"``, or ``"EV"``.
        wildcard: Whether the product should include "Wildcard" in its name.
        ucc: Whether the product should include "UCC" in its name.

    Returns:
        ``True`` if the product name matches all variant criteria.
    """
    tokens = set(re.split(r"\W+", product_name.upper()))
    has_type = validation_type.upper() in tokens
    has_wildcard = "WILDCARD" in tokens
    has_ucc = "UCC" in tokens
    return has_type and has_wildcard == wildcard and has_ucc == ucc


class DcvChallenge:
    """DCV challenge for a single domain in an SSL order.

    Instances are returned by :meth:`SslOrder.get_dcv`. Publish the
    :attr:`token` at the :attr:`host` using the :attr:`method` before
    calling :meth:`SslOrder.verify_dcv`.

    Example::

        challenges = order.get_dcv()
        for c in challenges:
            print(c.domain, c.method, c.host, c.token)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict for this challenge.
        """
        self._data = data

    @property
    def domain(self) -> str | None:
        """The domain name this challenge applies to."""
        return self._data.get("domain") or self._data.get("domainName")

    @property
    def method(self) -> str | None:
        """DCV method in upper case (e.g. ``"DNS-TXT"``, ``"HTTP-URL"``)."""
        raw = self._data.get("dcvMethod") or self._data.get("method") or ""
        return raw.upper() if raw else None

    @property
    def token(self) -> str | None:
        """Challenge token to publish (TXT record content or HTTP file content)."""
        return (
            self._data.get("txtToken")
            or self._data.get("fileToken")
            or self._data.get("token")
            or self._data.get("dnsContents")
            or None
        )

    @property
    def host(self) -> str | None:
        """DNS sub-domain or HTTP path where the challenge must be published."""
        return self._data.get("dnsHost") or self._data.get("host") or None

    @property
    def value(self) -> str | None:
        """Challenge value (alias for :attr:`token`; present on some API versions)."""
        return self._data.get("value") or self.token

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this challenge."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"DcvChallenge(domain={self.domain!r}, method={self.method!r}, host={self.host!r})"


class CertificateDownload:
    """Downloaded certificate in JSON format.

    Returned by :meth:`SslOrder.download_certificate` (JSON format). Contains
    the PEM-encoded end-entity certificate and intermediate chain.

    For raw PEM text use :meth:`SslOrder.download_certificate_pem`; for binary
    DER use :meth:`SslOrder.download_certificate_der`.

    Example::

        cert = order.download_certificate()
        with open("cert.pem", "w") as f:
            f.write(cert.certificate_pem or "")
        for pem in cert.chain_pem:
            f.write(pem)
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API response dict from the certificate download endpoint.
        """
        self._data = data

    @property
    def order_id(self) -> str | None:
        """Order ID this certificate belongs to."""
        return self._data.get("orderId")

    @property
    def serial_number(self) -> str | None:
        """Certificate serial number."""
        return self._data.get("serialNumber")

    @property
    def subject(self) -> str | None:
        """Certificate subject distinguished name."""
        return self._data.get("subject")

    @property
    def issuer(self) -> str | None:
        """Certificate issuer distinguished name."""
        return self._data.get("issuer")

    @property
    def not_before(self) -> str | None:
        """Certificate validity start timestamp (ISO 8601)."""
        return self._data.get("notBefore")

    @property
    def not_after(self) -> str | None:
        """Certificate validity end timestamp (ISO 8601)."""
        return self._data.get("notAfter")

    @property
    def certificate_pem(self) -> str | None:
        """PEM-encoded end-entity certificate."""
        return self._data.get("certificatePem")

    @property
    def chain_pem(self) -> list[str]:
        """List of PEM-encoded intermediate CA certificates."""
        val = self._data.get("chainPem")
        return val if isinstance(val, list) else []

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"CertificateDownload(order_id={self.order_id!r}, "
            f"serial_number={self.serial_number!r}, "
            f"not_after={self.not_after!r})"
        )


class SslOrder:
    """Represents a CertiNext SSL/TLS certificate order.

    Instances are returned by :class:`SslAccessor` create methods and
    :meth:`SslAccessor.get`. They should not be constructed directly.

    Lifecycle methods (:meth:`refresh`, :meth:`get_dcv`, :meth:`verify_dcv`,
    :meth:`submit_csr`, :meth:`accept_agreement`, :meth:`download_certificate`,
    :meth:`cancel`, :meth:`reject`, :meth:`revoke`, :meth:`reissue`) call the
    API directly.

    Typical DV flow::

        order = sess.ssl.create_dv("example.com", validity=365)
        for challenge in order.get_dcv():
            print(f"Add TXT record: {challenge.host}  {challenge.token}")
        # ... publish DNS challenge ...
        order.verify_dcv()
        order.submit_csr(csr_pem)
        order.accept_agreement()
        cert = order.download_certificate()
        print(cert.certificate_pem)
    """

    def __init__(self, client: CertiNextClient, data: dict[str, Any]) -> None:
        """
        Args:
            client: The underlying HTTP client used for subsequent API calls.
            data: Raw API response dict for this order.
        """
        self._client = client
        self._data: dict[str, Any] = data

    # --- properties ---

    @property
    def order_id(self) -> str | None:
        """Unique order identifier assigned by CertiNext."""
        return self._data.get("orderId")

    @property
    def request_id(self) -> str | None:
        """Request identifier associated with this order."""
        return self._data.get("requestId")

    @property
    def status(self) -> SslOrderStatus | None:
        """Current order status. See `SslOrderStatus` for valid values."""
        return self._data.get("status")

    @property
    def product_variant(self) -> str | None:
        """Certificate product variant (e.g. ``"dv"``, ``"ov"``, ``"ev"``)."""
        return self._data.get("productVariant")

    @property
    def domain(self) -> str | None:
        """Primary domain name (common name) for single-domain certificate types."""
        return self._data.get("domain")

    @property
    def additional_domains(self) -> list[str]:
        """Additional subject-alternative-name domains for this order."""
        val = self._data.get("additionalDomains")
        return val if isinstance(val, list) else []

    @property
    def created_at(self) -> str | None:
        """Order creation timestamp as an ISO 8601 string."""
        return self._data.get("createdAt")

    # --- helpers ---

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this order."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"SslOrder(order_id={self.order_id!r}, "
            f"domain={self.domain!r}, "
            f"status={self.status!r})"
        )

    # --- lifecycle API methods ---

    def refresh(self) -> "SslOrder":
        """Re-fetch this order from the API and update all properties in place.

        Returns:
            ``self``, allowing method chaining.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_SSL_BASE}/{self.order_id}")
        if isinstance(result, dict):
            self._data = result
        return self

    def get_dcv(self) -> list[DcvChallenge]:
        """Return the DCV challenges for all domains in this order.

        Returns:
            List of :class:`DcvChallenge` objects, one per domain requiring
            validation. Publish each challenge, then call :meth:`verify_dcv`.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_SSL_BASE}/{self.order_id}/dcv")
        raw: list[Any] = []
        if isinstance(result, list):
            raw = result
        elif isinstance(result, dict):
            challenges = result.get("challenges", [])
            if isinstance(challenges, list):
                raw = challenges
            else:
                for val in result.values():
                    if isinstance(val, list):
                        raw = val
                        break
        return [DcvChallenge(item) for item in raw]

    def verify_dcv(self) -> dict[str, Any]:
        """Trigger DCV verification for all domains in this order.

        Call after publishing all DCV challenges returned by :meth:`get_dcv`.
        Call :meth:`refresh` and check :attr:`status` to confirm the outcome.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/dcv/verify")

    def submit_csr(self, csr: str) -> dict[str, Any]:
        """Submit a Certificate Signing Request for this order.

        Args:
            csr: PEM-encoded Certificate Signing Request string.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.put(f"{_SSL_BASE}/{self.order_id}/csr", json={"csr": csr})

    def accept_agreement(self) -> dict[str, Any]:
        """Accept the subscriber agreement for this order.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/agreement")

    def download_certificate(self) -> CertificateDownload:
        """Download the issued certificate in JSON format.

        Returns:
            :class:`CertificateDownload` with the PEM-encoded certificate and
            chain. Use :meth:`download_certificate_pem` or
            :meth:`download_certificate_der` for other formats.

        Raises:
            CertiNextAPIError: On a non-2xx API response (404 if not yet issued).
                Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_SSL_BASE}/{self.order_id}/certificate")
        return CertificateDownload(result if isinstance(result, dict) else {})

    def download_certificate_pem(self) -> str:
        """Download the issued certificate bundle as a PEM text string.

        Returns:
            PEM-encoded certificate chain as a UTF-8 string.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw = self._client.get_bytes(
            f"{_SSL_BASE}/{self.order_id}/certificate",
            accept="application/x-pem-file",
        )
        return raw.decode("utf-8")

    def download_certificate_der(self) -> bytes:
        """Download the issued certificate in DER (binary) format.

        Returns:
            DER-encoded certificate as raw bytes.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.get_bytes(
            f"{_SSL_BASE}/{self.order_id}/certificate",
            accept="application/pkix-cert",
        )

    def cancel(self) -> dict[str, Any]:
        """Cancel this certificate order.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/cancel")

    def reject(self) -> dict[str, Any]:
        """Reject this draft certificate order.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/reject")

    def revoke(self, reason: str | None = None) -> dict[str, Any]:
        """Revoke this issued certificate.

        Args:
            reason: Optional revocation reason string (e.g. ``"keyCompromise"``).
                If ``None``, the API default reason is used.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/revoke", json=body or None)

    def reissue(
        self,
        mode: ReissueMode,
        csr: str | None = None,
        additional_domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Reissue this certificate.

        Args:
            mode: ``"rekey"`` to reissue with a new key pair (requires ``csr``);
                ``"update-sans"`` to add SANs without rekeying (requires
                ``additional_domains``).
            csr: PEM-encoded CSR. Required when ``mode="rekey"``.
            additional_domains: List of additional domain names to add as SANs.
                Required when ``mode="update-sans"``.

        Returns:
            Raw API response dict.

        Raises:
            ValueError: If required arguments for the selected ``mode`` are missing.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if mode == "rekey" and csr is None:
            raise ValueError("csr is required when mode='rekey'")
        if mode == "update-sans" and additional_domains is None:
            raise ValueError("additional_domains is required when mode='update-sans'")
        body: dict[str, Any] = {"mode": mode}
        if csr is not None:
            body["csr"] = csr
        if additional_domains is not None:
            body["additionalDomains"] = additional_domains
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/reissue", json=body)


class SslAccessor:
    """Accessor for the CertiNext SSL/TLS Certificates API.

    Mounted on a session as ``session.ssl``. Provides ten certificate creation
    methods (one per product variant) and a :meth:`get` method for tracking
    existing orders. Returned :class:`SslOrder` instances expose the full
    certificate lifecycle as methods.

    Product codes are resolved from the Catalog API (``GET /catalog/products``)
    the first time any ``create_*`` method is called. The resolved codes are
    cached per accessor instance so the catalog is queried at most once per
    session.

    OV and EV methods require an ``organization_id`` from
    :meth:`certinext.accounts.AccountAccessor.list_organizations`.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        order = sess.ssl.create_dv("example.com", validity=365)
        for challenge in order.get_dcv():
            print(f"Add TXT record: {challenge.host}  {challenge.token}")
        order.verify_dcv()
        order.submit_csr(csr_pem)
        order.accept_agreement()
        cert = order.download_certificate()
        print(cert.certificate_pem)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client
        self._catalog_cache: list["ProductCategory"] | None = None

    # --- product code resolution ---

    def _load_catalog(self) -> list["ProductCategory"]:
        """Fetch and cache product categories from the Catalog API.

        Returns:
            Cached list of :class:`~certinext.catalog.ProductCategory` objects.
        """
        if self._catalog_cache is None:
            from .catalog import CatalogAccessor
            self._catalog_cache = CatalogAccessor(self._client).list_products()
        return self._catalog_cache

    def _get_product_code(self, validation_type: str, wildcard: bool, ucc: bool) -> str:
        """Resolve the product code for an SSL variant from the catalog.

        Queries the catalog (once per session, cached) and returns the first
        product code whose name matches the requested validation type and
        variant flags via :func:`_matches_variant`.

        Args:
            validation_type: Uppercase validation tier: ``"DV"``, ``"OV"``, or ``"EV"``.
            wildcard: Whether the desired product is a wildcard certificate.
            ucc: Whether the desired product is a UCC (multi-domain) certificate.

        Returns:
            Product code string (e.g. ``"842"``).

        Raises:
            LookupError: If no matching product is found in the catalog. The error
                message lists the available product names.
        """
        categories = self._load_catalog()
        for cat in categories:
            for product in cat.products:
                if product.product_code and product.product_name:
                    if _matches_variant(product.product_name, validation_type, wildcard, ucc):
                        return product.product_code
        available = [p.product_name for cat in categories for p in cat.products if p.product_name]
        variant_desc = (
            f"{validation_type}"
            f"{' Wildcard' if wildcard else ''}"
            f"{' UCC' if ucc else ''}"
        ).strip()
        raise LookupError(
            f"No {variant_desc!r} product found in catalog. "
            f"Available products: {available}"
        )

    # --- internal create helper ---

    def _create(self, product_code: str, path: str, body: dict[str, Any]) -> SslOrder:
        """POST a create request with the X-Product-Code header.

        Args:
            product_code: Numeric product code string for ``X-Product-Code``.
            path: Sub-path under ``/api/certinext/v2/ssl`` (e.g. ``/dv``).
            body: JSON request body.

        Returns:
            :class:`SslOrder` wrapping the API response.
        """
        data = self._client.post(
            f"{_SSL_BASE}{path}",
            json=body,
            extra_headers={"X-Product-Code": product_code},
        )
        return SslOrder(self._client, data)

    @staticmethod
    def _single_domain_body(
        domain: str,
        validity: int,
        additional_domains: list[str] | None,
        csr: str | None,
        auto_renew: bool,
        custom_fields: dict[str, Any] | None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Build the JSON body for single-domain certificate creation requests."""
        body: dict[str, Any] = {"domain": domain, "validity": validity, "autoRenew": auto_renew}
        if additional_domains is not None:
            body["additionalDomains"] = additional_domains
        if csr is not None:
            body["csr"] = csr
        if custom_fields is not None:
            body["customFields"] = custom_fields
        body.update(extra)
        return body

    @staticmethod
    def _multi_domain_body(
        domains: list[str],
        validity: int,
        csr: str | None,
        auto_renew: bool,
        custom_fields: dict[str, Any] | None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Build the JSON body for multi-domain (UCC) certificate creation requests."""
        body: dict[str, Any] = {"domains": domains, "validity": validity, "autoRenew": auto_renew}
        if csr is not None:
            body["csr"] = csr
        if custom_fields is not None:
            body["customFields"] = custom_fields
        body.update(extra)
        return body

    # --- create methods ---

    def create_dv(
        self,
        domain: str,
        validity: int = 365,
        additional_domains: list[str] | None = None,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV (Domain Validated) single-domain certificate order.

        No organization validation required. Product code resolved from catalog.

        Args:
            domain: Primary FQDN (e.g. ``"example.com"``).
            validity: Certificate validity in days (default: 365).
            additional_domains: Optional list of additional SAN domains.
            csr: Optional PEM-encoded CSR. If omitted, submit later via
                :meth:`SslOrder.submit_csr`.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` with status ``"pending-dcv"`` (or a later stage if
            the domain is already validated).

        Raises:
            LookupError: If the DV SSL product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("DV", wildcard=False, ucc=False)
        return self._create(
            code, "/dv",
            self._single_domain_body(domain, validity, additional_domains, csr, auto_renew, custom_fields),
        )

    def create_dv_wildcard(
        self,
        domain: str,
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV wildcard certificate order.

        ``domain`` must start with ``*.``. Product code resolved from catalog.

        Args:
            domain: Wildcard FQDN (e.g. ``"*.example.com"``).
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the wildcard certificate.

        Raises:
            LookupError: If the DV Wildcard product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("DV", wildcard=True, ucc=False)
        return self._create(
            code, "/dv/wildcard",
            self._single_domain_body(domain, validity, None, csr, auto_renew, custom_fields),
        )

    def create_dv_ucc(
        self,
        domains: list[str],
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV UCC (multi-domain / Unified Communications) certificate order.

        Product code resolved from catalog.

        Args:
            domains: List of all FQDNs to include as SANs.
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the multi-domain certificate.

        Raises:
            LookupError: If the DV UCC product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("DV", wildcard=False, ucc=True)
        return self._create(
            code, "/dv/ucc",
            self._multi_domain_body(domains, validity, csr, auto_renew, custom_fields),
        )

    def create_dv_wildcard_ucc(
        self,
        domains: list[str],
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV wildcard UCC certificate order.

        ``domains`` may contain wildcard entries such as ``"*.example.com"``.
        Product code resolved from catalog.

        Args:
            domains: List of all FQDNs (may include wildcard entries).
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the wildcard UCC certificate.

        Raises:
            LookupError: If the DV Wildcard UCC product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("DV", wildcard=True, ucc=True)
        return self._create(
            code, "/dv/wildcard-ucc",
            self._multi_domain_body(domains, validity, csr, auto_renew, custom_fields),
        )

    def create_ov(
        self,
        domain: str,
        organization_id: str,
        validity: int = 365,
        additional_domains: list[str] | None = None,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV (Organization Validated) single-domain certificate order.

        Requires a pre-vetted ``organization_id`` from
        :meth:`certinext.accounts.AccountAccessor.list_organizations`.
        Product code resolved from catalog.

        Args:
            domain: Primary FQDN.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            additional_domains: Optional list of additional SAN domains.
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the OV certificate.

        Raises:
            LookupError: If the OV SSL product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("OV", wildcard=False, ucc=False)
        return self._create(
            code, "/ov",
            self._single_domain_body(
                domain, validity, additional_domains, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def create_ov_wildcard(
        self,
        domain: str,
        organization_id: str,
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV wildcard certificate order.

        ``domain`` must start with ``*.``. Product code resolved from catalog.

        Args:
            domain: Wildcard FQDN (e.g. ``"*.example.com"``).
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the OV wildcard certificate.

        Raises:
            LookupError: If the OV Wildcard product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("OV", wildcard=True, ucc=False)
        return self._create(
            code, "/ov/wildcard",
            self._single_domain_body(
                domain, validity, None, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def create_ov_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV UCC (multi-domain) certificate order.

        Product code resolved from catalog.

        Args:
            domains: List of all FQDNs to include.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the OV multi-domain certificate.

        Raises:
            LookupError: If the OV UCC product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("OV", wildcard=False, ucc=True)
        return self._create(
            code, "/ov/ucc",
            self._multi_domain_body(
                domains, validity, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def create_ov_wildcard_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV wildcard UCC certificate order.

        Product code resolved from catalog.

        Args:
            domains: List of all FQDNs (may include wildcard entries).
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the OV wildcard UCC certificate.

        Raises:
            LookupError: If the OV Wildcard UCC product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("OV", wildcard=True, ucc=True)
        return self._create(
            code, "/ov/wildcard-ucc",
            self._multi_domain_body(
                domains, validity, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def create_ev(
        self,
        domain: str,
        organization_id: str,
        validity: int = 365,
        additional_domains: list[str] | None = None,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an EV (Extended Validation) single-domain certificate order.

        Requires a pre-vetted ``organization_id`` from
        :meth:`certinext.accounts.AccountAccessor.list_organizations`.
        Product code resolved from catalog.

        Args:
            domain: Primary FQDN.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            additional_domains: Optional list of additional SAN domains.
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the EV certificate.

        Raises:
            LookupError: If the EV SSL product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("EV", wildcard=False, ucc=False)
        return self._create(
            code, "/ev",
            self._single_domain_body(
                domain, validity, additional_domains, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def create_ev_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity: int = 365,
        csr: str | None = None,
        auto_renew: bool = False,
        custom_fields: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an EV UCC (multi-domain) certificate order.

        Product code resolved from catalog.

        Args:
            domains: List of all FQDNs to include.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity: Certificate validity in days (default: 365).
            csr: Optional PEM-encoded CSR.
            auto_renew: Enable automatic renewal (default: ``False``).
            custom_fields: Optional dict of product-specific custom field values.

        Returns:
            :class:`SslOrder` for the EV multi-domain certificate.

        Raises:
            LookupError: If the EV UCC product is not found in the catalog.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        code = self._get_product_code("EV", wildcard=False, ucc=True)
        return self._create(
            code, "/ev/ucc",
            self._multi_domain_body(
                domains, validity, csr, auto_renew, custom_fields,
                organizationId=organization_id,
            ),
        )

    def get(self, order_id: str) -> SslOrder:
        """Return an existing SSL order by its order ID.

        Args:
            order_id: The ``orderId`` returned when the order was created.

        Returns:
            :class:`SslOrder` reflecting the current order state.

        Raises:
            ValueError: If the API returns an unexpected (non-dict) response.
            CertiNextAPIError: On a non-2xx API response (404 if not found).
                Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_SSL_BASE}/{order_id}")
        if not isinstance(result, dict):
            raise ValueError(f"Unexpected response type for order {order_id!r}")
        return SslOrder(self._client, result)
