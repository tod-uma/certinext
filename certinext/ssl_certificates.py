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

All certificate creation uses the single ``POST /api/certinext/v2/ssl-certificates``
endpoint with the ``productVariant`` field in the request body. Certificate
validity is specified in years (1, 2, or 3). A PEM-encoded CSR may be submitted
with the initial order or separately via ``PUT /ssl-certificates/{orderId}/csr``.

.. note:: **Organization Consent Token (prevettingToken)**

    OV and EV orders include ``organization.preVetted: true`` in the request
    body. Providing the Organization Consent Token via ``prevetting_token``
    additionally allows the CA to auto-approve the order without a manual
    approver step, bypassing the ``pending-approval`` stage.

    The token is a static administrative credential — it cannot be generated
    via the REST API. To retrieve it:

    1. Log in to the CertiNext Enterprise Portal.
    2. Go to **Organization Management** (or the Organization Vetting dashboard).
    3. Select the pre-vetted organization or department the certificate is for.
    4. Look for **Organization Consent**, **Consent Tokens**, or
       **API Integration Settings** in that organization's profile.
    5. The alphanumeric string listed there is the ``prevettingToken`` value.

    If your organization uses delegated departments, use the token for the
    specific department matching the certificate request — tokens are bound
    to individual pre-vetted entities.

.. note:: **DCV not required in this environment**

    University of Maine System domains are pre-validated in CertiNext (both
    production and sandbox), so per-certificate DCV challenges are never
    required. Orders will not enter ``pending-dcv`` status in normal
    operation. The :meth:`SslOrder.get_dcv` and :meth:`SslOrder.verify_dcv`
    methods are implemented for completeness but have not been exercised
    against the UMS CertiNext account.

.. note::

    The subscriber-agreement field is named ``agreement`` in the JSON request
    body (both for order creation and the ``/agreement`` endpoint). However,
    the API's validation error messages refer to it as ``agreementDetails``
    (e.g. *"'agreementDetails' block cannot be empty"*). These names refer to
    the same field — do not rename ``agreement`` to ``agreementDetails`` in
    the request body.
"""

import logging
from typing import Any, Literal

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

log = logging.getLogger(__name__)

_SSL_BASE = "/api/certinext/v2/ssl-certificates"

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

RevocationReason = Literal[
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "privilegeWithdrawn",
]
"""Valid ``reason`` values accepted by :meth:`SslOrder.revoke`.

Maps to the RFC 5280 CRL reason code extensions supported by CertiNext.
"""


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

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display.

        Returns:
            Dict with keys ``domain``, ``method``, ``host``, ``token``.
        """
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "domain": _s(self.domain),
            "method": _s(self.method),
            "host": _s(self.host),
            "token": _s(self.token),
        }

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

        order = sess.ssl.create_dv(
            "example.com",
            validity_years=1,
            requestor_name="John Doe",
            requestor_email="john@example.com",
            requestor_phone="+12075551234",
            requestor_designation="IT Administrator",
        )
        order.submit_csr(csr_pem)
        for challenge in order.get_dcv():
            print(f"Add TXT record: {challenge.host}  {challenge.token}")
        # ... publish DNS challenge ...
        order.verify_dcv()
        order.accept_agreement(signer_name="John Doe", signer_place="Portland, ME")
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

    @property
    def csr_submitted(self) -> bool:
        """Whether a CSR has been submitted for this order.

        ``True`` once :meth:`submit_csr` has been called successfully.
        The order cannot progress to issuance until this is ``True``.
        """
        return bool(self._data.get("csrSubmitted", False))

    @property
    def order_state(self) -> str | None:
        """Human-readable order status from the legacy pipeline.

        Examples: ``"Order Accepted"``, ``"Approved by System"``.
        This is a complement to the typed :attr:`status` field; both can be
        logged together to understand where an order is in the CA's internal
        workflow.
        """
        return self._data.get("orderState")

    @property
    def certificate_state(self) -> str | None:
        """Human-readable certificate/request status from the legacy pipeline.

        Examples: ``"Pending for Approver"``, ``"Certificate Generated"``,
        ``"Certificate Downloaded"``. A certificate is ready to download when
        this reads ``"Certificate Generated"`` (or similar). If this field is
        not ``"Certificate Generated"`` while :attr:`status` is ``"issued"``,
        the CA has approved the order but has not yet signed the certificate —
        typically because the CSR was not submitted through the normal
        ``pending-csr`` stage.
        """
        return self._data.get("certificateState")

    @property
    def all_domains(self) -> list[str]:
        """All domains covered by this order: primary domain followed by additional domains.

        Combines :attr:`domain` and :attr:`additional_domains` into a single list.
        Returns an empty list for orders where neither field is set.
        """
        result: list[str] = []
        if self.domain:
            result.append(self.domain)
        result.extend(self.additional_domains)
        return result

    @property
    def interim_dv_issued(self) -> bool:
        """Whether an interim DV certificate was issued for this order.

        ``True`` when the CA issued a short-lived DV certificate while an OV or
        EV order is pending organization verification. Present only on OV/EV orders
        and only when the CA offers interim issuance; ``False`` otherwise.
        """
        return bool(self._data.get("interimDvIssued", False))

    @property
    def subscriber_agreement(self) -> dict[str, Any] | None:
        """The subscriber agreement block returned for this order, or ``None``.

        Returns the raw ``subscriberAgreement`` dict from the API response when
        present. Contains acceptance status, signer name, and timestamp if the
        agreement has been accepted.
        """
        val = self._data.get("subscriberAgreement")
        return val if isinstance(val, dict) else None

    # --- helpers ---

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this order."""
        return self._data

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display.

        Returns:
            Dict with keys ``order_id``, ``domain``, ``status``,
            ``product_variant``, ``created_at``.
        """
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "order_id": _s(self.order_id),
            "domain": _s(self.domain),
            "status": _s(self.status),
            "product_variant": _s(self.product_variant),
            "created_at": _s(self.created_at),
        }

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

    def get_dcv(
        self,
        domain: str | None = None,
        method: str | None = None,
    ) -> list[DcvChallenge]:
        """Return the DCV challenges for domains in this order.

        .. note::
            UMS domains are pre-validated in CertiNext; orders will not enter
            ``pending-dcv`` status and this method is not called in normal
            UMS issuance flows. It has not been tested against the UMS account.

        Args:
            domain: Filter to challenges for a specific domain name only.
                ``None`` returns challenges for all domains in the order.
            method: Filter to challenges using a specific DCV method
                (e.g. ``"DNS-TXT"``, ``"HTTP-URL"``). ``None`` returns all methods.

        Returns:
            List of :class:`DcvChallenge` objects, one per domain (or filtered
            subset). Publish each challenge, then call :meth:`verify_dcv`.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        params: dict[str, Any] = {}
        if domain is not None:
            params["domain"] = domain
        if method is not None:
            params["method"] = method
        result = self._client.get(
            f"{_SSL_BASE}/{self.order_id}/dcv",
            params=params or None,
        )
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

    def verify_dcv(self, domain: str, method: str) -> dict[str, Any]:
        """Trigger DCV verification for a specific domain and method.

        Call after publishing the DCV challenge for ``domain`` using ``method``.
        Repeat for each domain returned by :meth:`get_dcv`, then call
        :meth:`refresh` and check :attr:`status` to confirm the outcome.

        .. note::
            UMS domains are pre-validated in CertiNext; this method is not
            called in normal UMS issuance flows and has not been tested
            against the UMS account.

        Args:
            domain: The domain name to verify (must match a challenge from
                :meth:`get_dcv`).
            method: DCV method to verify (e.g. ``"DNS-TXT"``, ``"HTTP-URL"``).

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(
            f"{_SSL_BASE}/{self.order_id}/dcv/verify",
            json={"domain": domain, "method": method},
        )

    def submit_csr(self, csr: str, attested: bool = False) -> dict[str, Any]:
        """Submit a Certificate Signing Request for this order.

        Must be called after order creation when the order status is
        ``"pending-csr"``. Call :meth:`refresh` after submitting to confirm
        the order has advanced.

        Args:
            csr: PEM-encoded Certificate Signing Request string.
            attested: Whether the CSR was generated and certified according to
                the CA's attestation requirements. Defaults to ``False``;
                pass ``True`` when the CSR was generated by a hardware security
                module or other attested source.

        Returns:
            Raw API response dict (structure is opaque).

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        body: dict[str, Any] = {"csr": csr}
        if attested:
            body["attested"] = True
        return self._client.put(f"{_SSL_BASE}/{self.order_id}/csr", json=body)

    def accept_agreement(self, signer_name: str, signer_place: str) -> dict[str, Any]:
        """Accept the subscriber agreement for this order.

        Call when the order status is ``"pending-agreement"``. Call
        :meth:`refresh` after accepting to confirm the order has advanced.

        Args:
            signer_name: Full name of the person accepting the agreement.
            signer_place: City or location of the signer (e.g. ``"Portland, ME"``).

        Returns:
            Raw API response dict (structure is opaque).

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.post(
            f"{_SSL_BASE}/{self.order_id}/agreement",
            json={"agreement": {"signerName": signer_name, "signerPlace": signer_place, "accepted": True}},
        )

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

    def revoke(
        self,
        reason: RevocationReason | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Revoke this issued certificate.

        Args:
            reason: Revocation reason from :data:`RevocationReason`. If ``None``,
                the API default (``"unspecified"``) is used.
            note: Optional free-text note to record with the revocation.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        if note is not None:
            body["note"] = note
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/revoke", json=body or None)

    def reissue(
        self,
        mode: ReissueMode,
        csr: str | None = None,
        additional_domains: list[str] | None = None,
        reason: str | None = None,
        revoke_previous: bool = False,
        revoke_reason: RevocationReason | None = None,
        revoke_all_prior_reissues: bool = False,
    ) -> dict[str, Any]:
        """Reissue this certificate.

        Args:
            mode: ``"rekey"`` to reissue with a new key pair (requires ``csr``);
                ``"update-sans"`` to add SANs without rekeying (requires
                ``additional_domains``).
            csr: PEM-encoded CSR. Required when ``mode="rekey"``.
            additional_domains: List of additional domain names to add as SANs.
                Required when ``mode="update-sans"``.
            reason: Optional free-text reason for the reissue (e.g.
                ``"Key rotation"``).
            revoke_previous: When ``True``, revoke the currently-issued
                certificate as part of this reissue. Defaults to ``False``.
            revoke_reason: Revocation reason from :data:`RevocationReason` to
                use when revoking the previous certificate. Only meaningful when
                ``revoke_previous=True``.
            revoke_all_prior_reissues: When ``True``, revoke all previously
                issued certificates in the reissue chain, not just the immediately
                preceding one. Defaults to ``False``.

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
        if reason is not None:
            body["reason"] = reason
        if revoke_previous:
            body["revokePrevious"] = True
        if revoke_reason is not None:
            body["revokeReason"] = revoke_reason
        if revoke_all_prior_reissues:
            body["revokeAllPriorReissues"] = True
        return self._client.post(f"{_SSL_BASE}/{self.order_id}/reissue", json=body)


class SslAccessor:
    """Accessor for the CertiNext SSL/TLS Certificates API.

    Mounted on a session as ``session.ssl``. Provides ten certificate creation
    methods — one per product variant — and a :meth:`get` method for tracking
    existing orders. Returned :class:`SslOrder` instances expose the full
    certificate lifecycle as methods.

    The ten creation methods are:

    - :meth:`create_dv` / :meth:`create_dv_wildcard` / :meth:`create_dv_ucc` / :meth:`create_dv_wildcard_ucc`
    - :meth:`create_ov` / :meth:`create_ov_wildcard` / :meth:`create_ov_ucc` / :meth:`create_ov_wildcard_ucc`
    - :meth:`create_ev` / :meth:`create_ev_ucc`

    All creation methods post to ``POST /api/certinext/v2/ssl-certificates``
    with the appropriate ``productVariant`` in the request body. Validity is
    specified in years (1, 2, or 3). The CSR must be submitted separately via
    :meth:`SslOrder.submit_csr` after the order is created.

    OV and EV methods require an ``organization_id`` from
    :meth:`certinext.accounts.AccountAccessor.list_organizations`.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        order = sess.ssl.create_dv(
            "example.com",
            validity_years=1,
            requestor_name="John Doe",
            requestor_email="john@example.com",
            requestor_phone="+12075551234",
            requestor_designation="IT Administrator",
        )
        order.submit_csr(csr_pem)
        for challenge in order.get_dcv():
            print(f"Add TXT record: {challenge.host}  {challenge.token}")
        order.verify_dcv()
        order.accept_agreement(signer_name="John Doe", signer_place="Portland, ME")
        order.refresh()
        cert = order.download_certificate()
        print(cert.certificate_pem)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    # --- internal helpers ---

    def _create(self, body: dict[str, Any]) -> SslOrder:
        """POST to the ssl-certificates endpoint and return an SslOrder.

        Args:
            body: JSON request body including ``productVariant`` and all required fields.

        Returns:
            :class:`SslOrder` wrapping the API response.
        """
        log.debug("POST %s body: %s", _SSL_BASE, body)
        data = self._client.post(_SSL_BASE, json=body)
        return SslOrder(self._client, data)

    @staticmethod
    def _build_body(
        product_variant: str,
        domain: str,
        validity_years: int,
        requestor_name: str,
        requestor_email: str,
        requestor_phone: str,
        requestor_designation: str,
        additional_domains: list[str] | None = None,
        organization_id: str | None = None,
        prevetting_token: str | None = None,
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the JSON body for a certificate creation request.

        Args:
            product_variant: Product variant string (e.g. ``"dv"``, ``"ov-wildcard"``).
            domain: Primary FQDN for the certificate.
            validity_years: Certificate validity period in years (1, 2, or 3).
            requestor_name: Full name of the person requesting the certificate.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format (e.g. ``"+12075551234"``).
            requestor_designation: Job title or designation of the requestor.
            additional_domains: Optional SANs beyond the primary domain.
            organization_id: Organization number for OV/EV orders; ``None`` for DV.
            prevetting_token: Organization Consent Token for OV/EV orders. When
                provided alongside ``organization_id``, the CA automatically
                approves the order without a manual approver step.
            signer_name: Full name of the person accepting the subscriber agreement.
                Defaults to ``requestor_name`` when empty.
            signer_place: City or location of the signer (e.g. ``"Portland, ME"``).
            auto_secure_www: Whether to request automatic www-redirect coverage.
                Defaults to ``False``; omitting this field from the request
                causes the API to default to ``True``, so it is always sent
                explicitly.
            csr: PEM-encoded CSR to include with the initial order. When provided,
                the CA may skip the ``pending-csr`` stage entirely.
            group_number: Account sub-group to associate with this order.
                Contact your CertiNext account manager for the correct value.
            request_id: Custom request identifier for correlating this order with
                an internal ticketing or provisioning system. Must be unique per
                account.
            renew_before_days: Days before expiry to begin the renewal process.
                Sent in the ``subscription`` block. ``None`` uses the account default.
            remarks: Free-text remarks stored with the order.
            tags: Tag strings attached to the order for filtering and reporting.
            recipient_emails: Email addresses notified when the certificate is issued,
                in addition to the account's default notification settings.
            email_notifications: Email addresses included in all notification events
                for this order (creation, issuance, expiry). Overrides the account
                default notification list when provided.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email address of the technical point of contact.
            technical_poc_phone: Phone number of the technical POC in E.164 format.
            technical_poc_designation: Job title or designation of the technical POC.
            delegation: Raw delegation block as a dict. Contact your CertiNext
                account manager for the correct structure and valid values.

        Returns:
            Dict ready to be serialised as the JSON request body. The
            subscriber-agreement block is keyed as ``"agreement"`` per the API
            docs; ignore API error messages that call it ``"agreementDetails"``
            — that is a vendor-side naming inconsistency.
        """
        subscription: dict[str, Any] = {"validityYears": validity_years, "autoRenew": False}
        if renew_before_days is not None:
            subscription["renewBeforeDays"] = renew_before_days

        cert: dict[str, Any] = {"domain": domain, "autoSecureWww": auto_secure_www}
        if additional_domains:
            cert["additionalDomains"] = additional_domains

        body: dict[str, Any] = {
            "productVariant": product_variant,
            "certificate": cert,
            "subscription": subscription,
            "requestor": {
                "name": requestor_name,
                "email": requestor_email,
                "phone": requestor_phone,
                "designation": requestor_designation,
            },
            "agreement": {
                "signerName": signer_name or requestor_name,
                "signerPlace": signer_place,
                "accepted": True,
            },
        }
        if organization_id is not None:
            org: dict[str, Any] = {
                "organizationNumber": organization_id,
                "preVetted": True,
            }
            if prevetting_token:
                org["preVettingToken"] = prevetting_token
            body["organization"] = org
        if csr:
            body["csr"] = csr
        if group_number is not None:
            body["groupNumber"] = group_number
        if request_id is not None:
            body["requestId"] = request_id
        if remarks is not None:
            body["remarks"] = remarks
        if tags is not None:
            body["tags"] = tags
        if recipient_emails is not None:
            body["recipientEmails"] = recipient_emails
        if email_notifications is not None:
            body["emailNotifications"] = email_notifications
        if any([technical_poc_name, technical_poc_email, technical_poc_phone, technical_poc_designation]):
            body["technicalPointOfContact"] = {
                "name": technical_poc_name,
                "email": technical_poc_email,
                "phone": technical_poc_phone,
                "designation": technical_poc_designation,
            }
        if delegation is not None:
            body["delegation"] = delegation
        return body

    # --- create methods ---

    def create_dv(
        self,
        domain: str,
        validity_years: int = 1,
        additional_domains: list[str] | None = None,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV (Domain Validated) single-domain certificate order.

        The CSR may be included with the initial order via ``csr`` or submitted
        separately via :meth:`SslOrder.submit_csr` after the order is created.

        Args:
            domain: Primary FQDN (e.g. ``"example.com"``).
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            additional_domains: Optional list of additional SAN domains.
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format (e.g. ``"+12075551234"``).
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer (e.g. ``"Portland, ME"``).
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` with status ``"pending-csr"`` or a later stage.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._create(self._build_body(
            "dv", domain, validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=additional_domains,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_dv_wildcard(
        self,
        domain: str,
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV wildcard certificate order.

        ``domain`` must start with ``*.``.

        Args:
            domain: Wildcard FQDN (e.g. ``"*.example.com"``).
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the wildcard certificate.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._create(self._build_body(
            "dv-wildcard", domain, validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_dv_ucc(
        self,
        domains: list[str],
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV UCC (multi-domain / Unified Communications) certificate order.

        The first entry in ``domains`` is the primary domain; the remainder
        become subject alternative names.

        Args:
            domains: List of all FQDNs to include. The first is the primary domain.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the multi-domain certificate.

        Raises:
            ValueError: If ``domains`` is empty.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if not domains:
            raise ValueError("domains must not be empty")
        return self._create(self._build_body(
            "dv-ucc", domains[0], validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=domains[1:] or None,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_dv_wildcard_ucc(
        self,
        domains: list[str],
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create a DV wildcard UCC certificate order.

        ``domains`` may contain wildcard entries such as ``"*.example.com"``.
        The first entry is the primary domain; the remainder become SANs.

        Args:
            domains: List of all FQDNs (may include wildcard entries).
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the wildcard UCC certificate.

        Raises:
            ValueError: If ``domains`` is empty.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if not domains:
            raise ValueError("domains must not be empty")
        return self._create(self._build_body(
            "dv-wildcard-ucc", domains[0], validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=domains[1:] or None,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ov(
        self,
        domain: str,
        organization_id: str,
        validity_years: int = 1,
        additional_domains: list[str] | None = None,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV (Organization Validated) single-domain certificate order.

        Requires a pre-vetted ``organization_id`` from
        :meth:`certinext.accounts.AccountAccessor.list_organizations`.

        Args:
            domain: Primary FQDN.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            additional_domains: Optional list of additional SAN domains.
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the OV certificate.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._create(self._build_body(
            "ov", domain, validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=additional_domains,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ov_wildcard(
        self,
        domain: str,
        organization_id: str,
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV wildcard certificate order.

        ``domain`` must start with ``*.``.

        Args:
            domain: Wildcard FQDN (e.g. ``"*.example.com"``).
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the OV wildcard certificate.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._create(self._build_body(
            "ov-wildcard", domain, validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ov_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV UCC (multi-domain) certificate order.

        The first entry in ``domains`` is the primary domain; the remainder
        become subject alternative names.

        Args:
            domains: List of all FQDNs to include.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the OV multi-domain certificate.

        Raises:
            ValueError: If ``domains`` is empty.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if not domains:
            raise ValueError("domains must not be empty")
        return self._create(self._build_body(
            "ov-ucc", domains[0], validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=domains[1:] or None,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ov_wildcard_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an OV wildcard UCC certificate order.

        The first entry in ``domains`` is the primary domain; the remainder
        become subject alternative names.

        Args:
            domains: List of all FQDNs (may include wildcard entries).
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the OV wildcard UCC certificate.

        Raises:
            ValueError: If ``domains`` is empty.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if not domains:
            raise ValueError("domains must not be empty")
        return self._create(self._build_body(
            "ov-wildcard-ucc", domains[0], validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=domains[1:] or None,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ev(
        self,
        domain: str,
        organization_id: str,
        validity_years: int = 1,
        additional_domains: list[str] | None = None,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an EV (Extended Validation) single-domain certificate order.

        Requires a pre-vetted ``organization_id`` from
        :meth:`certinext.accounts.AccountAccessor.list_organizations`.

        Args:
            domain: Primary FQDN.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            additional_domains: Optional list of additional SAN domains.
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the EV certificate.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._create(self._build_body(
            "ev", domain, validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=additional_domains,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

    def create_ev_ucc(
        self,
        domains: list[str],
        organization_id: str,
        validity_years: int = 1,
        requestor_name: str = "",
        requestor_email: str = "",
        requestor_phone: str = "",
        requestor_designation: str = "",
        signer_name: str = "",
        signer_place: str = "",
        auto_secure_www: bool = False,
        prevetting_token: str | None = None,
        csr: str | None = None,
        group_number: str | None = None,
        request_id: str | None = None,
        renew_before_days: int | None = None,
        remarks: str | None = None,
        tags: list[str] | None = None,
        recipient_emails: list[str] | None = None,
        email_notifications: list[str] | None = None,
        technical_poc_name: str = "",
        technical_poc_email: str = "",
        technical_poc_phone: str = "",
        technical_poc_designation: str = "",
        delegation: dict[str, Any] | None = None,
    ) -> SslOrder:
        """Create an EV UCC (multi-domain) certificate order.

        The first entry in ``domains`` is the primary domain; the remainder
        become subject alternative names.

        Args:
            domains: List of all FQDNs to include.
            organization_id: :attr:`~certinext.accounts.Organization.organization_number`
                of the pre-vetted organization.
            validity_years: Certificate validity in years (1, 2, or 3; default: 1).
            requestor_name: Full name of the certificate requestor.
            requestor_email: Email address of the requestor.
            requestor_phone: Phone number in E.164 format.
            requestor_designation: Job title or designation of the requestor.
            signer_name: Name of the subscriber agreement signer (defaults to requestor_name).
            signer_place: City or location of the signer.
            auto_secure_www: Request automatic www-redirect coverage (default: ``False``).
            prevetting_token: Organization Consent Token; when provided the CA
                auto-approves without a manual approver step.
            csr: PEM-encoded CSR to include with the initial order (optional).
            group_number: Account sub-group for this order (optional).
            request_id: Custom request identifier for internal correlation (optional).
            renew_before_days: Days before expiry to begin renewal (``None`` = account default).
            remarks: Free-text remarks stored with the order.
            tags: Tag strings for filtering and reporting.
            recipient_emails: Email addresses notified on issuance.
            email_notifications: Email addresses for all order notifications.
            technical_poc_name: Full name of the technical point of contact.
            technical_poc_email: Email of the technical point of contact.
            technical_poc_phone: Phone of the technical POC (E.164 format).
            technical_poc_designation: Job title of the technical POC.
            delegation: Raw delegation block (see CertiNext account manager).

        Returns:
            :class:`SslOrder` for the EV multi-domain certificate.

        Raises:
            ValueError: If ``domains`` is empty.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        if not domains:
            raise ValueError("domains must not be empty")
        return self._create(self._build_body(
            "ev-ucc", domains[0], validity_years,
            requestor_name, requestor_email, requestor_phone, requestor_designation,
            additional_domains=domains[1:] or None,
            organization_id=organization_id, prevetting_token=prevetting_token,
            signer_name=signer_name, signer_place=signer_place,
            auto_secure_www=auto_secure_www, csr=csr,
            group_number=group_number, request_id=request_id,
            renew_before_days=renew_before_days, remarks=remarks, tags=tags,
            recipient_emails=recipient_emails, email_notifications=email_notifications,
            technical_poc_name=technical_poc_name, technical_poc_email=technical_poc_email,
            technical_poc_phone=technical_poc_phone, technical_poc_designation=technical_poc_designation,
            delegation=delegation,
        ))

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
