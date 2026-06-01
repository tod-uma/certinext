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
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from .client import CertiNextClient
from .exceptions import CertiNextAPIError, CertiNextTimeoutError  # noqa: F401 — referenced in Raises docstrings

if TYPE_CHECKING:
    from .session import CertiNextSession

log = logging.getLogger(__name__)

_SSL_BASE = "/api/certinext/v2/ssl-certificates"
_WORKFLOW_TERMINAL = frozenset({"issued", "revoked", "cancelled", "rejected", "expired"})

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
    DER use :meth:`SslOrder.download_certificate_der`; for PKCS#7 use
    :meth:`SslOrder.download_certificate_pkcs7`.

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

    def as_pem_chain(self) -> str:
        """Return the full certificate chain as a leaf-first PEM string.

        Concatenates the end-entity certificate (:attr:`certificate_pem`)
        followed by each intermediate in :attr:`chain_pem`, normalised so the
        result ends with exactly one trailing newline. This is the
        ``fullchain`` layout ACME clients and servers expect, assembled
        deterministically from the JSON download fields — independent of the
        ordering of the raw bundle returned by
        :meth:`SslOrder.download_certificate_pem`.

        Returns:
            Leaf-first PEM chain (end-entity certificate followed by its
            intermediates) ending in a single newline, or an empty string if
            no certificate is present.
        """
        pems = [
            pem.strip()
            for pem in [self.certificate_pem or "", *self.chain_pem]
            if pem and pem.strip()
        ]
        if not pems:
            return ""
        return "\n".join(pems) + "\n"

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
    :meth:`download_certificate_pem`, :meth:`download_certificate_der`,
    :meth:`download_certificate_pkcs7`, :meth:`cancel`, :meth:`reject`,
    :meth:`revoke`, :meth:`reissue`) call the API directly.

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

    def download_certificate_pkcs7(self) -> bytes:
        """Download the issued certificate in PKCS#7 (P7B) format.

        Returns:
            PKCS#7-encoded certificate bundle as raw bytes.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._client.get_bytes(
            f"{_SSL_BASE}/{self.order_id}/certificate",
            accept="application/x-pkcs7-certificates",
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

    def create(
        self,
        product: str,
        domain: str,
        *,
        organization_id: str | None = None,
        **kwargs: Any,
    ) -> SslOrder:
        """Create an SSL order, dispatching on validation level.

        Convenience wrapper over :meth:`create_dv`, :meth:`create_ov`, and
        :meth:`create_ev` so callers that take the product as configuration or
        CLI input don't have to branch on it themselves.

        Args:
            product: Validation level — ``"dv"``, ``"ov"``, or ``"ev"``
                (case-insensitive).
            domain: Primary domain (common name) for the certificate.
            organization_id: CertiNext organization ID. Required for ``"ov"``
                and ``"ev"`` orders; ignored for ``"dv"``.
            **kwargs: Forwarded verbatim to the underlying ``create_*`` method
                (e.g. ``validity_years``, ``additional_domains``, ``csr``,
                requestor/signer fields).

        Returns:
            The created :class:`SslOrder`.

        Raises:
            ValueError: If *product* is not one of ``dv``/``ov``/``ev``, or if
                *organization_id* is missing for an ``ov``/``ev`` order.
            CertiNextAPIError: On a non-2xx API response.
        """
        level = product.strip().lower()
        if level == "dv":
            return self.create_dv(domain, **kwargs)
        if level in ("ov", "ev"):
            if not organization_id:
                raise ValueError(
                    f"organization_id is required for {level!r} certificates"
                )
            if level == "ov":
                return self.create_ov(domain, organization_id, **kwargs)
            return self.create_ev(domain, organization_id, **kwargs)
        raise ValueError(
            f"Unknown product {product!r}; expected one of 'dv', 'ov', 'ev'"
        )

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


class OrderWorkflow:
    """Drives a CertiNext SSL certificate order through to issuance.

    Encapsulates the full certificate lifecycle state machine — agreement
    acceptance, CSR submission, DCV challenge handling, polling, and
    certificate download — so scripts don't need to reimplement it.

    The simplest usage::

        order = sess.ssl.create_ov("example.com", org_id, ...)
        pem = OrderWorkflow(order, signer_name="Jane Doe", signer_place="Portland, ME").run(csr=csr_pem)

    Or, when you have a CSR, use :meth:`from_csr` to fill defaults automatically::

        pem = OrderWorkflow.from_csr(order, csr_pem, signer_name="Jane Doe").run()

    For more control, drive the workflow step by step::

        wf = (
            OrderWorkflow.from_csr(order, csr_pem, signer_name="Jane Doe")
            .on("status_change", lambda old, new: print(f"{old} → {new}"))
            .on("dcv_available", lambda cs: publish_dns(cs))
            .on("issued", lambda o: print(f"Issued: {o.order_id}"))
        )
        wf.submit_csr(csr_pem, force=True)
        if not wf.poll(wait=600):
            raise TimeoutError("timed out")
        pem = wf.download()

    **Events**

    Register handlers with :meth:`on`. All handlers receive positional arguments:

    - ``"status_change"`` — ``(old_status: str | None, new_status: str | None)``
    - ``"dcv_available"`` — ``(challenges: list[DcvChallenge])``
    - ``"poll"`` — ``(order: SslOrder)`` — fired each tick while waiting
    - ``"issued"`` — ``(order: SslOrder)``
    """

    def __init__(
        self,
        order: SslOrder,
        *,
        signer_name: str = "",
        signer_place: str = "",
        auto_verify_dcv: bool = True,
    ) -> None:
        """
        Args:
            order: The :class:`SslOrder` to drive.
            signer_name: Full name of the person accepting the subscriber
                agreement. Required when the order enters ``pending-agreement``.
            signer_place: City and state of the signer (e.g. ``"Portland, ME"``).
                Required when the order enters ``pending-agreement``. Can be
                derived from the CSR via :meth:`from_csr`.
            auto_verify_dcv: When ``True`` (default), :meth:`advance` calls
                :meth:`~SslOrder.verify_dcv` automatically for each challenge
                when the order is in ``pending-dcv``. Set ``False`` for
                environments where you must publish DNS records manually before
                triggering verification — in that case call :meth:`verify_dcv`
                yourself after publishing, then resume :meth:`poll`.
        """
        self._order = order
        self._signer_name = signer_name
        self._signer_place = signer_place
        self._auto_verify_dcv = auto_verify_dcv
        self._handlers: dict[str, list[Callable[..., None]]] = {}

    @classmethod
    def from_csr(
        cls,
        order: SslOrder,
        csr_pem: str,
        *,
        signer_name: str = "",
        signer_place: str = "",
        auto_verify_dcv: bool = True,
    ) -> "OrderWorkflow":
        """Create an :class:`OrderWorkflow`, filling defaults from the CSR subject.

        Parses ``csr_pem`` with :func:`~certinext.csr.parse_csr` and uses
        :attr:`~certinext.csr.CsrInfo.signer_place` as the default for
        ``signer_place`` when not explicitly provided.

        Falls back to an empty string if the ``cryptography`` package is not
        installed or the CSR cannot be parsed — no exception is raised.

        Args:
            order: The :class:`SslOrder` to drive.
            csr_pem: PEM-encoded CSR to parse for subject fields.
            signer_name: Signer name; not inferred from the CSR.
            signer_place: Signer location. Defaults to ``"<L>, <ST>"`` from the
                CSR subject when not provided.
            auto_verify_dcv: Passed through to :meth:`__init__`.

        Returns:
            A configured :class:`OrderWorkflow`.
        """
        if not signer_place:
            try:
                from .csr import parse_csr
                info = parse_csr(csr_pem)
                signer_place = info.signer_place or ""
            except (ImportError, ValueError):
                pass
        return cls(order, signer_name=signer_name, signer_place=signer_place, auto_verify_dcv=auto_verify_dcv)

    @classmethod
    def from_order_id(
        cls,
        session: "CertiNextSession",
        order_id: str,
        *,
        signer_name: str = "",
        signer_place: str = "",
        auto_verify_dcv: bool = True,
    ) -> "OrderWorkflow":
        """Create an :class:`OrderWorkflow` for an existing order by its ID.

        Fetches the live order with :meth:`SslAccessor.get` and wraps it. This
        is the resume pattern for callers that persist only the ``order_id``
        (e.g. an externally-retried finalizer) and re-derive order state from
        the API on each attempt.

        Args:
            session: A :class:`~certinext.session.CertiNextSession`.
            order_id: The ``orderId`` returned when the order was created.
            signer_name: Signer name for agreement acceptance (see
                :meth:`__init__`).
            signer_place: Signer location for agreement acceptance.
            auto_verify_dcv: Passed through to :meth:`__init__`.

        Returns:
            A configured :class:`OrderWorkflow` wrapping the fetched order.

        Raises:
            CertiNextAPIError: On a non-2xx API response (404 if not found).
        """
        order = session.ssl.get(order_id)
        return cls(
            order,
            signer_name=signer_name,
            signer_place=signer_place,
            auto_verify_dcv=auto_verify_dcv,
        )

    # --- Event registration ---

    def on(self, event: str, handler: Callable[..., None]) -> "OrderWorkflow":
        """Register an event handler. Returns ``self`` for method chaining.

        Args:
            event: One of ``"status_change"``, ``"dcv_available"``,
                ``"poll"``, or ``"issued"``.
            handler: Callable invoked when the event fires. Arguments depend
                on the event — see class docstring for signatures.

        Returns:
            ``self``, so calls can be chained: ``wf.on(...).on(...)``.
        """
        self._handlers.setdefault(event, []).append(handler)
        return self

    def _emit(self, event: str, *args: Any) -> None:
        """Invoke all handlers registered for *event*."""
        for handler in self._handlers.get(event, []):
            handler(*args)

    # --- Properties ---

    @property
    def order(self) -> SslOrder:
        """The underlying :class:`SslOrder`."""
        return self._order

    @property
    def status(self) -> str | None:
        """Current order status (passthrough to :attr:`SslOrder.status`)."""
        return self._order.status

    @property
    def is_terminal(self) -> bool:
        """``True`` when the order is in any terminal status.

        Terminal statuses are ``issued``, ``revoked``, ``cancelled``,
        ``rejected``, and ``expired``.
        """
        return self._order.status in _WORKFLOW_TERMINAL

    @property
    def is_complete(self) -> bool:
        """``True`` when the order has been issued successfully."""
        return self._order.status == "issued"

    # --- Step-by-step API ---

    def submit_csr(self, csr: str, *, force: bool = False) -> bool:
        """Submit the CSR to the order (best-effort).

        Skips silently when the order is already in a terminal status
        (unless ``force=True``) or when ``csr`` is empty. A 422 response is
        treated as "not needed" (the CSR was already submitted or not required
        at this stage) rather than an error.

        Args:
            csr: PEM-encoded CSR string.
            force: When ``True``, attempt submission even if the order is not
                in ``pending-csr`` status. Useful immediately after order
                creation when the CA may have already advanced the order.

        Returns:
            ``True`` if the CSR was accepted, ``False`` if skipped or not needed.

        Raises:
            CertiNextAPIError: On any non-422 API error during submission.
        """
        if not csr.strip():
            return False
        if not force and self.is_terminal:
            return False
        try:
            self._order.submit_csr(csr)
            self._order.refresh()
            return True
        except CertiNextAPIError as exc:
            if exc.status_code == 422:
                return False
            raise

    def advance(self, csr: str = "") -> str:
        """Perform one state-machine step based on the current order status.

        Refreshes the order first, fires ``"status_change"`` if the status
        changed since the last refresh, then acts on the current state:

        - ``pending-agreement``: accepts the subscriber agreement (errors are
          logged and swallowed — the CA may advance the order on its own).
        - ``pending-csr``: submits ``csr``; raises :exc:`ValueError` if no CSR
          was provided.
        - ``pending-dcv``: fires ``"dcv_available"``; calls
          :meth:`~SslOrder.verify_dcv` for each challenge when
          ``auto_verify_dcv`` is ``True``.
        - Terminal states: fires ``"issued"`` if issued.
        - All other states (``pending-approval``, etc.): fires ``"poll"``
          and returns ``"waiting"``.

        Args:
            csr: PEM-encoded CSR. Required when the order reaches
                ``pending-csr``.

        Returns:
            One of ``"accepted-agreement"``, ``"submitted-csr"``,
            ``"triggered-dcv"``, ``"dcv-pending"``, ``"waiting"``,
            or ``"complete"``.

        Raises:
            CertiNextAPIError: On an API error during any state action.
            ValueError: If the order is in ``pending-csr`` and no CSR was provided.
        """
        prev = self._order.status
        self._order.refresh()
        current = self._order.status

        if current != prev:
            self._emit("status_change", prev, current)

        if current in _WORKFLOW_TERMINAL:
            if current == "issued":
                self._emit("issued", self._order)
            return "complete"

        if current == "pending-agreement":
            try:
                self._order.accept_agreement(self._signer_name, self._signer_place)
                self._order.refresh()
                if self._order.status != current:
                    self._emit("status_change", current, self._order.status)
            except CertiNextAPIError as exc:
                log.debug(
                    "accept_agreement returned HTTP %s for order %s — "
                    "order may advance on its own",
                    exc.status_code, self._order.order_id,
                )
            return "accepted-agreement"

        if current == "pending-csr":
            if not csr.strip():
                raise ValueError(
                    f"Order {self._order.order_id!r} is in pending-csr "
                    "but no CSR was provided to advance()"
                )
            self._order.submit_csr(csr)
            self._order.refresh()
            if self._order.status != current:
                self._emit("status_change", current, self._order.status)
            return "submitted-csr"

        if current == "pending-dcv":
            challenges: list[DcvChallenge] = []
            try:
                challenges = self._order.get_dcv()
            except CertiNextAPIError as exc:
                log.debug(
                    "get_dcv returned HTTP %s for order %s",
                    exc.status_code, self._order.order_id,
                )
            if challenges:
                self._emit("dcv_available", challenges)
            if self._auto_verify_dcv:
                for c in challenges:
                    if c.domain and c.method:
                        try:
                            self._order.verify_dcv(c.domain, c.method)
                        except CertiNextAPIError as exc:
                            log.debug(
                                "verify_dcv returned HTTP %s for %s on order %s",
                                exc.status_code, c.domain, self._order.order_id,
                            )
                self._order.refresh()
                if self._order.status != current:
                    self._emit("status_change", current, self._order.status)
                return "triggered-dcv"
            return "dcv-pending"

        self._emit("poll", self._order)
        return "waiting"

    def poll(self, wait: int = 300, interval: int = 5) -> bool:
        """Poll the order by calling :meth:`advance` repeatedly until terminal.

        Calls :meth:`advance` immediately on entry (no initial sleep), then
        sleeps ``interval`` seconds between subsequent calls. Returns as soon
        as the order reaches a terminal status or the deadline passes.

        Args:
            wait: Maximum seconds to wait before returning ``False``.
            interval: Seconds between :meth:`advance` calls.

        Returns:
            ``True`` if the order reached ``issued``, ``False`` if the
            deadline was reached before a terminal status.

        Raises:
            CertiNextAPIError: On an unrecoverable API error during polling.
        """
        deadline = time.monotonic() + wait
        while not self.is_terminal:
            self.advance()
            if self.is_terminal:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(interval, remaining))
        return self.is_complete

    def verify_dcv(self) -> None:
        """Manually trigger DCV verification for all pending challenges.

        Fetches the current DCV challenges and calls
        :meth:`~SslOrder.verify_dcv` for each. Use this when
        ``auto_verify_dcv=False`` — publish your DNS records first, then
        call this method, then resume :meth:`poll`.

        Raises:
            CertiNextAPIError: On an API error during verification.
        """
        challenges: list[DcvChallenge] = []
        try:
            challenges = self._order.get_dcv()
        except CertiNextAPIError:
            pass
        for c in challenges:
            if c.domain and c.method:
                self._order.verify_dcv(c.domain, c.method)
        self._order.refresh()

    def download(self, *, retries: int = 5, retry_delay: int = 5) -> str:
        """Download the issued certificate as a PEM string.

        Retries on HTTP 422 (certificate file not yet ready after issuance)
        up to ``retries`` times, waiting ``retry_delay`` seconds between
        attempts.

        Args:
            retries: Maximum number of download attempts (default 5).
            retry_delay: Seconds between retries (default 5).

        Returns:
            PEM-encoded certificate string.

        Raises:
            CertiNextAPIError: If all attempts fail.
        """
        for attempt in range(1, retries + 1):
            try:
                return self._order.download_certificate_pem()
            except CertiNextAPIError as exc:
                if exc.status_code == 422 and attempt < retries:
                    log.debug(
                        "Certificate not ready yet (HTTP 422), retrying in %ds "
                        "(attempt %d/%d)",
                        retry_delay, attempt, retries,
                    )
                    time.sleep(retry_delay)
                else:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover

    def download_chain(self, *, retries: int = 5, retry_delay: int = 5) -> str:
        """Download the issued certificate as a leaf-first PEM fullchain.

        Behaves like :meth:`download` (same HTTP 422 "not ready yet" retry
        loop) but returns :meth:`CertificateDownload.as_pem_chain` — the
        end-entity certificate followed by its intermediates, normalised to a
        single trailing newline. Prefer this over :meth:`download` when you
        need a deterministically ordered ``fullchain``.

        Args:
            retries: Maximum number of download attempts (default 5).
            retry_delay: Seconds between retries (default 5).

        Returns:
            Leaf-first PEM fullchain string.

        Raises:
            CertiNextAPIError: If all attempts fail.
        """
        for attempt in range(1, retries + 1):
            try:
                return self._order.download_certificate().as_pem_chain()
            except CertiNextAPIError as exc:
                if exc.status_code == 422 and attempt < retries:
                    log.debug(
                        "Certificate not ready yet (HTTP 422), retrying in %ds "
                        "(attempt %d/%d)",
                        retry_delay, attempt, retries,
                    )
                    time.sleep(retry_delay)
                else:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover

    # --- High-level API ---

    def run(self, csr: str = "", *, wait: int = 300) -> str:
        """Run the complete workflow and return the issued PEM certificate.

        Calls :meth:`submit_csr` (``force=True``) to attempt an upfront CSR
        submission, then :meth:`poll` to drive the order to issuance, then
        :meth:`download` to retrieve the certificate.

        Args:
            csr: PEM-encoded CSR. Required unless the CSR was already
                submitted at order creation time.
            wait: Maximum seconds to wait for issuance.

        Returns:
            PEM-encoded certificate string.

        Raises:
            CertiNextTimeoutError: If the order does not reach ``issued``
                within ``wait`` seconds. :attr:`CertiNextTimeoutError.order_id`
                can be used to resume with
                :meth:`~certinext.ssl_certificates.SslAccessor.get`.
            CertiNextAPIError: On an unrecoverable API error.
            ValueError: If the order reaches ``pending-csr`` and no CSR
                was provided.
        """
        self.submit_csr(csr, force=True)
        if not self.poll(wait=wait):
            raise CertiNextTimeoutError(self._order.order_id, wait)
        return self.download()
