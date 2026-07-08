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

"""Pydantic models for the SSL/TLS Certificates API (orders, DCV, downloads).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
:class:`SslOrder` carries the HTTP client in a private attribute (set by
:meth:`SslOrder.from_payload`) so its lifecycle methods keep working.
"""

from typing import Any, Literal

from pydantic import Field, PrivateAttr, field_validator, model_validator

from ..client import CertiNextClient
from ._base import CertiNextModel, _LenientDatetime, coerce_flag

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


class DcvChallenge(CertiNextModel):
    """DCV challenge for a single domain in an SSL order.

    Instances are returned by :meth:`SslOrder.get_dcv`. Publish the
    :attr:`token` at the :attr:`host` using the :attr:`method` before
    calling :meth:`SslOrder.verify_dcv`.

    Example::

        challenges = order.get_dcv()
        for c in challenges:
            print(c.domain, c.method, c.host, c.token)
    """

    domain: str | None = Field(
        default=None,
        description="The domain name this challenge applies to.",
    )
    method: str | None = Field(
        default=None,
        description='DCV method in upper case (e.g. ``"DNS-TXT"``, ``"HTTP-URL"``).',
    )
    token: str | None = Field(
        default=None,
        description="Challenge token to publish (TXT record content or HTTP file content).",
    )
    host: str | None = Field(
        default=None,
        description="DNS sub-domain or HTTP path where the challenge must be published.",
    )
    token_expiry: _LenientDatetime = Field(
        default=None,
        alias="tokenExpiry",
        description="Timezone-aware UTC expiry of `token`, or `None` if absent/unparseable.",
    )

    @model_validator(mode="before")
    @classmethod
    def _resolve_wire_chains(cls, data: Any) -> Any:
        """Resolve the 0.3.x fallback chains for the challenge fields.

        Chains (falsy values fall through, which ``AliasChoices`` cannot
        express): ``domain``/``domainName``; ``dcvMethod``/``method``
        (upper-cased, ``None`` when empty); ``txtToken``/``fileToken``/
        ``token``/``dnsContents``; ``dnsHost``/``host``. ``tokenExpiry`` has
        a single wire name, so it's left to the field's own alias.

        Args:
            data: The raw wire payload.

        Returns:
            A shallow copy with the canonical keys resolved (the original
            dict is left unmutated for the raw-payload stash).
        """
        if not isinstance(data, dict):
            return data
        out = dict(data)
        out["domain"] = data.get("domain") or data.get("domainName") or None
        raw_method = data.get("dcvMethod") or data.get("method") or ""
        out["method"] = raw_method.upper() if raw_method else None
        out["token"] = (
            data.get("txtToken")
            or data.get("fileToken")
            or data.get("token")
            or data.get("dnsContents")
            or None
        )
        out["host"] = data.get("dnsHost") or data.get("host") or None
        return out

    @property
    def value(self) -> str | None:
        """Challenge value (alias for :attr:`token`; present on some API versions)."""
        return (self._raw or {}).get("value") or self.token

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


class CertificateDownload(CertiNextModel):
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

    order_id: str | None = Field(
        default=None,
        alias="orderId",
        description="Order ID this certificate belongs to.",
    )
    serial_number: str | None = Field(
        default=None,
        alias="serialNumber",
        description="Certificate serial number.",
    )
    subject: str | None = Field(
        default=None,
        description="Certificate subject distinguished name.",
    )
    issuer: str | None = Field(
        default=None,
        description="Certificate issuer distinguished name.",
    )
    not_before: _LenientDatetime = Field(
        default=None,
        alias="notBefore",
        description="Certificate validity start, as a timezone-aware UTC datetime, or ``None``.",
    )
    not_after: _LenientDatetime = Field(
        default=None,
        alias="notAfter",
        description="Certificate validity end, as a timezone-aware UTC datetime, or ``None``.",
    )
    certificate_pem: str | None = Field(
        default=None,
        alias="certificatePem",
        description="PEM-encoded end-entity certificate.",
    )
    chain_pem: list[str] = Field(
        default_factory=list,
        alias="chainPem",
        description="List of PEM-encoded intermediate CA certificates.",
    )

    @field_validator("chain_pem", mode="before")
    @classmethod
    def _chain_list_or_empty(cls, value: Any) -> Any:
        """Coerce non-list wire values to an empty list (0.3.x behavior).

        Args:
            value: The raw wire value for ``chainPem``.

        Returns:
            The value unchanged if it is a list, else ``[]``.
        """
        return value if isinstance(value, list) else []

    def as_pem_chain(self, *, sort: bool = True) -> str:
        """Return the full certificate chain as a leaf-first PEM string.

        Concatenates the end-entity certificate (:attr:`certificate_pem`)
        followed by its intermediates, normalised so the result ends with
        exactly one trailing newline. This is the ``fullchain`` layout ACME
        clients and servers expect.

        By default (``sort=True``) the intermediates are re-ordered into true
        signing order (each certificate's issuer follows it, root last) rather
        than trusting the order CertiNext returns them in, which is non-standard
        and breaks Windows Schannel / IIS validation (GitLab #4). Pass
        ``sort=False`` to concatenate the fields in the exact order the API
        returned — useful for debugging or when ``cryptography`` is unavailable.

        Args:
            sort: When ``True`` (default), re-order the chain into leaf-first
                signing order. When ``False``, preserve the API's order.

        Returns:
            Leaf-first PEM chain (end-entity certificate followed by its
            intermediates) ending in a single newline, or an empty string if
            no certificate is present.

        Raises:
            ImportError: If ``sort=True`` and the ``cryptography`` package is
                not installed. Install it with ``pip install certinext[csr]``,
                or pass ``sort=False`` to skip sorting.
        """
        pems = [
            pem.strip()
            for pem in [self.certificate_pem or "", *self.chain_pem]
            if pem and pem.strip()
        ]
        if not pems:
            return ""
        if sort:
            from certinext._chain import order_certificate_chain

            ordered = order_certificate_chain(self.chain_pem, leaf_pem=self.certificate_pem)
            if ordered:
                return "\n".join(ordered) + "\n"
        return "\n".join(pems) + "\n"

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"CertificateDownload(order_id={self.order_id!r}, "
            f"serial_number={self.serial_number!r}, "
            f"not_after={self.not_after!r})"
        )


class SslOrder(CertiNextModel):
    """Represents a CertiNext SSL/TLS certificate order.

    Instances are returned by :class:`SslAccessor` create methods and
    :meth:`SslAccessor.get`. They should not be constructed directly.

    Lifecycle methods (:meth:`refresh`, :meth:`get_dcv`, :meth:`verify_dcv`,
    :meth:`submit_csr`, :meth:`accept_agreement`, :meth:`download_certificate`,
    :meth:`download_certificate_pem`, :meth:`download_certificate_der`,
    :meth:`cancel`, :meth:`reject`, :meth:`revoke`, :meth:`reissue`) call
    the API directly.

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
        order.verify_dcv(domain="example.com", method="DNS-TXT")
        order.accept_agreement(signer_name="John Doe", signer_place="Portland, ME")
        cert = order.download_certificate()
        print(cert.certificate_pem)
    """

    order_id: str | None = Field(
        default=None,
        alias="orderId",
        description="Unique order identifier assigned by CertiNext.",
    )
    request_id: str | None = Field(
        default=None,
        alias="requestId",
        description="Request identifier associated with this order.",
    )
    status: str | None = Field(
        default=None,
        description="Current order status. See `SslOrderStatus` for valid values.",
    )
    product_variant: str | None = Field(
        default=None,
        alias="productVariant",
        description='Certificate product variant (e.g. ``"dv"``, ``"ov"``, ``"ev"``).',
    )
    domain: str | None = Field(
        default=None,
        description="Primary domain name (common name) for single-domain certificate types.",
    )
    additional_domains: list[str] = Field(
        default_factory=list,
        alias="additionalDomains",
        description="Additional subject-alternative-name domains for this order.",
    )
    created_at: _LenientDatetime = Field(
        default=None,
        alias="createdAt",
        description="Order creation timestamp as a timezone-aware UTC datetime, or ``None``.",
    )
    expires_at: _LenientDatetime = Field(
        default=None,
        alias="expiresAt",
        description=(
            "Certificate expiry timestamp as a timezone-aware UTC datetime, or "
            "``None``. Present on the order-detail response once a certificate "
            "has been issued; distinct from :meth:`download_certificate`'s "
            ":attr:`CertificateDownload.not_after`, which comes from the "
            "certificate-download endpoint instead."
        ),
    )
    csr_submitted: bool = Field(
        default=False,
        alias="csrSubmitted",
        description=(
            "Whether a CSR has been submitted for this order. ``True`` once "
            ":meth:`submit_csr` has been called successfully; the order cannot "
            "progress to issuance until then."
        ),
    )
    order_state: str | None = Field(
        default=None,
        alias="orderState",
        description=(
            'Human-readable order status from the legacy pipeline (e.g. '
            '``"Order Accepted"``, ``"Approved by System"``); complements '
            "the typed :attr:`status` field."
        ),
    )
    certificate_state: str | None = Field(
        default=None,
        alias="certificateState",
        description=(
            'Human-readable certificate/request status from the legacy pipeline '
            '(e.g. ``"Pending for Approver"``, ``"Certificate Generated"``, '
            '``"Certificate Downloaded"``). A certificate is ready to download '
            'when this reads ``"Certificate Generated"`` (or similar); if not, '
            'while :attr:`status` is ``"issued"``, the CA has approved the order '
            "but not yet signed the certificate."
        ),
    )
    interim_dv_issued: bool = Field(
        default=False,
        alias="interimDvIssued",
        description=(
            "Whether an interim DV certificate was issued while an OV or EV "
            "order is pending organization verification. Present only on OV/EV "
            "orders when the CA offers interim issuance; ``False`` otherwise."
        ),
    )
    subscriber_agreement: dict[str, Any] | None = Field(
        default=None,
        alias="subscriberAgreement",
        description=(
            "The raw subscriber agreement block for this order, or ``None``. "
            "Contains acceptance status, signer name, and timestamp when accepted."
        ),
    )
    remarks: str | None = Field(
        default=None,
        description="Free-text remarks stored with the order, or ``None`` if not set.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tag strings attached to the order for filtering and reporting.",
    )

    _client: CertiNextClient | None = PrivateAttr(default=None)

    @field_validator("additional_domains", "tags", mode="before")
    @classmethod
    def _list_or_empty(cls, value: Any) -> Any:
        """Coerce non-list wire values to an empty list (0.3.x behavior).

        Args:
            value: The raw wire value.

        Returns:
            The value unchanged if it is a list, else ``[]``.
        """
        return value if isinstance(value, list) else []

    @field_validator("subscriber_agreement", mode="before")
    @classmethod
    def _dict_or_none(cls, value: Any) -> Any:
        """Coerce non-dict wire values to ``None`` (0.3.x behavior).

        Args:
            value: The raw wire value for ``subscriberAgreement``.

        Returns:
            The value unchanged if it is a dict, else ``None``.
        """
        return value if isinstance(value, dict) else None

    @field_validator("csr_submitted", "interim_dv_issued", mode="before")
    @classmethod
    def _flag(cls, value: Any) -> bool:
        """Coerce wire boolean flags leniently (string ``"0"`` is falsy).

        Args:
            value: The raw wire value.

        Returns:
            The coerced boolean.
        """
        return coerce_flag(value)

    @classmethod
    def from_payload(cls, client: CertiNextClient | None, data: Any) -> "SslOrder":
        """Build an SslOrder from a wire payload and attach the HTTP client.

        Args:
            client: The underlying HTTP client used by the lifecycle methods.
                ``None`` produces a detached object usable for field access only.
            data: Raw API response dict for this order (non-dict values
                validate as an empty payload).

        Returns:
            The validated SslOrder instance.
        """
        order = cls.model_validate(data if isinstance(data, dict) else {})
        order._client = client
        return order

    def _require_client(self) -> CertiNextClient:
        """Return the attached HTTP client or raise for detached instances.

        Returns:
            The client set by :meth:`from_payload`.

        Raises:
            RuntimeError: When the SslOrder was constructed without a client.
        """
        if self._client is None:
            raise RuntimeError(
                "This SslOrder has no attached API client; "
                "obtain instances from a session accessor"
            )
        return self._client

    # --- helpers ---

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

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display.

        Returns:
            Dict with keys ``order_id``, ``domain``, ``status``,
            ``product_variant``, ``created_at``, ``expires_at``.
        """
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "order_id": _s(self.order_id),
            "domain": _s(self.domain),
            "status": _s(self.status),
            "product_variant": _s(self.product_variant),
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "expires_at": self.expires_at.isoformat() if self.expires_at else "",
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
        """Re-fetch this order from the API and update all fields in place.

        Returns:
            ``self``, allowing method chaining.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._require_client().get(f"{_SSL_BASE}/{self.order_id}")
        if isinstance(result, dict):
            self._replace_payload(result)
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
        result = self._require_client().get(
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
        return [DcvChallenge.model_validate(item) for item in raw if isinstance(item, dict)]

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
        return self._require_client().post(
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
        return self._require_client().put(f"{_SSL_BASE}/{self.order_id}/csr", json=body)

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
        return self._require_client().post(
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
        result = self._require_client().get(f"{_SSL_BASE}/{self.order_id}/certificate")
        return CertificateDownload.model_validate(result if isinstance(result, dict) else {})

    def download_certificate_pem(self) -> str:
        """Download the issued certificate bundle as a PEM text string.

        Returns:
            PEM-encoded certificate chain as a UTF-8 string.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw = self._require_client().get_bytes(
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
        return self._require_client().get_bytes(
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
        return self._require_client().post(f"{_SSL_BASE}/{self.order_id}/cancel")

    def reject(self) -> dict[str, Any]:
        """Reject this draft certificate order.

        Returns:
            Raw API response dict.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._require_client().post(f"{_SSL_BASE}/{self.order_id}/reject")

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
        return self._require_client().post(f"{_SSL_BASE}/{self.order_id}/revoke", json=body or None)

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
        return self._require_client().post(f"{_SSL_BASE}/{self.order_id}/reissue", json=body)
