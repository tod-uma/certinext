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

"""CSR parsing utilities.

Requires the ``csr`` optional dependency::

    pip install certinext[csr]
"""

from pydantic import BaseModel, Field


class CsrInfo(BaseModel):
    """Structured information extracted from a PEM-encoded CSR.

    Returned by :func:`parse_csr`. All string fields are ``None`` when the
    corresponding OID is absent from the CSR subject or extensions.

    :class:`CsrInfo` itself has no dependency on ``cryptography`` — only
    :func:`parse_csr` requires it. You can import and type-hint :class:`CsrInfo`
    without installing the optional ``[csr]`` extra.

    Attributes:
        common_name: Common Name (CN) from the subject.
        email: Email address (``emailAddress`` OID) from the subject.
        locality: City or locality (L) from the subject.
        state: State or province (ST) from the subject.
        organization: Organisation name (O) from the subject.
        sans: DNS Subject Alternative Names, excluding the common name.

    Example::

        from certinext.csr import parse_csr

        info = parse_csr(open("server.csr").read())
        print(info.common_name, info.email, info.signer_place)
    """

    common_name: str | None = Field(description="Common Name (CN) from the subject.")
    email: str | None = Field(description="Email address (``emailAddress`` OID) from the subject.")
    locality: str | None = Field(description="City or locality (L) from the subject.")
    state: str | None = Field(description="State or province (ST) from the subject.")
    organization: str | None = Field(description="Organisation name (O) from the subject.")
    sans: list[str] = Field(
        default_factory=list,
        description="DNS Subject Alternative Names, excluding the common name.",
    )

    @property
    def signer_place(self) -> str | None:
        """Return ``"<locality>, <state>"`` derived from the CSR subject.

        Combines :attr:`locality` and :attr:`state` (e.g. ``"Orono, Maine"``).
        Returns whichever field is present when only one is available, or
        ``None`` when both are absent.
        """
        parts = [p for p in [self.locality, self.state] if p]
        return ", ".join(parts) if parts else None


def parse_csr(pem: str) -> CsrInfo:
    """Extract identity fields and DNS SANs from a PEM-encoded CSR.

    Parses the subject for ``CN``, ``emailAddress``, ``L``, ``ST``, and ``O``,
    and the SAN extension for DNS names. Use :attr:`CsrInfo.signer_place` to
    combine locality and state into a single string suitable for the
    ``signer_place`` argument of certificate creation methods.

    Args:
        pem: PEM-encoded certificate signing request string.

    Returns:
        :class:`CsrInfo` with all available fields populated.

    Raises:
        ImportError: If the ``cryptography`` package is not installed. Install
            it with ``pip install certinext[csr]``.
        ValueError: If the PEM cannot be parsed as a CSR, or the CSR subject
            contains no Common Name.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required to parse CSRs. "
            "Install it with: pip install certinext[csr]"
        ) from exc

    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except Exception as exc:
        raise ValueError(f"Failed to parse CSR: {exc}") from exc

    def _get(oid: object) -> str | None:
        attrs = csr.subject.get_attributes_for_oid(oid)  # type: ignore[arg-type] - oid is loosely typed as object to avoid importing ObjectIdentifier at call sites
        return str(attrs[0].value) if attrs else None

    cn = _get(NameOID.COMMON_NAME)
    if not cn:
        raise ValueError(
            "CSR subject has no Common Name - use --domain to specify the primary domain"
        )

    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_value = san_ext.value
        dns_names = (
            [name for name in san_value.get_values_for_type(x509.DNSName) if name != cn]
            if isinstance(san_value, x509.SubjectAlternativeName)
            else []
        )
    except x509.ExtensionNotFound:
        dns_names = []

    return CsrInfo(
        common_name=cn,
        email=_get(NameOID.EMAIL_ADDRESS),
        locality=_get(NameOID.LOCALITY_NAME),
        state=_get(NameOID.STATE_OR_PROVINCE_NAME),
        organization=_get(NameOID.ORGANIZATION_NAME),
        sans=dns_names,
    )
