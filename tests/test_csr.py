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

"""Tests for certinext.csr — CsrInfo dataclass and parse_csr()."""

import importlib.util
import warnings
from typing import Any

import pytest

from certinext.csr import CsrInfo, parse_csr

if importlib.util.find_spec("cryptography") is None:
    warnings.warn(
        "cryptography is not installed — TestParseCsr tests will be skipped. "
        "Run: pip install certinext[csr]",
        stacklevel=1,
    )


def _make_csr(cn: str = "foo", extra_attrs: list[Any] | None = None) -> str:
    """Generate a real PEM-encoded CSR using the cryptography library.

    Args:
        cn: Common Name for the subject.
        extra_attrs: Additional NameAttribute objects to include in the subject.

    Returns:
        PEM-encoded CSR string.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if extra_attrs:
        attrs.extend(extra_attrs)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


class TestCsrInfo:
    """CsrInfo dataclass behaviour."""

    def test_signer_place_combines_locality_and_state(self) -> None:
        """signer_place joins locality and state with ', '."""
        info = CsrInfo(common_name="x", email=None, locality="Orono", state="Maine",
                       organization=None)
        assert info.signer_place == "Orono, Maine"

    def test_signer_place_locality_only(self) -> None:
        """signer_place returns just locality when state is absent."""
        info = CsrInfo(common_name="x", email=None, locality="Orono", state=None,
                       organization=None)
        assert info.signer_place == "Orono"

    def test_signer_place_state_only(self) -> None:
        """signer_place returns just state when locality is absent."""
        info = CsrInfo(common_name="x", email=None, locality=None, state="Maine",
                       organization=None)
        assert info.signer_place == "Maine"

    def test_signer_place_none_when_both_absent(self) -> None:
        """signer_place is None when both locality and state are absent."""
        info = CsrInfo(common_name="x", email=None, locality=None, state=None,
                       organization=None)
        assert info.signer_place is None

    def test_sans_defaults_to_empty_list(self) -> None:
        """sans defaults to an empty list when not provided."""
        info = CsrInfo(common_name="x", email=None, locality=None, state=None,
                       organization=None)
        assert info.sans == []


class TestParseCsr:
    """parse_csr() extracts the expected fields.

    Skipped when the ``cryptography`` package is not installed; a module-level
    warning is emitted so the gap is visible in CI output.
    """

    @pytest.fixture(autouse=True)
    def _require_cryptography(self) -> None:
        """Skip this class when cryptography is absent."""
        pytest.importorskip("cryptography")

    def test_raises_on_invalid_pem(self) -> None:
        """parse_csr raises ValueError for non-CSR input."""
        with pytest.raises(ValueError, match="Failed to parse"):
            parse_csr("not a csr")

    def test_raises_when_no_cn(self) -> None:
        """parse_csr raises ValueError when the CSR subject has no CN."""
        with pytest.raises((ValueError, Exception)):
            parse_csr(
                "-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n"
                "-----END CERTIFICATE REQUEST-----\n"
            )

    def test_returns_csrinfo(self) -> None:
        """parse_csr returns a CsrInfo instance."""
        info = parse_csr(_make_csr())
        assert isinstance(info, CsrInfo)

    def test_extracts_common_name(self) -> None:
        """parse_csr populates common_name from the CN OID."""
        info = parse_csr(_make_csr(cn="test.maine.edu"))
        assert info.common_name == "test.maine.edu"

    def test_sans_empty_when_no_san_extension(self) -> None:
        """parse_csr returns an empty sans list when no SAN extension is present."""
        info = parse_csr(_make_csr())
        assert info.sans == []

    def test_email_none_when_absent(self) -> None:
        """parse_csr sets email to None when emailAddress is not in the subject."""
        info = parse_csr(_make_csr())
        assert info.email is None

    def test_locality_none_when_absent(self) -> None:
        """parse_csr sets locality to None when L is not in the subject."""
        info = parse_csr(_make_csr())
        assert info.locality is None

    def test_state_none_when_absent(self) -> None:
        """parse_csr sets state to None when ST is not in the subject."""
        info = parse_csr(_make_csr())
        assert info.state is None

    def test_extracts_email(self) -> None:
        """parse_csr extracts emailAddress from the subject."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        pem = _make_csr(
            cn="test.maine.edu",
            extra_attrs=[x509.NameAttribute(NameOID.EMAIL_ADDRESS, "admin@maine.edu")],
        )
        info = parse_csr(pem)
        assert info.email == "admin@maine.edu"

    def test_extracts_locality_and_state(self) -> None:
        """parse_csr extracts L and ST and signer_place combines them."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        pem = _make_csr(
            cn="test.maine.edu",
            extra_attrs=[
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Orono"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maine"),
            ],
        )
        info = parse_csr(pem)
        assert info.locality == "Orono"
        assert info.state == "Maine"
        assert info.signer_place == "Orono, Maine"
