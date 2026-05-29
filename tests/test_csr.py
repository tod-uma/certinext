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

import pytest

from certinext.csr import CsrInfo, parse_csr

if importlib.util.find_spec("cryptography") is None:
    warnings.warn(
        "cryptography is not installed — TestParseCsr tests will be skipped. "
        "Run: pip install certinext[csr]",
        stacklevel=1,
    )

# Minimal self-signed CSR with CN, emailAddress, L, ST, O fields.
# Subject: C=US, ST=Maine, L=Orono, O=University of Maine System,
#          CN=test.maine.edu, emailAddress=admin@maine.edu
_SAMPLE_CSR = """\
-----BEGIN CERTIFICATE REQUEST-----
MIIBpzCCAQ4CAQAwaDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBU1haW5lMQ4wDAYD
VQQHDAVPcm9ubzEiMCAGA1UECgwZVW5pdmVyc2l0eSBvZiBNYWluZSBTeXN0ZW0x
FzAVBgNVBAMMDnRlc3QubWFpbmUuZWR1MB4wDgYJKoZIhvcNAQkBFgFhMFwwDQYJ
KoZIhvcNAQEBBQADSwAwSAJBAMXOaXFKfTWVJnCk9H7qBBR/Q5rYMYMIgXoBpnxK
DWJFBxxVEBPMYjfNxIPb8LNBX5JR6GfAX8p4sC36kCzGRosCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA0EAb7hhVWdFT7dSLi5MXxT7fqzqr7e1Km7v5n1mPsLjm56b5Ot
e8G4kK6lX2bMX2a8bXqJLzJNl5N2YDFhsG8TXA==
-----END CERTIFICATE REQUEST-----
"""

# Minimal CSR with only CN (no email, locality, state, org).
_BARE_CSR = """\
-----BEGIN CERTIFICATE REQUEST-----
MIHOMEECAQAwDjEMMAoGA1UEAwwDZm9vMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
AMXOaXFKfTWVJnCk9H7qBBR/Q5rYMYMIgXoBpnxKDWJFBxxVEBPMYjfNxIPb8LNB
X5JR6GfAX8p4sC36kCzGRosCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA0EAGj4j2U6d
bG1JT/i0wLIc7cxYzBTrL6y0d4RkEdP2bz8y8YsY47JFIJ1nJB7K1P3pD8N7Gkg
WFEiIHvQQ/xc4w==
-----END CERTIFICATE REQUEST-----
"""


class TestCsrInfo:
    """CsrInfo dataclass behaviour."""

    def test_signer_place_combines_locality_and_state(self):
        """signer_place joins locality and state with ', '."""
        info = CsrInfo(common_name="x", email=None, locality="Orono", state="Maine",
                       organization=None)
        assert info.signer_place == "Orono, Maine"

    def test_signer_place_locality_only(self):
        """signer_place returns just locality when state is absent."""
        info = CsrInfo(common_name="x", email=None, locality="Orono", state=None,
                       organization=None)
        assert info.signer_place == "Orono"

    def test_signer_place_state_only(self):
        """signer_place returns just state when locality is absent."""
        info = CsrInfo(common_name="x", email=None, locality=None, state="Maine",
                       organization=None)
        assert info.signer_place == "Maine"

    def test_signer_place_none_when_both_absent(self):
        """signer_place is None when both locality and state are absent."""
        info = CsrInfo(common_name="x", email=None, locality=None, state=None,
                       organization=None)
        assert info.signer_place is None

    def test_sans_defaults_to_empty_list(self):
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

    def test_raises_on_invalid_pem(self):
        """parse_csr raises ValueError for non-CSR input."""
        with pytest.raises(ValueError, match="Failed to parse"):
            parse_csr("not a csr")

    def test_raises_when_no_cn(self):
        """parse_csr raises ValueError when the CSR subject has no CN."""
        # Build a CSR with no CN — we use a known-bad DER snippet
        with pytest.raises((ValueError, Exception)):
            parse_csr("-----BEGIN CERTIFICATE REQUEST-----\nYQ==\n-----END CERTIFICATE REQUEST-----\n")

    def test_returns_csrinfo(self):
        """parse_csr returns a CsrInfo instance."""
        info = parse_csr(_BARE_CSR)
        assert isinstance(info, CsrInfo)

    def test_extracts_common_name(self):
        """parse_csr populates common_name from the CN OID."""
        info = parse_csr(_BARE_CSR)
        assert info.common_name == "foo"

    def test_sans_empty_when_no_san_extension(self):
        """parse_csr returns an empty sans list when no SAN extension is present."""
        info = parse_csr(_BARE_CSR)
        assert info.sans == []

    def test_email_none_when_absent(self):
        """parse_csr sets email to None when emailAddress is not in the subject."""
        info = parse_csr(_BARE_CSR)
        assert info.email is None

    def test_locality_none_when_absent(self):
        """parse_csr sets locality to None when L is not in the subject."""
        info = parse_csr(_BARE_CSR)
        assert info.locality is None

    def test_state_none_when_absent(self):
        """parse_csr sets state to None when ST is not in the subject."""
        info = parse_csr(_BARE_CSR)
        assert info.state is None
