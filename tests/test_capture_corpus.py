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

"""Tests for the corpus sanitizer in scripts/capture_corpus.py.

The corpus is committed to a repository mirrored publicly, so the sanitizer
is the only thing between a capture and publishing real hostnames and
contact emails. These tests pin the cases that once leaked or were mangled.
"""

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture(scope="module")
def cc() -> ModuleType:
    """Load scripts/capture_corpus.py as a module (it is not a package)."""
    path = Path(__file__).resolve().parent.parent / "scripts" / "capture_corpus.py"
    spec = importlib.util.spec_from_file_location("capture_corpus", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A CAA answer as it appears in DCV diagnostics (found.rawData,
# consensus.consensusValue), with placeholder names.
_CAA = (
    'example.edu.\t\t559\tIN\tCAA\t0 iodef "mailto:soc@example.edu"\n'
    'example.edu.\t\t559\tIN\tCAA\t0 issue "ssl.com"\n'
)


class TestFreeTextScrubbing:
    """Hostnames and emails embedded in free-text values are pseudonymized."""

    def test_raw_dns_answer_has_no_original_names(self, cc: ModuleType) -> None:
        """A CAA answer under rawData keeps its structure but loses every real name."""
        out = cc.sanitize({"found": {"rawData": _CAA, "ttl": "559"}})["found"]["rawData"]
        assert "example.edu" not in out
        assert "soc@" not in out
        assert "ssl.com" not in out
        assert "\t559\tIN\tCAA\t0 iodef \"mailto:user-" in out
        assert "@example.invalid\"" in out

    def test_trailing_root_dot_is_kept(self, cc: ModuleType) -> None:
        """A fully qualified name stays fully qualified after pseudonymizing."""
        out = cc.sanitize({"queryName": "example.edu."})["queryName"]
        assert out == cc._pseudo_domain("example.edu") + "."

    def test_same_name_maps_consistently(self, cc: ModuleType) -> None:
        """Embedded names use the same mapping as whole-value domain keys."""
        out = cc.sanitize({"consensusValue": "a.example.edu", "domainName": "a.example.edu"})
        assert out["consensusValue"] == out["domainName"]

    @pytest.mark.parametrize(
        ("value", "secret"),
        [("ABC123.txt", "ABC123"), ("www.example.edu.txt", "example")],
    )
    def test_dcv_token_filename_scrubbed(self, cc: ModuleType, value: str, secret: str) -> None:
        """expected.fileName is free text: a token or domain inside it is pseudonymized."""
        out = cc.sanitize({"expected": {"fileName": value}})["expected"]["fileName"]
        assert secret not in out
        assert out.endswith(".txt")

    def test_empty_filename_kept(self, cc: ModuleType) -> None:
        """An empty fileName (DNS-method attempts) stays empty."""
        assert cc.sanitize({"fileName": ""}) == {"fileName": ""}

    def test_ip_addresses_untouched(self, cc: ModuleType) -> None:
        """IPv4 addresses inside free text are not mistaken for hostnames."""
        assert cc.sanitize({"errorMessage": "timeout from 3.120.195.69"})["errorMessage"] == (
            "timeout from 3.120.195.69"
        )

    def test_email_host_not_rewritten_twice(self, cc: ModuleType) -> None:
        """An email is replaced whole; its pseudonym's domain is not re-hashed."""
        out = cc.sanitize({"caMessage": "contact soc@example.edu"})["caMessage"]
        assert out == "contact " + cc._pseudo_email("soc@example.edu")

    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("answer bücher.de.", "bücher"),
            ("answer пример.рф", "пример"),
            ("mailto:soc@bücher.de", "soc@"),
            ("answer example.xn--p1ai", "example"),
            ("answer host.xn--bcher-kva.de", "xn--bcher-kva"),
        ],
    )
    def test_internationalized_names_scrubbed(self, cc: ModuleType, text: str, secret: str) -> None:
        """Unicode and punycode names inside free text lose every non-TLD label."""
        out = cc.sanitize({"rawData": text})["rawData"]
        assert secret not in out


class TestSentinelIds:
    """Vendor literal ids survive; real ids are still pseudonymized."""

    def test_sslcom_latest_kept(self, cc: ModuleType) -> None:
        """attemptId 'sslcom-latest' is a vendor literal and must survive."""
        assert cc.sanitize({"attemptId": "sslcom-latest"}) == {"attemptId": "sslcom-latest"}

    def test_numeric_attempt_id_pseudonymized(self, cc: ModuleType) -> None:
        """A real numeric attempt id is replaced, keeping its digit count."""
        out = cc.sanitize({"attemptId": "729645"})["attemptId"]
        assert out != "729645"
        assert out.isdigit()
        assert len(out) == 6
