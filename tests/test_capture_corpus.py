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
from collections.abc import Iterator
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


@pytest.fixture
def fresh(cc: ModuleType) -> Iterator[ModuleType]:
    """The capture module with its remembered-names registry cleared."""
    cc.reset_seen()
    yield cc
    cc.reset_seen()


class TestV3Payloads:
    """v3 users, orders, audit logs and API credentials leak no names or ids."""

    def test_audit_activity_scrubs_names_seen_earlier(self, fresh: ModuleType) -> None:
        """A user's name inside later audit text is replaced with the same pseudonym."""
        users = fresh.sanitize({"users": [{"name": "Pat Example (ITS)", "email": "pat@example.edu"}]})
        audit = fresh.sanitize({"auditLogs": [
            {"activity": "User information of Pat Example (ITS) updated", "userName": "Pat Example (ITS)"},
            {"activity": "Group access of user Pat Example set to TEAMX"},
        ]})
        rows = audit["auditLogs"]
        assert "Pat" not in rows[0]["activity"] and "Pat" not in rows[1]["activity"]
        assert users["users"][0]["name"] in rows[0]["activity"]
        assert rows[0]["userName"] == users["users"][0]["name"]
        assert rows[1]["activity"] == (
            f"Group access of user {fresh._pseudo_person('Pat Example')} set to {fresh._pseudo_org('TEAMX')}"
        )

    def test_audit_activity_scrubs_quoted_name_and_email(self, fresh: ModuleType) -> None:
        """An org representative line loses the name, the email and the org name."""
        fresh.sanitize({"organizationName": "Example University", "requestorName": "Sam Sample"})
        out = fresh.sanitize({"activity": (
            "Organization representative 'Sam Sample (sam@example.edu)' added in 'Example University' Organization"
        )})["activity"]
        for secret in ("Sam", "sam@", "example.edu", "Example University"):
            assert secret not in out
        assert out.startswith("Organization representative 'Name-")

    def test_short_terms_not_scrubbed_from_text(self, fresh: ModuleType) -> None:
        """A three-letter group name is pseudonymized as a value but left in prose."""
        assert fresh.sanitize({"group": "ITS"})["group"].startswith("Org-")
        assert fresh.sanitize({"errorMessage": "ask ITS for access"})["errorMessage"] == "ask ITS for access"

    def test_ordered_by_string_and_detail_forms(self, fresh: ModuleType) -> None:
        """orderedBy is a person as a string (lists) and as {"user": ...} (detail)."""
        out = fresh.sanitize({"orderedBy": "Pat Example", "detail": {"orderedBy": {"user": "Pat Example"}}})
        assert out["orderedBy"] == out["detail"]["orderedBy"]["user"] == fresh._pseudo_person("Pat Example")

    def test_opaque_v3_ids_pseudonymized(self, fresh: ModuleType) -> None:
        """Alphanumeric v3 ids in bodies, params and paths are replaced consistently."""
        body = fresh.sanitize({"orderId": "-aB3dE5", "userId": "x9Y8z7", "credentialId": "c1_d2"})
        assert all(v.startswith("id-") for v in body.values())
        assert fresh.sanitize({"userIds": "x9Y8z7"})["userIds"] == body["userId"]
        path = fresh.sanitize_path("/api/v3/certinext/orders/-aB3dE5")
        assert path == f"/api/v3/certinext/orders/{body['orderId']}"

    def test_path_keeps_versions_sentinels_and_words(self, fresh: ModuleType) -> None:
        """Version segments, the sslcom-latest sentinel and plain words are not ids."""
        assert fresh.sanitize_path("/api/v3/certinext/audit-logs/modules") == "/api/v3/certinext/audit-logs/modules"
        path = fresh.sanitize_path("/api/certinext/v2/domains/12345/dcv/attempts/sslcom-latest")
        assert path.startswith("/api/certinext/v2/domains/") and path.endswith("/dcv/attempts/sslcom-latest")
        assert "12345" not in path

    def test_numeric_path_ids_unchanged_from_before(self, fresh: ModuleType) -> None:
        """Numeric path ids map exactly as the pre-v3 rule did, so v2 fixtures don't churn."""
        assert fresh.sanitize_path("/x/12345") == f"/x/{fresh._pseudo_id(12345)}"
        assert fresh.sanitize_path("/x/7") == "/x/7"

    def test_description_is_a_label_only_when_asked(self, fresh: ModuleType) -> None:
        """API credential descriptions become Cred- labels; product descriptions are untouched."""
        text = "pat-desktop (certbot mon01)"
        assert fresh.sanitize({"description": text})["description"] == text
        out = fresh.sanitize({"description": text}, label_keys=frozenset({"description"}))["description"]
        assert out == fresh._pseudo_label(text)

    def test_credential_label_matches_in_audit_text(self, fresh: ModuleType) -> None:
        """A credential's label is replaced in audit text with the same pseudonym as in /apis."""
        fresh.sanitize({"credentials": [{"description": "pat-desktop"}]}, label_keys=frozenset({"description"}))
        out = fresh.sanitize({"activity": "API credential pat-desktop updated"})["activity"]
        assert out == f"API credential {fresh._pseudo_label('pat-desktop')} updated"

    @pytest.mark.parametrize(
        ("text", "secret", "kind"),
        [
            ("API credential 'Team 30 Day (certbot mon01)' updated.", "mon01", "label"),
            ("API credential gone-desktop updated", "gone-desktop", "label"),
            ("ACME EAB credentials for robin-test1 deleted", "robin-test1", "label"),
            ("ACME EAB credentials for robin-test1 revoked", "robin-test1", "label"),
            ("ACME credential 'xyz-123' updated.", "xyz-123", "label"),
            ("New Group proxy-team created", "proxy-team", "org"),
            ("Group access of user Robin Sample set to TEAMX", "Robin", "person"),
            ("Group access of user Robin Sample set to TEAMX", "TEAMX", "org"),
            ("User information of Robin Sample (ITS) updated", "Robin", "person"),
            ("Organization representative 'Robin Sample (r@example.edu)' added in 'Example U' Organization",
             "Robin", "person"),
            ("Organization representative 'Robin Sample (r@example.edu)' added in 'Example U' Organization",
             "Example U", "org"),
        ],
    )
    def test_activity_templates_scrub_unseen_names(
        self, fresh: ModuleType, text: str, secret: str, kind: str
    ) -> None:
        """Names of deleted objects, never seen under a key, are caught by the templates."""
        out = fresh.sanitize({"activity": text})["activity"]
        assert secret not in out
        assert any(k == kind for k, _ in fresh._SEEN.values())

    def test_activity_rules_leave_generic_text(self, fresh: ModuleType) -> None:
        """Activity lines without a named object pass through unchanged."""
        for text in ("Logged in via SSO", "Certificate download (ZIP) for order 1234", "Domain deleted"):
            assert fresh.sanitize({"activity": text})["activity"] == text

    def test_role_named_after_a_person_is_scrubbed(self, fresh: ModuleType) -> None:
        """A custom role sharing a user's name is pseudonymized; generic roles stay readable."""
        fresh.sanitize({"users": [{"name": "Pat Example", "email": "pat@example.edu"}]})
        out = fresh.sanitize({"customRoles": [{"customRoleName": "Pat Example"}, {"customRoleName": "Administrator"}]})
        names = [r["customRoleName"] for r in out["customRoles"]]
        assert names == [fresh._pseudo_person("Pat Example"), "Administrator"]

    def test_identifier_is_a_domain(self, fresh: ModuleType) -> None:
        """A v3 order identifier is pseudonymized as a domain name."""
        assert fresh.sanitize({"identifier": "www.example.edu"})["identifier"] == fresh._pseudo_domain(
            "www.example.edu"
        )


class TestLeakCheck:
    """The post-write leak check finds raw values and never prints them."""

    def test_reports_raw_value_by_pseudonym(self, fresh: ModuleType, tmp_path: Path) -> None:
        """A raw name left in a written file is reported by kind and pseudonym only."""
        fresh.sanitize({"userName": "Pat Example"})
        leaky = tmp_path / "v3-audit-logs.json"
        leaky.write_text('{"activity": "deleted by pat example"}', encoding="utf-8")
        hits = fresh.leak_check([leaky])
        assert hits == [
            f"v3-audit-logs.json: raw person value found (should be {fresh._pseudo_person('Pat Example')}) at activity"
        ]
        assert "Pat" not in hits[0] and "pat" not in hits[0].split("(")[0]

    def test_clean_file_passes(self, fresh: ModuleType, tmp_path: Path) -> None:
        """A file holding only pseudonyms produces no hits."""
        out = fresh.sanitize({"users": [{"name": "Pat Example", "email": "pat@example.edu"}]})
        clean = tmp_path / "v3-users.json"
        clean.write_text(str(out), encoding="utf-8")
        assert fresh.leak_check([clean]) == []

    def test_word_boundaries(self, fresh: ModuleType, tmp_path: Path) -> None:
        """A raw value inside a longer word is not a hit."""
        fresh.sanitize({"createdBy": "Robin"})
        f = tmp_path / "x.json"
        f.write_text('{"note": "Robinson"}', encoding="utf-8")
        assert fresh.leak_check([f]) == []
