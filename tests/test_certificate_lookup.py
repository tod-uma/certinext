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

"""Offline SAN and lookup contract tests; all certificates and contacts are synthetic.

Contact blocks below test raw pass-through only, not vendor response availability.
"""

import csv
import datetime as dt
import io
import ipaddress
import json
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certinext._inspection_cache import InspectionCache
from certinext.certificate_lookup import CertificateEntry, LookupField, enrich_sans, lookup_certificates
from certinext.cli import main
from certinext.cli._shared import _output_stream
from certinext.exceptions import CertiNextRateLimitError
from certinext.models.orders import OrderRecord
from certinext.models.ssl_certificates import CertificateDownload, SslOrder
from certinext.retry import RetryPolicy
from certinext.session import CertiNextSession


def _download(serial: int = 171) -> CertificateDownload:
    """Build a test leaf with DNS, IP, email, and URI SANs and a parseable chain."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lb.example.org")])
    now = dt.datetime.now(dt.timezone.utc)
    leaf = (
        (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("node.example.org"),
                        x509.DNSName("*.example.org"),
                        x509.IPAddress(ipaddress.ip_address("192.0.2.1")),
                        x509.RFC822Name("certs@example.org"),
                        x509.UniformResourceIdentifier("https://example.org/cert"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )
    return CertificateDownload.model_validate({"certificatePem": leaf, "chainPem": [leaf]})


def _record(order: str = "ORDER-1", serial: str = "AB") -> OrderRecord:
    """Build a synthetic report row using the model's established wire keys."""
    return OrderRecord.model_validate(
        {
            "orderNumber": order,
            "certificateSerialNumber": serial,
            "commonName": "lb.example.org",
            "requestNumber": "REQ-1",
            "certificateExpiryDate": "2020-01-01T00:00:00Z",
        }
    )


def _session(*records: OrderRecord) -> Mock:
    """Provide an offline session whose detail accessor returns a real bound order."""
    sess = Mock(spec=CertiNextSession)
    sess.retry = None
    sess.retrying = MagicMock()  # a context manager, unlike a plain Mock
    sess.orders = Mock()
    sess.ssl = Mock()
    sess.catalog = Mock()
    sess.sandbox = False
    sess.orders.get_list.return_value = list(records or [_record()])
    client = Mock()
    client.get.return_value = _download().as_dict()
    sess.ssl.get.return_value = SslOrder.from_payload(
        client,
        {
            "orderId": "ORDER-1",
            "recipientEmails": ["current@example.org"],
            "delegation": {"unverifiedFixtureShape": True},
        },
    )
    return sess


def test_shared_cache_and_live_contacts(tmp_path: Path) -> None:
    """A replacement-compatible warm download avoids downloads, but not live details."""
    sess = _session()
    cache = InspectionCache(tmp_path)
    cache.put("ORDER-1", "AB", _download().as_dict(), {"email": "old@example.org"})
    result = lookup_certificates(sess, "NODE.EXAMPLE.ORG.", cache=cache)
    assert len(result.matches) == 1 and not result.errors
    entry = result.matches[0]
    assert entry.from_cache
    assert entry.sans == [
        "node.example.org",
        "*.example.org",
        "192.0.2.1",
        "certs@example.org",
        "https://example.org/cert",
    ]
    assert entry.details and entry.details["recipientEmails"] == ["current@example.org"]
    sess.ssl.get.assert_called_once_with("ORDER-1")
    sess.ssl.get.return_value._client.get.assert_not_called()


@pytest.mark.parametrize(
    "field,query", [("cn", "LB.EXAMPLE.ORG."), ("order", "order-1"), ("serial", "00:AB"), ("request", "req-1")]
)
def test_report_identifiers_do_not_download(field: LookupField, query: str) -> None:
    """Explicit report identifiers skip the SAN scan and preserve duplicate matches."""
    sess = _session(_record(), _record("ORDER-2"))
    result = lookup_certificates(sess, query, field=field)
    assert len(result.matches) == (1 if field == "order" else 2)
    sess.ssl.get.return_value._client.get.assert_not_called()


def test_cold_cache_round_trip(tmp_path: Path) -> None:
    """Cold enrichment writes entries consumable by the existing inspection cache."""
    sess = _session()
    cache = InspectionCache(tmp_path)
    entries = [CertificateEntry(_record())]
    enrich_sans(sess, entries, cache)
    assert not entries[0].error and cache.writes == 1
    cached = cache.get("ORDER-1", "AB")
    assert cached and cached.download["certificatePem"]
    second = [CertificateEntry(_record())]
    enrich_sans(sess, second, cache)
    assert second[0].from_cache and second[0].sans == entries[0].sans


def test_decimal_report_serial_matches_emsign_leaf() -> None:
    """The sandbox emSign report's decimal serial matches its downloaded leaf."""
    sess = _session(_record(serial="171"))
    entries = [CertificateEntry(_record(serial="171"))]
    enrich_sans(sess, entries)
    assert entries[0].sans and entries[0].error is None


def test_wrong_decimal_report_serial_still_fails() -> None:
    """Decimal compatibility never accepts a different issued certificate."""
    sess = _session(_record(serial="172"))
    entries = [CertificateEntry(_record(serial="172"))]
    enrich_sans(sess, entries)
    assert entries[0].sans is None and entries[0].error


def test_cache_keeps_only_order_contact_name_and_email(tmp_path: Path) -> None:
    """The shared cache stores only the documented contact fields."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(
        sess.ssl.get.return_value._client,
        {"orderId": "ORDER-1", "orderedBy": {"name": "Example", "email": "a@example.org", "phone": "private"}},
    )
    cache = InspectionCache(tmp_path)
    enrich_sans(sess, [CertificateEntry(_record())], cache)
    hit = cache.get("ORDER-1", "AB")
    assert hit is not None and hit.ordered_by == {"name": "Example", "email": "a@example.org"}


def test_bad_chain_does_not_invalidate_leaf_sans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cache eligibility failure leaves a successful leaf SAN inspection intact."""
    sess = _session()
    cache = InspectionCache(tmp_path)
    monkeypatch.setattr("certinext.certificate_lookup.inspect_download", Mock(side_effect=ValueError("bad chain")))
    entries = [CertificateEntry(_record())]
    enrich_sans(sess, entries, cache)
    assert entries[0].sans and entries[0].error is None and cache.writes == 0


def test_san_scan_runs_under_default_retry_policy() -> None:
    """Without a caller policy the scan retries under the defaults (ADR 0025)."""
    sess = _session()
    enrich_sans(sess, [CertificateEntry(_record())])
    sess.retrying.assert_called_once_with(RetryPolicy())


def test_lookup_keeps_the_callers_retry_policy() -> None:
    """A policy the caller set on the session is the one the lookup uses."""
    sess = _session()
    mine = RetryPolicy(attempts=7)
    sess.retry = mine
    lookup_certificates(sess, "ORDER-1", field="order")
    sess.retrying.assert_called_once_with(mine)


def test_exhausted_rate_limit_is_recorded_per_row() -> None:
    """A 429 left after the client's retries fails only that row."""
    sess = _session(_record(), _record("ORDER-2"))
    sess.ssl.get.side_effect = CertiNextRateLimitError(429, {}, retry_after=0.25)
    entries = [CertificateEntry(r) for r in sess.orders.get_list()]
    enrich_sans(sess, entries)
    assert all(e.error and "RateLimit" in e.error for e in entries)


def test_cold_san_match_reuses_live_detail() -> None:
    """A cold SAN match uses the order already read during that same scan."""
    sess = _session()
    result = lookup_certificates(sess, "node.example.org", field="san")
    assert len(result.matches) == 1 and result.matches[0].details
    sess.ssl.get.assert_called_once_with("ORDER-1")


def test_bad_cache_falls_back_and_live_mismatch_fails(tmp_path: Path) -> None:
    """A mismatched cached leaf is a miss; a mismatched live leaf is never cached."""
    sess = _session()
    cache = InspectionCache(tmp_path)
    cache.put("ORDER-1", "AB", _download(172).as_dict(), {})
    entries = [CertificateEntry(_record())]
    enrich_sans(sess, entries, cache)
    assert not entries[0].error and not entries[0].from_cache
    sess.ssl.get.return_value._client.get.return_value = _download(172).as_dict()
    cache.refresh = True
    failed = [CertificateEntry(_record())]
    enrich_sans(sess, failed, cache)
    assert failed[0].sans is None and failed[0].error
    assert cache.writes == 2  # the bad seed plus the corrected live download


def test_unknown_sans_and_missing_order_remain_visible() -> None:
    """Pending rows and broken issued rows are retained as unknown, never empty SANs."""
    sess = _session(
        OrderRecord.model_validate({"commonName": "pending.example.org"}),
        OrderRecord.model_validate({"certificateSerialNumber": "AB"}),
    )
    result = lookup_certificates(sess, "absent.example.org", field="san")
    assert not result.matches and result.unknown_sans == 2 and len(result.errors) == 1


def test_no_wildcard_expansion() -> None:
    """A stored wildcard SAN is matched literally, never used as a coverage rule."""
    sess = _session()
    assert not lookup_certificates(sess, "other.example.org", field="san").matches
    assert lookup_certificates(sess, "*.example.org", field="san").matches


def test_list_csv_and_lookup_cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Both commands are wired; CSV and JSON preserve all SANs and live raw details."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    assert main(["list-certificates", "--sans", "--no-cache", "--csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert "node.example.org" in json.loads(rows[0]["sans"])
    assert main(["lookup-certificate", "00:AB", "--field", "serial", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["matches"][0]["details"]["recipientEmails"]
    assert main(["lookup-certificate", "absent", "--field", "order", "--json"]) == 3
    capsys.readouterr()
    assert main(["lookup-certificate", "--help"]) == 0


def test_list_sans_pending_order_exits_partial(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A pending order with unknown SANs makes --sans output incomplete."""
    sess = _session(OrderRecord.model_validate({"orderNumber": "PENDING-1"}))
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    assert main(["list-certificates", "--sans", "--no-cache", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)[0]["sans"] is None


def test_lookup_partial_cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """A failed scan exits 1 with an explicit incomplete JSON result."""
    sess = _session()
    sess.ssl.get.side_effect = ValueError("malformed synthetic response")
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    assert main(["lookup-certificate", "node.example.org", "--field", "san", "--no-cache", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert not payload["complete"] and payload["errors"]


def test_no_serial_or_chain_is_never_cached(tmp_path: Path) -> None:
    """SAN output can succeed without a chain or report serial, but cannot seed cache."""
    sess = _session()
    cache = InspectionCache(tmp_path)
    download = _download().as_dict()
    download["chainPem"] = []
    sess.ssl.get.return_value._client.get.return_value = download
    entries = [CertificateEntry(_record()), CertificateEntry(_record("ORDER-2", ""))]
    enrich_sans(sess, entries, cache)
    assert all(e.sans and not e.error for e in entries)
    assert cache.writes == 0


def test_expired_cache_and_refresh(tmp_path: Path) -> None:
    """Expired entries and forced refresh both download again."""
    sess = _session()
    old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    cache = InspectionCache(tmp_path, clock=lambda: old)
    cache.put("ORDER-1", "AB", _download().as_dict(), {})
    current = InspectionCache(tmp_path)
    entries = [CertificateEntry(_record())]
    enrich_sans(sess, entries, current)
    assert not entries[0].from_cache and current.writes == 1
    current.refresh = True
    enrich_sans(sess, [CertificateEntry(_record())], current)
    assert current.writes == 2


def test_absent_contacts_are_not_fabricated() -> None:
    """A raw response without delegation remains without delegation in output."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"orderId": "ORDER-1"})
    result = lookup_certificates(sess, "ORDER-1", field="order")
    assert result.matches[0].details == {"orderId": "ORDER-1"}


@pytest.mark.parametrize(
    "args",
    [
        ["list-certificates", "--sans", "--no-cache", "--refresh-cache"],
        ["lookup-certificate", "   "],
    ],
)
def test_cache_usage_errors_are_local(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    """Conflicting or invalid flags fail before opening a session."""
    assert main(args) == 2
    capsys.readouterr()


@pytest.mark.parametrize("environment", ["prod", "sandbox"])
def test_requestor_from_captured_corpus(environment: str) -> None:
    """Requestor matching uses captured response fields, not a guessed schema."""
    fixture = Path(__file__).parent / "fixtures" / "corpus" / environment / "ssl-certificates-detail.json"
    detail = json.loads(fixture.read_text(encoding="utf-8"))["response"]["body"]
    sess = _session(_record(), _record("ORDER-2"))
    client = Mock()
    sess.ssl.get.return_value = SslOrder.from_payload(client, detail)
    for identifier in (detail["requestor"]["name"], detail["requestor"]["email"]):
        sess.ssl.get.reset_mock()
        result = lookup_certificates(sess, "  " + identifier.upper() + "  ", field="requestor")
        assert len(result.matches) == 2 and result.unknown_requestors == 0 and not result.errors
        assert sess.ssl.get.call_count == 2  # a matching detail is not fetched again
        client.get.assert_not_called()  # requestor search never downloads certificates


@pytest.mark.parametrize("who", [None, "invalid", [], {}, {"name": "", "email": None}, {"name": ["bad"]}])
def test_unavailable_requestor_is_unknown(who: object) -> None:
    """Malformed or missing requestor data limits completeness without inventing identity."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(
        Mock(),
        {
            "orderId": "ORDER-1",
            "requestor": who,
            "orderedBy": {"name": "Example Person"},
        },
    )
    result = lookup_certificates(sess, "Example Person", field="requestor")
    assert not result.matches and result.unknown_requestors == 1


def test_requestor_search_keeps_successes_after_detail_failure() -> None:
    """A failed detail read cannot hide later matches or become a clean no-match result."""
    sess = _session(_record(), OrderRecord.model_validate({"orderNumber": "PENDING-2"}))
    client = Mock()
    sess.ssl.get.side_effect = [
        ValueError("synthetic malformed response"),
        SslOrder.from_payload(client, {"requestor": {"email": "person@example.org"}}),
    ]
    result = lookup_certificates(sess, "person@example.org", field="requestor")
    assert len(result.matches) == 1 and result.matches[0].record.order_number == "PENDING-2"
    assert result.unknown_requestors == 1 and len(result.errors) == 1
    client.get.assert_not_called()


def test_requestor_does_not_substring_match() -> None:
    """A name or email must match completely, without substring or wildcard expansion."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"requestor": {"name": "Example Person"}})
    result = lookup_certificates(sess, "Example", field="requestor")
    assert not result.matches and result.unknown_requestors == 0


@pytest.mark.parametrize(
    "who,query",
    [({"name": "Example Person"}, "person@example.org"), ({"email": "person@example.org"}, "Example Person")],
)
def test_missing_requestor_target_is_unknown(who: dict[str, str], query: str) -> None:
    """An absent name or email cannot prove a non-match for that field."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"requestor": who})
    result = lookup_certificates(sess, query, field="requestor")
    assert not result.matches and result.unknown_requestors == 1


def test_requestor_cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI requestor matching reports unavailable rows explicitly and returns partial success."""
    sess = _session(_record(), _record("ORDER-2"))
    sess.ssl.get.side_effect = [
        SslOrder.from_payload(Mock(), {"requestor": {"email": "person@example.org"}}),
        SslOrder.from_payload(Mock(), {"orderId": "ORDER-2"}),
    ]
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    assert main(["lookup-certificate", "person@example.org", "--field", "requestor", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["matches"]) == 1 and payload["unknown_requestors"] == 1 and not payload["complete"]


def test_requestor_cli_ignores_cache(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """An unnecessary cache flag warns without preventing the live requestor lookup."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"requestor": {"email": "person@example.org"}})
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    assert main(["lookup-certificate", "person@example.org", "--field", "requestor", "--cache", "--json"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["cache"]["enabled"] is False
    assert "Cache options ignored" in output.err
    sess.ssl.get.assert_called_once()


@pytest.mark.parametrize(
    "cache_flags",
    [["--cache"], ["--no-cache"], ["--refresh-cache"], ["--cache-max-age", "3"], ["--no-cache", "--refresh-cache"]],
)
def test_report_field_lookup_ignores_cache(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], cache_flags: list[str]
) -> None:
    """A report-field lookup continues when cache options cannot help it."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"orderId": "ORDER-1"})
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    assert main(["lookup-certificate", "ORDER-1", "--field", "order", *cache_flags, "--json"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["cache"]["enabled"] is False
    assert "Cache options ignored" in output.err


def test_report_field_lookup_ignores_file_cache_dir(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A non-scanning lookup accepts an unused cache directory naming a file."""
    sess = _session()
    sess.ssl.get.return_value = SslOrder.from_payload(Mock(), {"orderId": "ORDER-1"})
    monkeypatch.setattr("certinext.cli.lookup_certificate.session", lambda ctx: sess)
    blocker = tmp_path / "cache-file"
    blocker.write_text("x", encoding="utf-8")
    assert main(["lookup-certificate", "ORDER-1", "--field", "order", "--cache-dir", str(blocker), "--json"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["cache"]["enabled"] is False
    assert "Cache options ignored" in output.err
    assert blocker.read_text(encoding="utf-8") == "x"


@pytest.mark.parametrize("cache_flag", ["--cache", "--no-cache"])
def test_listing_without_sans_ignores_cache(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], cache_flag: str
) -> None:
    """A regular listing still runs when an unnecessary cache flag is present."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    assert main(["list-certificates", cache_flag, "--json"]) == 0
    output = capsys.readouterr()
    assert "ORDER-1" in output.out
    assert "Cache options ignored" in output.err


def test_listing_ignores_cache_directory_without_creating_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An unused directory option neither rejects a file nor creates a new directory."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    new_dir = tmp_path / "new-cache"
    for path in (blocker, new_dir):
        assert main(["list-certificates", "--cache-dir", str(path), "--json"]) == 0
        output = capsys.readouterr()
        assert "ORDER-1" in output.out
        assert "Cache options ignored" in output.err
    assert blocker.read_text(encoding="utf-8") == "x"
    assert not new_dir.exists()


def test_listing_without_cache_flags_has_no_ignored_notice(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An ordinary listing has no cache diagnostic."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    assert main(["list-certificates", "--json"]) == 0
    assert "Cache options ignored" not in capsys.readouterr().err


def test_ignored_cache_notice_uses_json_logging(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The cache notice remains a JSON log event under the JSON log format."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    assert main(["--log-format", "json", "list-certificates", "--cache", "--json"]) == 0
    output = capsys.readouterr()
    notices = [json.loads(line) for line in output.err.splitlines() if "Cache options ignored" in line]
    assert len(notices) == 1
    assert notices[0]["event"] == "Cache options ignored"


@pytest.mark.parametrize("option", ["-o", "--output"])
@pytest.mark.parametrize("format_flag", [None, "--json", "--csv"])
def test_list_output_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    option: str,
    format_flag: str | None,
) -> None:
    """Both output spellings save the selected format without data on stdout."""
    record = OrderRecord.model_validate({**_record().as_dict(), "commonName": "caf\u00e9.example.org"})
    sess = _session(record)
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    path = tmp_path / "certificates.txt"
    path.write_text("old content", encoding="utf-8")
    args = ["list-certificates", option, str(path), "--yes"]
    if format_flag:
        args.append(format_flag)
    assert main(args) == 0
    assert not capsys.readouterr().out
    text = path.read_text(encoding="utf-8")
    assert "old content" not in text
    if format_flag == "--json":
        assert json.loads(text)[0]["commonName"] == record.common_name
    elif format_flag == "--csv":
        assert list(csv.DictReader(io.StringIO(text)))[0]["common_name"] == record.common_name
        assert b"\r\n" not in path.read_bytes()
    else:
        assert "ORDER-1" in text and "caf\u00e9.example.org" in text
        assert "1 certificate(s)" in text and "\x1b[" not in text


@pytest.mark.parametrize("invalid", ["directory", "missing-parent"])
def test_list_invalid_output_before_session(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, invalid: str
) -> None:
    """Unusable output paths fail before authentication or API calls."""
    session_mock = Mock()
    monkeypatch.setattr("certinext.cli.list_certificates.session", session_mock)
    path = tmp_path if invalid == "directory" else tmp_path / "missing" / "out.json"
    assert main(["list-certificates", "--json", "-o", str(path)]) == 2
    session_mock.assert_not_called()
    assert "--output" in capsys.readouterr().err


def test_list_existing_output_refused_before_session(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """An unattended overwrite requires --yes before any session starts."""
    path = tmp_path / "existing.json"
    path.write_text("keep me", encoding="utf-8")
    session_mock = Mock()
    monkeypatch.setattr("certinext.cli.list_certificates.session", session_mock)
    assert main(["list-certificates", "--json", "-o", str(path)]) == 1
    session_mock.assert_not_called()
    assert path.read_text(encoding="utf-8") == "keep me"
    assert "--yes" in capsys.readouterr().err


def test_list_invalid_cache_dir_precedes_overwrite_prompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A bad cache directory is reported before asking to replace output."""
    output = tmp_path / "existing.json"
    output.write_text("keep me", encoding="utf-8")
    blocker = tmp_path / "cache-file"
    blocker.write_text("x", encoding="utf-8")
    stdin = Mock()
    stdin.isatty.return_value = True
    monkeypatch.setattr("certinext.cli._shared.sys.stdin", stdin)
    prompt = Mock(return_value="yes")
    monkeypatch.setattr("certinext.cli._shared.prompt_stderr", prompt)
    assert main(["list-certificates", "--sans", "--cache-dir", str(blocker), "-o", str(output)]) == 2
    prompt.assert_not_called()
    assert output.read_text(encoding="utf-8") == "keep me"
    assert "--cache-dir" in capsys.readouterr().err


def test_stdout_broken_pipe_exits_without_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """A consumer closing stdout is translated to a normal CLI exit."""
    stream = Mock()
    stream.write.side_effect = BrokenPipeError("closed")
    monkeypatch.setattr("certinext.cli._shared.sys.stdout", stream)
    with pytest.raises(typer.Exit) as exc:
        with _output_stream(None) as out:
            out.write("data")
    assert exc.value.exit_code == 1


def test_list_existing_output_confirmed_before_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An interactive answer is collected before authentication."""
    path = tmp_path / "existing.json"
    path.write_text("old", encoding="utf-8")
    stdin = Mock()
    stdin.isatty.return_value = True
    monkeypatch.setattr("certinext.cli._shared.sys.stdin", stdin)
    prompt = Mock(return_value="yes")
    monkeypatch.setattr("certinext.cli._shared.prompt_stderr", prompt)
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}

    def checked_session(ctx: object) -> Mock:
        """Require the overwrite answer before session creation."""
        prompt.assert_called_once()
        return sess

    monkeypatch.setattr("certinext.cli.list_certificates.session", checked_session)
    assert main(["list-certificates", "--json", "-o", str(path)]) == 0
    assert json.loads(path.read_text(encoding="utf-8"))[0]["orderNumber"] == "ORDER-1"


def test_list_output_open_failure_preserves_listing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A locked file falls back to stdout and reports failure like replacement-report."""
    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    monkeypatch.setattr("certinext.cli._shared.open", Mock(side_effect=PermissionError("locked")), raising=False)
    assert main(["list-certificates", "--json", "-o", str(tmp_path / "out.json")]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)[0]["orderNumber"] == "ORDER-1"
    assert "Cannot write output file" in captured.err


def test_list_output_close_failure_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A flush or close error is visible and produces a failing status."""

    class FailingClose(io.StringIO):
        """Stand in for a file whose final flush fails."""

        def close(self) -> None:
            """Fail as a filesystem close can fail after writes."""
            super().close()
            raise OSError("disk full")

    sess = _session()
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    monkeypatch.setattr("certinext.cli._shared.open", lambda *_a, **_kw: FailingClose(), raising=False)
    assert main(["list-certificates", "--json", "-o", str(tmp_path / "out.json")]) == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "Cannot finish writing output file" in captured.err


@pytest.mark.parametrize("format_flag", [None, "--json", "--csv"])
def test_list_empty_output_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    format_flag: str | None,
) -> None:
    """Empty results still produce the selected file format."""
    sess = _session()
    sess.orders.get_list.return_value = []
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    path = tmp_path / "empty.txt"
    args = ["list-certificates", "-o", str(path)]
    if format_flag:
        args.append(format_flag)
    assert main(args) == 0
    assert not capsys.readouterr().out
    text = path.read_text(encoding="utf-8")
    if format_flag == "--json":
        assert json.loads(text) == []
    elif format_flag == "--csv":
        assert list(csv.reader(io.StringIO(text))) == [["order_number", "sans", "error"]]
    else:
        assert "(no certificates)" in text


def test_list_partial_sans_output_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """Partial inspection writes the data file while retaining stderr and exit status."""
    sess = _session(OrderRecord.model_validate({"orderNumber": "PENDING-1"}))
    sess.catalog.ca_by_product_code.return_value = {}
    monkeypatch.setattr("certinext.cli.list_certificates.session", lambda ctx: sess)
    path = tmp_path / "partial.json"
    assert main(["list-certificates", "--sans", "--no-cache", "--json", "-o", str(path)]) == 1
    captured = capsys.readouterr()
    assert not captured.out and "SANs unknown" in captured.err
    assert json.loads(path.read_text(encoding="utf-8"))[0]["sans"] is None
