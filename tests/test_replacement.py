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

"""Tests for :mod:`certinext.replacement` and ``certinext replacement-report``.

Every certificate here is synthetic, built with ``cryptography`` against
placeholder CA names; the fake API routes the same paths the real accessors
call, so the full report/model/CLI stack runs.
"""

import copy
import csv
import datetime as dt
import io
import json
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from certinext import replacement as rp
from certinext._config import ConfigError, replacement_criteria
from certinext.cli import main as cli_main
from certinext.exceptions import CertiNextAPIError, CertiNextRateLimitError
from certinext.models.ssl_certificates import CertificateDownload
from certinext.session import CertiNextSession

NOW = dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc)

# Placeholder CA hierarchy: an "ECC" root that is distrusted, and a good one.
BAD_ROOT = "Example ECC Root CA - G3"
BAD_INT = "Example Intermediate CA - OV3"
GOOD_ROOT = "Example Root CA - G1"
GOOD_INT = "Example Intermediate CA - OV2"

CRITERIA = rp.ReplacementCriteria(issuers=[BAD_INT], key_types=["EC"], chain_cas=[BAD_ROOT])

_KeyT = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


def _name(cn: str) -> x509.Name:
    """Return an X.509 name holding only a common name.

    Args:
        cn: The common name.

    Returns:
        The name.
    """
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    subject: str, key: _KeyT, issuer: str, issuer_key: _KeyT, *, ca: bool, sans: list[str] | None = None
) -> str:
    """Build and sign a certificate, returning its PEM.

    Args:
        subject: Subject common name.
        key: The subject's private key.
        issuer: Issuer common name.
        issuer_key: The issuer's private key (signs the certificate).
        ca: Whether to mark it as a CA.
        sans: DNS SANs to add to a leaf.

    Returns:
        The PEM-encoded certificate.
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = builder.sign(issuer_key, algorithm)
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _hierarchy(root: str, intermediate: str) -> tuple[_KeyT, list[str]]:
    """Build a root and intermediate; return the intermediate key and chain PEMs.

    Args:
        root: Root common name.
        intermediate: Intermediate common name.

    Returns:
        ``(intermediate_key, [intermediate_pem, root_pem])``.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    int_key = ec.generate_private_key(ec.SECP256R1())
    root_pem = _cert(root, root_key, root, root_key, ca=True)
    int_pem = _cert(intermediate, int_key, root, root_key, ca=True)
    return int_key, [int_pem, root_pem]


_BAD_KEY, _BAD_CHAIN = _hierarchy(BAD_ROOT, BAD_INT)
_GOOD_KEY, _GOOD_CHAIN = _hierarchy(GOOD_ROOT, GOOD_INT)


def _download(leaf_key: _KeyT, *, bad: bool, sans: list[str] | None = None, bundle: bool = False) -> dict[str, Any]:
    """Build a JSON certificate-download payload.

    Args:
        leaf_key: The leaf's private key (decides the key type).
        bad: Issue from the distrusted hierarchy instead of the good one.
        sans: Leaf SANs (defaults to ``host.example.edu``).
        bundle: Serve the chain as one concatenated string inside the list.

    Returns:
        A wire-shaped download payload.
    """
    int_key, chain = (_BAD_KEY, _BAD_CHAIN) if bad else (_GOOD_KEY, _GOOD_CHAIN)
    issuer = BAD_INT if bad else GOOD_INT
    names = sans or ["host.example.edu"]
    leaf = _cert(names[0], leaf_key, issuer, int_key, ca=False, sans=names)
    return {"orderId": "ORDER-X", "certificatePem": leaf, "chainPem": ["".join(chain)] if bundle else chain}


def _facts(**kwargs: Any) -> rp.CertificateFacts:
    """Build report-level facts with sensible defaults.

    Args:
        **kwargs: Field overrides.

    Returns:
        The facts.
    """
    base: dict[str, Any] = {
        "order_number": "ORDER-00001", "common_name": "host.example.edu", "issuer": BAD_INT,
        "valid_to": NOW + dt.timedelta(days=30), "order_date": NOW - dt.timedelta(days=10),
    }
    base.update(kwargs)
    return rp.CertificateFacts(**base)


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------


def test_describe_key_families() -> None:
    """EC, RSA and Ed25519 leaves are labelled with type and size."""
    def leaf(key: _KeyT) -> x509.Certificate:
        return x509.load_pem_x509_certificate(_cert("h.example.edu", key, "i", key, ca=False).encode())

    assert rp.describe_key(leaf(ec.generate_private_key(ec.SECP384R1()))) == ("EC", 384, "EC P-384")
    assert rp.describe_key(leaf(rsa.generate_private_key(65537, 2048))) == ("RSA", 2048, "RSA 2048")
    assert rp.describe_key(leaf(ed25519.Ed25519PrivateKey.generate())) == ("Ed25519", None, "Ed25519")


@pytest.mark.parametrize("bundle", [False, True])
def test_inspect_download_reads_leaf_and_chain(bundle: bool) -> None:
    """Key, SANs, leaf issuer and every chain CA come out, list or bundled chain."""
    payload = _download(
        ec.generate_private_key(ec.SECP384R1()), bad=True,
        sans=["host.example.edu", "www.example.edu"], bundle=bundle,
    )
    result = rp.inspect_download(CertificateDownload.model_validate(payload))
    assert (result.key_type, result.key_size) == ("EC", 384)
    assert result.sans == ["host.example.edu", "www.example.edu"]
    assert result.leaf_issuer == BAD_INT
    assert result.chain_cas == [BAD_INT, BAD_ROOT]


def test_inspect_download_without_leaf_raises() -> None:
    """A download with no leaf certificate is a ValueError, not a crash."""
    with pytest.raises(ValueError, match="no leaf"):
        rp.inspect_download(CertificateDownload.model_validate({"chainPem": _BAD_CHAIN}))


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _inspected(key: _KeyT, *, bad: bool) -> rp.CertificateFacts:
    """Return facts carrying a real inspection.

    Args:
        key: Leaf key.
        bad: Distrusted hierarchy or good one.

    Returns:
        Inspected facts whose report issuer agrees with the leaf.
    """
    insp = rp.inspect_download(CertificateDownload.model_validate(_download(key, bad=bad)))
    return _facts(issuer=insp.leaf_issuer, inspection=insp)


def test_all_signals_match_is_replace() -> None:
    """EC leaf from the distrusted chain matches every signal."""
    c = rp.classify(_inspected(ec.generate_private_key(ec.SECP256R1()), bad=True), CRITERIA)
    assert c.verdict is rp.Verdict.REPLACE
    assert c.matched == ["issuer", "key", "chain"]


def test_no_signal_matches_is_ok() -> None:
    """RSA leaf from the good chain matches nothing."""
    c = rp.classify(_inspected(rsa.generate_private_key(65537, 2048), bad=False), CRITERIA)
    assert c.verdict is rp.Verdict.OK
    assert c.evaluated == ["issuer", "key", "chain"]


def test_ec_key_on_trusted_chain_is_conflict() -> None:
    """An EC leaf on the good chain is flagged for review, not counted as replace.

    Mirrors real data: EC keys issued under an RSA-rooted intermediate exist,
    so key type alone would overstate what needs replacing.
    """
    c = rp.classify(_inspected(ec.generate_private_key(ec.SECP256R1()), bad=False), CRITERIA)
    assert c.verdict is rp.Verdict.CONFLICT
    assert c.matched == ["key"]
    assert not c.verdict.needs_replacing


def test_rsa_key_on_distrusted_chain_is_conflict() -> None:
    """The reverse disagreement (RSA leaf, distrusted chain) is a conflict too."""
    c = rp.classify(_inspected(rsa.generate_private_key(65537, 2048), bad=True), CRITERIA)
    assert c.verdict is rp.Verdict.CONFLICT
    assert c.matched == ["issuer", "chain"]


def test_uninspected_uses_issuer_only() -> None:
    """Without inspection only the issuer is evaluated; key/chain are reported as such."""
    c = rp.classify(_facts(issuer=BAD_INT.upper()), CRITERIA)
    assert c.verdict is rp.Verdict.REPLACE
    assert c.unevaluated == ["key", "chain"]


def test_nothing_evaluable_is_unknown() -> None:
    """No issuer and no inspection leaves nothing to judge."""
    assert rp.classify(_facts(issuer=None), CRITERIA).verdict is rp.Verdict.UNKNOWN


def test_disabled_signal_is_not_evaluated() -> None:
    """A disabled signal can neither match nor cause a conflict."""
    criteria = CRITERIA.with_overrides(disable=["key"])
    c = rp.classify(_inspected(ec.generate_private_key(ec.SECP256R1()), bad=False), criteria)
    assert c.verdict is rp.Verdict.OK
    assert c.evaluated == ["issuer", "chain"]


# ---------------------------------------------------------------------------
# Criteria layering
# ---------------------------------------------------------------------------


def test_default_criteria_describe_the_emudhra_distrust() -> None:
    """Out of the box the criteria target the October 2026 eMudhra ECC distrust."""
    c = rp.ReplacementCriteria()
    assert c.issuers == ["InCommon Intermediate CA - OVG3C"]
    assert c.key_types == ["EC"]
    assert c.chain_cas == ["emSign ECC Root CA - G3"]
    assert c.active_signals() == ["issuer", "key", "chain"]


def test_from_config_overrides_only_named_keys() -> None:
    """A partial table keeps defaults for absent keys and normalizes key case."""
    c = rp.ReplacementCriteria.from_config({"replacement": {"key_types": ["ec", "rsa"]}})
    assert c.key_types == ["EC", "RSA"]
    assert c.issuers == list(rp.DEFAULT_ISSUERS)


def test_from_config_rejects_bad_table() -> None:
    """Unknown keys, bad key types and non-tables fail rather than being ignored."""
    with pytest.raises(ValidationError):
        rp.ReplacementCriteria.from_config({"replacement": {"issuer": ["typo"]}})
    with pytest.raises(ValidationError):
        rp.ReplacementCriteria.from_config({"replacement": {"key_types": ["ECDSA"]}})
    with pytest.raises(ValueError, match="table"):
        rp.ReplacementCriteria.from_config({"replacement": "nope"})


def test_overrides_replace_lists_and_empty_list_disables() -> None:
    """A CLI list replaces the configured one; an empty list switches the signal off."""
    c = CRITERIA.with_overrides(issuers=["Other CA"], chain_cas=[])
    assert c.issuers == ["Other CA"]
    assert c.active_signals() == ["issuer", "key"]


def test_replacement_criteria_reads_config_file(tmp_path: Path) -> None:
    """The [replacement] table is read from config.toml; a bad one is a ConfigError."""
    good = tmp_path / "good.toml"
    good.write_text('[replacement]\nissuers = ["Other CA"]\n', encoding="utf-8")
    assert replacement_criteria(good).issuers == ["Other CA"]

    bad = tmp_path / "bad.toml"
    bad.write_text('[replacement]\nkey_types = ["ECDSA"]\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="key_types"):
        replacement_criteria(bad)

    assert replacement_criteria(tmp_path / "missing.toml") == rp.ReplacementCriteria()


# ---------------------------------------------------------------------------
# Superseded detection
# ---------------------------------------------------------------------------


def _row(facts: rp.CertificateFacts) -> rp.ReportRow:
    """Wrap facts in a classified report row.

    Args:
        facts: The facts.

    Returns:
        The row.
    """
    return rp.ReportRow(facts=facts, classification=rp.classify(facts, CRITERIA))


def test_newer_same_name_supersedes_older() -> None:
    """Only the older of two certificates for the same name is superseded."""
    old = _row(_facts(order_number="ORDER-00001", order_date=NOW - dt.timedelta(days=60)))
    new = _row(_facts(order_number="ORDER-00002", order_date=NOW - dt.timedelta(days=5)))
    other = _row(_facts(order_number="ORDER-00003", common_name="other.example.edu"))
    rp.mark_superseded([old, new, other])
    assert (old.superseded, new.superseded, other.superseded) == (True, False, False)


def test_superseded_needs_every_name_covered() -> None:
    """A newer certificate covering only some of the older one's SANs does not supersede it."""
    def with_sans(order: str, days_ago: int, sans: list[str]) -> rp.ReportRow:
        insp = rp.Inspection("RSA", 2048, "RSA 2048", sans, GOOD_INT, [GOOD_INT, GOOD_ROOT])
        return _row(_facts(order_number=order, order_date=NOW - dt.timedelta(days=days_ago), inspection=insp))

    old = with_sans("ORDER-00001", 60, ["a.example.edu", "b.example.edu"])
    partial = with_sans("ORDER-00002", 5, ["a.example.edu"])
    rp.mark_superseded([old, partial])
    assert not old.superseded

    full = with_sans("ORDER-00003", 1, ["a.example.edu", "b.example.edu", "c.example.edu"])
    rp.mark_superseded([old, partial, full])
    assert old.superseded and partial.superseded and not full.superseded


# ---------------------------------------------------------------------------
# build_report against a fake API
# ---------------------------------------------------------------------------

_API = "/api/certinext/v2"


def _order_row(n: int, **kwargs: Any) -> dict[str, Any]:
    """Build an orders-report row.

    Args:
        n: Order sequence number (also used in the CN).
        **kwargs: Wire-field overrides.

    Returns:
        The wire-shaped row.
    """
    row = {
        "orderNumber": f"ORDER-{n:05d}", "domainName": f"host{n}.example.edu",
        "issuerCA": BAD_INT, "originator": "CERTInext", "groupNumber": "G-1",
        "productCode": "100", "certificateSerialNumber": f"SERIAL-{n}",
        "orderStatus": "Order Fulfilled", "certificateStatus": "Certificate Downloaded",
        "orderDate": "2026-10-01T00:00:00", "certificateExpiryDate": "2027-01-01T00:00:00",
    }
    row.update(kwargs)
    return row


class _FakeApi:
    """Exact-path router for :meth:`CertiNextClient.get` with programmable failures."""

    def __init__(self, routes: dict[str, Any]) -> None:
        """
        Args:
            routes: Path -> payload, or an exception instance (raised), or a
                list of those (consumed one per call).
        """
        self.routes = routes
        self.calls: list[str] = []

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Return or raise the canned response for ``path``.

        Args:
            path: API path.
            params: Ignored.

        Returns:
            A deep copy of the canned payload.

        Raises:
            AssertionError: For an unregistered path.
            Exception: Whatever exception the route holds.
        """
        self.calls.append(path)
        if path not in self.routes:
            raise AssertionError(f"unexpected GET {path}")
        value = self.routes[path]
        if isinstance(value, list) and value and isinstance(value[0], Exception | dict):
            value = value.pop(0) if len(value) > 1 else value[0]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def _routes() -> dict[str, Any]:
    """Build the standard fake-API routes: two valid orders and one expired.

    Returns:
        Path -> payload routes.
    """
    rows = [
        _order_row(1),
        _order_row(2, issuerCA=GOOD_INT, originator="ACME", groupNumber="G-2"),
        _order_row(3, certificateExpiryDate="2026-01-01T00:00:00"),
    ]
    return {
        f"{_API}/groups": {"groups": [{"groupNumber": "G-1", "groupName": "Portal"}]},
        f"{_API}/reports/orders": {"content": rows, "totalPages": 1},
        f"{_API}/ssl-certificates/ORDER-00001": {
            "orderId": "ORDER-00001", "status": "issued",
            "orderedBy": {"name": "Jane Doe", "email": "jane@example.edu"},
        },
        f"{_API}/ssl-certificates/ORDER-00001/certificate": _download(
            ec.generate_private_key(ec.SECP384R1()), bad=True, sans=["host1.example.edu"]
        ),
        f"{_API}/ssl-certificates/ORDER-00002": {"orderId": "ORDER-00002", "status": "issued"},
        f"{_API}/ssl-certificates/ORDER-00002/certificate": _download(
            rsa.generate_private_key(65537, 2048), bad=False, sans=["host2.example.edu"]
        ),
    }


def _session(monkeypatch: pytest.MonkeyPatch, routes: dict[str, Any]) -> tuple[CertiNextSession, _FakeApi]:
    """Return a real session whose HTTP GET is the fake router.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        routes: Routes for :class:`_FakeApi`.

    Returns:
        ``(session, fake_api)``.
    """
    sess = CertiNextSession(client_id="test", client_secret="secret")
    api = _FakeApi(routes)
    monkeypatch.setattr(sess._client, "get", api.get)
    return sess, api


def test_report_without_inspection_makes_no_per_order_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Issuer-only mode reads the report once, drops expired rows, and resolves group names."""
    sess, api = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, now=NOW)
    assert [r.facts.order_number for r in report.rows] == ["ORDER-00001", "ORDER-00002"]
    assert [r.verdict for r in report.rows] == [rp.Verdict.REPLACE, rp.Verdict.OK]
    assert report.rows[0].facts.group_name == "Portal"
    assert report.rows[1].facts.group_name is None
    assert not any("ssl-certificates" in c for c in api.calls)


def test_report_with_inspection_fills_details(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inspection adds key, SANs, chain and who ordered it; signals all agree."""
    sess, _ = _session(monkeypatch, _routes())
    seen: list[str] = []
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, on_progress=lambda f: seen.append(f.order_number))
    first = report.rows[0]
    assert first.facts.inspection and first.facts.inspection.key_label == "EC P-384"
    assert first.facts.ordered_by_name == "Jane Doe"
    assert first.classification.matched == ["issuer", "key", "chain"]
    assert report.rows[1].verdict is rp.Verdict.OK
    assert seen == ["ORDER-00001", "ORDER-00002"]


def test_report_filters_by_originator_and_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """Originator and group filters are case-insensitive; groups match by name or number."""
    sess, _ = _session(monkeypatch, _routes())
    assert [r.facts.order_number for r in rp.build_report(sess, CRITERIA, now=NOW, originators=["acme"]).rows] == [
        "ORDER-00002"
    ]
    assert [r.facts.order_number for r in rp.build_report(sess, CRITERIA, now=NOW, groups=["portal"]).rows] == [
        "ORDER-00001"
    ]


def test_inspection_failure_is_recorded_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """One order's API error lands on its row; the rest of the report still builds."""
    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00002"] = CertiNextAPIError(500, "boom")
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW)
    broken = report.rows[1]
    assert broken.facts.error and "500" in broken.facts.error
    assert broken.classification.unevaluated == ["key", "chain"]
    assert report.summarize(report.rows)["errors"] == 1


def test_rate_limit_is_retried_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 429 waits Retry-After and retries; the second attempt's data is used."""
    routes = _routes()
    detail = routes[f"{_API}/ssl-certificates/ORDER-00001"]
    routes[f"{_API}/ssl-certificates/ORDER-00001"] = [CertiNextRateLimitError(429, "slow", retry_after=7), detail]
    sess, _ = _session(monkeypatch, routes)
    waits: list[float] = []
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, sleep=waits.append)
    assert waits == [7]
    assert report.rows[0].facts.error is None and report.rows[0].facts.inspection


def test_conflicts_counted_separately_from_replace() -> None:
    """The headline count excludes conflicts; they get their own figure."""
    rows = [
        _row(_inspected(ec.generate_private_key(ec.SECP256R1()), bad=True)),
        _row(_inspected(ec.generate_private_key(ec.SECP256R1()), bad=False)),
    ]
    summary = rp.ReplacementReport.summarize(rows)
    assert (summary["needs_replacing"], summary["replace"], summary["conflict"]) == (1, 1, 1)


def test_summary_and_breakdown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Summary counts verdicts; breakdown groups them without hardcoded names."""
    sess, _ = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, now=NOW)
    summary = report.summarize(report.rows)
    assert (summary["valid"], summary["needs_replacing"], summary["ok"]) == (2, 1, 1)
    by_origin = {b["originator"]: b["needs_replacing"] for b in report.breakdown(report.rows, "originator")}
    assert by_origin == {"CERTInext": 1, "ACME": 0}
    assert [r.facts.order_number for r in report.select()] == ["ORDER-00001"]
    assert len(report.select(include_ok=True)) == 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def run_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Callable[..., tuple[int, str, str]]:
    """Run ``certinext replacement-report`` against the fake API.

    Pins "now", points ``CERTINEXT_CONFIG`` at a temp file (with optional
    contents), and patches the command's session.

    Returns:
        A ``run(argv, routes=None, config=None) -> (exit, stdout, stderr)`` callable.
    """
    monkeypatch.setattr(rp, "_utcnow", lambda: NOW)

    def run(argv: list[str], routes: dict[str, Any] | None = None, config: str | None = None) -> tuple[int, str, str]:
        """Invoke the command.

        Args:
            argv: Arguments after ``replacement-report``.
            routes: Fake-API routes (defaults to :func:`_routes`).
            config: config.toml contents, or None for no file.

        Returns:
            ``(exit_code, stdout, stderr)``.
        """
        cfg = tmp_path / "config.toml"
        if config is not None:
            cfg.write_text(config, encoding="utf-8")
        monkeypatch.setenv("CERTINEXT_CONFIG", str(cfg))
        sess, _ = _session(monkeypatch, routes or _routes())
        monkeypatch.setattr("certinext.cli.replacement_report.session", lambda ctx, **kw: sess)
        try:
            code = cli_main(["replacement-report", *argv])
        except SystemExit as exc:
            code = int(exc.code or 0)
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


def test_cli_json(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--json carries criteria, summary and certificate rows; stdout is pure JSON."""
    code, out, _ = run_cli(
        ["--json", "--all", "--group-by", "originator"], config=f'[replacement]\nissuers = ["{BAD_INT}"]\n'
    )
    assert code == 0
    doc = json.loads(out)
    assert doc["summary"]["needs_replacing"] == 1
    assert doc["criteria"]["issuers"] == [BAD_INT]
    assert doc["criteria"]["chain_cas"] == list(rp.DEFAULT_CHAIN_CAS)
    assert [c["order_number"] for c in doc["certificates"]] == ["ORDER-00001", "ORDER-00002"]
    assert doc["certificates"][0]["days_left"] == (dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc) - NOW).days
    assert {b["originator"] for b in doc["breakdown"]} == {"CERTInext", "ACME"}


def test_cli_table_uses_configured_criteria(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """The [replacement] table drives classification; the summary line follows the table."""
    code, out, _ = run_cli([], config=f'[replacement]\nissuers = ["{BAD_INT}"]\n')
    assert code == 0
    assert "ORDER-00001" in out and "ORDER-00002" not in out
    assert "1 of 2 valid certificates need replacing; 0 conflicts to review" in out
    assert "not inspected; use --inspect" in out


def test_cli_flag_overrides_config(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--issuer replaces the configured issuer list for one run."""
    code, out, _ = run_cli(
        ["--issuer", GOOD_INT, "--json"], config=f'[replacement]\nissuers = ["{BAD_INT}"]\n'
    )
    assert code == 0
    assert [c["order_number"] for c in json.loads(out)["certificates"]] == ["ORDER-00002"]


def test_cli_csv_with_inspection(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--csv writes parseable rows to stdout and the summary to stderr."""
    code, out, err = run_cli(["--csv", "--inspect", "--all", "--issuer", BAD_INT, "--chain-ca", BAD_ROOT])
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["verdict"] for r in rows] == ["replace", "ok"]
    assert rows[0]["chain_cas"] == f"{BAD_INT};{BAD_ROOT}"
    assert "need replacing" in err and "need replacing" not in out


def test_cli_inspection_error_exits_1(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """A certificate that could not be inspected makes the report incomplete: exit 1."""
    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00002/certificate"] = CertiNextAPIError(404, "gone")
    code, out, _ = run_cli(["--inspect", "--all"], routes=routes)
    assert code == 1
    assert "inspection errors" in out


@pytest.mark.parametrize(
    ("argv", "config"),
    [
        (["--csv", "--json"], None),
        (["--disable-signal", "issuer", "--disable-signal", "key", "--disable-signal", "chain"], None),
        (["--key-type", "ECDSA"], None),
        ([], '[replacement]\nkey_types = "EC"\n'),
    ],
)
def test_cli_usage_and_config_errors_exit_2(
    run_cli: Callable[..., tuple[int, str, str]], argv: list[str], config: str | None
) -> None:
    """Conflicting outputs, no enabled signal, bad flags and a bad config all exit 2."""
    code, _, _ = run_cli(argv, config=config)
    assert code == 2
