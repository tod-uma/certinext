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

import contextlib
import copy
import csv
import datetime as dt
import io
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest
import structlog.testing
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from certinext import replacement as rp
from certinext._config import ConfigError, replacement_criteria
from certinext._inspection_cache import DEFAULT_MAX_AGE
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

# G3-style criteria (ca signal off) for the issuer/key/chain tests.
CRITERIA = rp.ReplacementCriteria(cas=[], issuers=[BAD_INT], key_types=["EC"], chain_cas=[BAD_ROOT])
# The default migration criteria: every emSign certificate needs replacing.
CA_CRITERIA = rp.ReplacementCriteria()

# Fake catalog product codes: "100" is emSign (the _order_row default), "200" SSL.com,
# "300" sits in an uncategorised product family.
EMSIGN_CODE, SSLCOM_CODE, OTHER_CODE = "100", "200", "300"

# config.toml for the CLI tests written before the ca signal: issuer signal only.
G3_CONFIG = f'[replacement]\ncas = []\nissuers = ["{BAD_INT}"]\n'
NO_CA_CONFIG = "[replacement]\ncas = []\n"

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


def test_missing_chain_leaves_chain_unevaluated() -> None:
    """No served chain is missing evidence: an affected leaf stays 'replace', not 'conflict'."""
    payload = _download(ec.generate_private_key(ec.SECP256R1()), bad=True)
    payload["chainPem"] = []
    insp = rp.inspect_download(CertificateDownload.model_validate(payload))
    c = rp.classify(_facts(inspection=insp), CRITERIA)
    assert c.verdict is rp.Verdict.REPLACE
    assert c.unevaluated == ["chain"]


# ---------------------------------------------------------------------------
# Criteria layering
# ---------------------------------------------------------------------------


def test_default_criteria_target_every_emsign_certificate() -> None:
    """Out of the box only the ca signal is on, naming emSign (ADR 0021)."""
    c = rp.ReplacementCriteria()
    assert c.cas == ["EMSIGN"]
    assert (c.issuers, c.key_types, c.chain_cas) == ([], [], [])
    assert c.active_signals() == ["ca"]


def test_ecc_g3_constants_keep_the_old_criteria_reachable() -> None:
    """The G3 values survive as constants, and the old DEFAULT_* names alias them."""
    assert rp.ECC_G3_ISSUERS == ("InCommon Intermediate CA - OVG3C",)
    assert rp.ECC_G3_KEY_TYPES == ("EC",)
    assert rp.ECC_G3_CHAIN_CAS == ("emSign ECC Root CA - G3",)
    assert (rp.DEFAULT_ISSUERS, rp.DEFAULT_KEY_TYPES, rp.DEFAULT_CHAIN_CAS) == (
        rp.ECC_G3_ISSUERS, rp.ECC_G3_KEY_TYPES, rp.ECC_G3_CHAIN_CAS,
    )
    g3 = rp.ReplacementCriteria().with_overrides(
        issuers=list(rp.ECC_G3_ISSUERS), key_types=list(rp.ECC_G3_KEY_TYPES),
        chain_cas=list(rp.ECC_G3_CHAIN_CAS), disable=["ca"],
    )
    assert g3.active_signals() == ["issuer", "key", "chain"]


def test_ca_names_are_upper_cased() -> None:
    """CA names from config or flags match the catalog's upper-case names."""
    assert rp.ReplacementCriteria(cas=[" emsign ", "SslCom"]).cas == ["EMSIGN", "SSLCOM"]
    assert CA_CRITERIA.with_overrides(cas=["sslcom"]).cas == ["SSLCOM"]


def test_from_config_overrides_only_named_keys() -> None:
    """A partial table keeps defaults for absent keys and normalizes key case."""
    c = rp.ReplacementCriteria.from_config({"replacement": {"key_types": ["ec", "rsa"]}})
    assert c.key_types == ["EC", "RSA"]
    assert c.issuers == []
    assert c.cas == list(rp.DEFAULT_CAS)
    assert c.active_signals() == ["ca", "key"]


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


def _with_sans(order: str, days_ago: int, sans: list[str]) -> rp.ReportRow:
    """Build an inspected row with the given SANs.

    Args:
        order: Order number.
        days_ago: Order age in days (decides recency).
        sans: The leaf's SANs.

    Returns:
        The row.
    """
    insp = rp.Inspection("RSA", 2048, "RSA 2048", sans, GOOD_INT, [GOOD_INT, GOOD_ROOT])
    return _row(_facts(
        order_number=order, common_name=sans[0], order_date=NOW - dt.timedelta(days=days_ago), inspection=insp,
    ))


def test_cn_only_match_is_only_possibly_superseded() -> None:
    """Without known SANs a newer same-CN certificate cannot prove coverage, so it is flagged 'maybe'."""
    old = _row(_facts(order_number="ORDER-00001", order_date=NOW - dt.timedelta(days=60)))
    new = _row(_facts(order_number="ORDER-00002", order_date=NOW - dt.timedelta(days=5)))
    other = _row(_facts(order_number="ORDER-00003", common_name="other.example.edu"))
    rp.mark_superseded([old, new, other])
    assert (old.superseded, new.superseded, other.superseded) == (False, False, False)
    assert (old.possibly_superseded, new.possibly_superseded, other.possibly_superseded) == (True, False, False)


def test_failed_inspection_is_not_superseded_by_inspected_newer() -> None:
    """An older row whose inspection failed may carry SANs the newer one lacks: 'maybe', not superseded."""
    old = _row(_facts(order_number="ORDER-00001", common_name="a.example.edu",
                      order_date=NOW - dt.timedelta(days=60), error="boom"))
    new = _with_sans("ORDER-00002", 5, ["a.example.edu", "c.example.edu"])
    rp.mark_superseded([old, new])
    assert not old.superseded and old.possibly_superseded


def test_latest_only_keeps_possibly_superseded() -> None:
    """--latest-only hides confirmed superseded rows but keeps CN-only matches, and counts both."""
    cn_old = _row(_facts(order_number="ORDER-00001", order_date=NOW - dt.timedelta(days=60)))
    cn_new = _row(_facts(order_number="ORDER-00002", order_date=NOW - dt.timedelta(days=5)))
    san_old = _with_sans("ORDER-00003", 60, ["x.example.edu"])
    san_new = _with_sans("ORDER-00004", 5, ["x.example.edu"])
    rows = [cn_old, cn_new, san_old, san_new]
    rp.mark_superseded(rows)
    report = rp.ReplacementReport(criteria=CRITERIA, rows=rows, inspected=True, started_at=NOW)
    kept = [r.facts.order_number for r in report.population(latest_only=True)]
    assert kept == ["ORDER-00001", "ORDER-00002", "ORDER-00004"]
    summary = report.summarize(rows)
    assert (summary["superseded"], summary["possibly_superseded"]) == (1, 1)


def test_superseded_needs_every_name_covered() -> None:
    """A newer certificate covering only some of the older one's SANs does not supersede it."""
    old = _with_sans("ORDER-00001", 60, ["a.example.edu", "b.example.edu"])
    partial = _with_sans("ORDER-00002", 5, ["a.example.edu"])
    rp.mark_superseded([old, partial])
    assert not old.superseded

    full = _with_sans("ORDER-00003", 1, ["a.example.edu", "b.example.edu", "c.example.edu"])
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


def _catalog() -> dict[str, Any]:
    """Build a catalog payload mapping the fake product codes to CAs.

    Wrapped in a ``products`` envelope because :class:`_FakeApi` treats a bare
    list of dicts as a queue of successive responses.

    Returns:
        Wire-shaped product categories: emSign, SSL.com, and an
        uncategorised family.
    """
    return {"products": [
        {"categoryName": "SSL/TLS Certificates", "products": [{"productCode": EMSIGN_CODE}]},
        {"categoryName": "SSL.com", "products": [{"productCode": SSLCOM_CODE}]},
        {"categoryName": "Private PKI Products", "products": [{"productCode": OTHER_CODE}]},
    ]}


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
        f"{_API}/catalog/products": _catalog(),
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


def test_rate_limit_retries_twice_then_records_the_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two 429s still recover; a third gives up on that row only."""
    routes = _routes()
    detail = routes[f"{_API}/ssl-certificates/ORDER-00001"]
    limited = CertiNextRateLimitError(429, "slow", retry_after=7)
    routes[f"{_API}/ssl-certificates/ORDER-00001"] = [limited, limited, detail]
    sess, _ = _session(monkeypatch, routes)
    waits: list[float] = []
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, sleep=waits.append)
    assert waits == [7, 7]
    assert report.rows[0].facts.error is None

    routes[f"{_API}/ssl-certificates/ORDER-00001"] = [limited]
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, sleep=lambda _s: None)
    assert report.rows[0].facts.error and report.rows[0].facts.error.startswith("rate limited")
    assert report.rows[1].facts.error is None


def test_parallel_inspection_matches_sequential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Several workers produce the same rows as one, and report progress for every certificate."""
    def snapshot(workers: int) -> tuple[list[Any], list[str]]:
        """Build an inspected report and reduce it to comparable values."""
        sess, _ = _session(monkeypatch, _routes())
        seen: list[str] = []
        report = rp.build_report(
            sess, CRITERIA, inspect=True, now=NOW, workers=workers, on_progress=lambda f: seen.append(f.order_number)
        )
        rows = [
            (r.facts.order_number, r.verdict, r.facts.error, r.facts.inspection and r.facts.inspection.key_label)
            for r in report.rows
        ]
        return rows, sorted(seen)

    assert snapshot(4) == snapshot(1)


def test_workers_must_be_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero workers is a caller bug, not a silent no-op."""
    sess, _ = _session(monkeypatch, _routes())
    with pytest.raises(ValueError, match="workers"):
        rp.build_report(sess, CRITERIA, inspect=True, now=NOW, workers=0)


def test_missing_cryptography_still_aborts_with_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    """ImportError raised in a worker thread reaches the caller instead of becoming a row error."""
    def no_crypto(_download: Any) -> Any:
        """Stand in for an install without ``cryptography``."""
        raise ImportError("cryptography")

    monkeypatch.setattr(rp, "inspect_download", no_crypto)
    sess, _ = _session(monkeypatch, _routes())
    with pytest.raises(ImportError):
        rp.build_report(sess, CRITERIA, inspect=True, now=NOW, workers=4)


def test_backoff_holds_other_workers_until_the_pause_ends() -> None:
    """While one worker waits out a 429, the others block before their next request."""
    release = threading.Event()

    def held_sleep(_seconds: float) -> None:
        """Sleep until the test releases it, instead of for real."""
        release.wait(5)

    backoff = rp._Backoff(held_sleep)
    pauser = threading.Thread(target=backoff.pause, args=(7,))
    pauser.start()
    for _ in range(200):
        if not backoff._clear.is_set():
            break
        time.sleep(0.01)
    waiter = threading.Thread(target=backoff.wait)
    waiter.start()
    waiter.join(0.2)
    assert waiter.is_alive()
    release.set()
    pauser.join(5)
    waiter.join(5)
    assert not waiter.is_alive()


def test_malformed_responses_are_recorded_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """A download failing model validation, or a non-dict order detail, lands on its row only."""
    routes = _routes()
    bad = routes[f"{_API}/ssl-certificates/ORDER-00001/certificate"]
    bad["certificatePem"] = [bad["certificatePem"]]  # a list where a string belongs
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW)
    assert report.rows[0].facts.error and report.rows[0].facts.error.startswith("unexpected response")
    assert report.rows[1].facts.error is None and report.rows[1].facts.inspection

    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00002"] = "not a dict"
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW)
    assert report.rows[1].facts.error and "Unexpected response type" in report.rows[1].facts.error


def test_download_without_chain_is_an_inspection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A download with a leaf but no chain is inspected, but flagged so the run is incomplete."""
    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00001/certificate"]["chainPem"] = None
    sess, _ = _session(monkeypatch, routes)
    row = rp.build_report(sess, CRITERIA, inspect=True, now=NOW).rows[0]
    assert row.facts.inspection and row.facts.error and "no chain" in row.facts.error
    assert row.verdict is rp.Verdict.REPLACE
    assert row.classification.unevaluated == ["chain"]


def test_issued_rows_missing_fields_are_listed_not_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Issued rows with no expiry or order number go to ``incomplete``; expired ones are still skipped."""
    routes = _routes()
    report_rows = routes[f"{_API}/reports/orders"]["content"]
    report_rows += [
        _order_row(4, certificateExpiryDate=None),
        _order_row(5, orderNumber=None),
        _order_row(6, orderNumber=None, certificateExpiryDate="2026-01-01T00:00:00"),
    ]
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, now=NOW)
    assert [r.facts.order_number for r in report.rows] == ["ORDER-00001", "ORDER-00002"]
    assert [(i.order_number, i.common_name, i.reason) for i in report.incomplete] == [
        ("ORDER-00004", "host4.example.edu", "no certificate expiry date"),
        (None, "host5.example.edu", "no order number"),
    ]


def test_group_filter_fails_when_group_names_cannot_be_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    """A group filter with no name lookup would silently drop named groups, so it raises instead."""
    routes = _routes()
    routes[f"{_API}/groups"] = CertiNextAPIError(500, "boom")
    sess, _ = _session(monkeypatch, routes)
    with pytest.raises(CertiNextAPIError):
        rp.build_report(sess, CRITERIA, now=NOW, groups=["portal"])
    report = rp.build_report(sess, CRITERIA, now=NOW)
    assert len(report.rows) == 2 and report.rows[0].facts.group_name is None


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


def test_report_records_start_and_end_times(monkeypatch: pytest.MonkeyPatch) -> None:
    """started_at is the reference "now"; ended_at is taken after classification."""
    later = NOW + dt.timedelta(minutes=20)
    monkeypatch.setattr(rp, "_utcnow", lambda: later)
    sess, _ = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, now=NOW)
    assert (report.started_at, report.ended_at) == (NOW, later)
    assert report.cache is None


# ---------------------------------------------------------------------------
# CA signal and migration tracking (ADR 0021)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ca", "verdict"),
    [
        ("EMSIGN", rp.Verdict.REPLACE),
        ("SSLCOM", rp.Verdict.OK),
        (None, rp.Verdict.UNKNOWN),  # product code missing from the catalog
        ("UNKNOWN", rp.Verdict.UNKNOWN),  # code in an uncategorised or ambiguous family
    ],
)
def test_ca_signal_classification(ca: str | None, verdict: rp.Verdict) -> None:
    """Under the default criteria the CA alone decides; an unmapped CA is missing evidence."""
    c = rp.classify(_facts(ca=ca), CA_CRITERIA)
    assert c.verdict is verdict
    assert c.unevaluated == ([] if verdict is not rp.Verdict.UNKNOWN else ["ca"])


def test_ca_signal_combines_with_others() -> None:
    """An SSL.com cert from a matching issuer is a conflict, not silently OK."""
    criteria = CA_CRITERIA.with_overrides(issuers=[BAD_INT])
    c = rp.classify(_facts(ca="SSLCOM", issuer=BAD_INT), criteria)
    assert c.verdict is rp.Verdict.CONFLICT
    assert (c.evaluated, c.matched) == (["ca", "issuer"], ["issuer"])


def _ca_row(order: str, days_ago: int, ca: str, sans: list[str] | None = None, cn: str | None = None) -> rp.ReportRow:
    """Build a row classified under the default (CA) criteria.

    Args:
        order: Order number.
        days_ago: Order age in days (decides recency).
        ca: The row's CA.
        sans: Leaf SANs; ``None`` leaves the row uninspected (CN only).
        cn: Common name; defaults to the first SAN or ``host.example.edu``.

    Returns:
        The classified row.
    """
    insp = rp.Inspection("RSA", 2048, "RSA 2048", sans, GOOD_INT, [GOOD_INT, GOOD_ROOT]) if sans else None
    facts = _facts(
        order_number=order, common_name=cn or (sans[0] if sans else "host.example.edu"),
        order_date=NOW - dt.timedelta(days=days_ago), ca=ca, inspection=insp,
    )
    return rp.ReportRow(facts=facts, classification=rp.classify(facts, CA_CRITERIA))


def test_newer_sslcom_cert_replaces_emsign() -> None:
    """A covering newer SSL.com cert is recorded as the replacement, with its CA."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu", "b.example.edu"])
    new = _ca_row("ORDER-00002", 5, "SSLCOM", ["a.example.edu", "b.example.edu", "c.example.edu"])
    rp.mark_superseded([old, new])
    assert (old.replaced_by, old.replaced_by_ca, old.possibly_replaced_by) == ("ORDER-00002", "SSLCOM", None)
    assert old.superseded and not old.outstanding
    assert new.replaced_by is None  # an OK row is never "replaced"


def test_newer_emsign_cert_supersedes_but_does_not_replace() -> None:
    """A newer emSign renewal carries the work forward: the old row is superseded, the new one outstanding."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00002", 5, "EMSIGN", ["a.example.edu"])
    rp.mark_superseded([old, new])
    assert old.superseded and old.renewed and old.replaced_by is None and not old.outstanding
    assert old.renewed_by == "ORDER-00002" and new.renewed_by is None
    assert new.outstanding


def test_renewed_by_names_the_newest_renewal() -> None:
    """With two emSign renewals, renewed_by is the newer one, and a re-run resets it."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    mid = _ca_row("ORDER-00002", 30, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00003", 5, "EMSIGN", ["a.example.edu"])
    rp.mark_superseded([old, mid, new])
    assert (old.renewed_by, mid.renewed_by, new.renewed_by) == ("ORDER-00003", "ORDER-00003", None)
    rp.mark_superseded([old])
    assert old.renewed_by is None and not old.renewed


def test_partial_sslcom_coverage_is_not_a_replacement() -> None:
    """An SSL.com cert missing one of the old SANs leaves the emSign cert outstanding."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu", "b.example.edu"])
    new = _ca_row("ORDER-00002", 5, "SSLCOM", ["a.example.edu"])
    rp.mark_superseded([old, new])
    assert old.replaced_by is None and old.outstanding


def test_cn_only_sslcom_match_is_possibly_replaced() -> None:
    """Without known SANs on the old cert, a same-CN SSL.com cert is only a possible replacement.

    It stays outstanding: the SSL.com cert may lack SANs the emSign cert has
    (external review finding 1), so a CN match must never clear the work.
    """
    old = _ca_row("ORDER-00001", 60, "EMSIGN")
    new = _ca_row("ORDER-00002", 5, "SSLCOM")
    rp.mark_superseded([old, new])
    assert (old.replaced_by, old.possibly_replaced_by) == (None, "ORDER-00002")
    assert old.possibly_superseded and old.outstanding


@pytest.mark.parametrize("coverer_ca", ["SSLCOM", "EMSIGN"])
def test_coverer_with_unknown_sans_never_clears_the_row(coverer_ca: str) -> None:
    """An inspected row matched only by a newer cert's CN stays outstanding.

    The newer cert's inspection failed, so its names() fell back to the CN;
    that is no proof it covers the old SANs. It is only a *possible*
    replacement or renewal (external review rc7, finding 1).
    """
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00002", 5, coverer_ca, cn="a.example.edu")
    assert old.facts.sans_known and not new.facts.sans_known
    rp.mark_superseded([old, new])
    assert not (old.superseded or old.renewed or old.replaced_by)
    assert old.possibly_superseded and old.outstanding
    assert old.possibly_replaced_by == ("ORDER-00002" if coverer_ca == "SSLCOM" else None)


def test_confirmed_coverer_wins_over_newer_cn_only_one() -> None:
    """A confirmed SSL.com replacement is recorded even when a newer CN-only match exists."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    confirmed = _ca_row("ORDER-00002", 20, "SSLCOM", ["a.example.edu"])
    cn_only = _ca_row("ORDER-00003", 2, "SSLCOM", cn="a.example.edu")
    rp.mark_superseded([old, confirmed, cn_only])
    assert (old.replaced_by, old.possibly_replaced_by) == ("ORDER-00002", None)
    assert old.superseded and not old.possibly_superseded and not old.outstanding


def test_coverer_with_unevaluated_ca_is_not_a_replacement() -> None:
    """An OK coverer whose CA is unmapped proves no CA move (external review finding 2).

    With ca plus issuer active, a newer cert with an unmapped product code and
    a non-matching issuer scores OK on the issuer alone; it must not count as
    the emSign cert's replacement.
    """
    criteria = CA_CRITERIA.with_overrides(issuers=[BAD_INT])
    sans = ["a.example.edu"]
    insp = rp.Inspection("RSA", 2048, "RSA 2048", sans, GOOD_INT, [GOOD_INT, GOOD_ROOT])
    old_insp = rp.Inspection("RSA", 2048, "RSA 2048", sans, BAD_INT, [BAD_INT])
    old_f = _facts(order_number="ORDER-00001", common_name=sans[0], order_date=NOW - dt.timedelta(days=60),
                   ca="EMSIGN", issuer=BAD_INT, inspection=old_insp)
    new_f = _facts(order_number="ORDER-00002", common_name=sans[0], order_date=NOW - dt.timedelta(days=5),
                   ca=None, issuer=GOOD_INT, inspection=insp)
    old = rp.ReportRow(facts=old_f, classification=rp.classify(old_f, criteria))
    new = rp.ReportRow(facts=new_f, classification=rp.classify(new_f, criteria))
    assert (old.verdict, new.verdict, new.classification.unevaluated) == (rp.Verdict.REPLACE, rp.Verdict.OK, ["ca"])
    rp.mark_superseded([old, new])
    # Superseded (CA-blind), but neither replaced nor renewed: the work stays counted.
    assert old.superseded and old.replaced_by is None and not old.renewed and old.outstanding
    report = rp.ReplacementReport(criteria=criteria, rows=[old, new], inspected=True, started_at=NOW)
    assert report.select(outstanding=True) == [old]


def test_unknown_coverer_does_not_carry_the_work() -> None:
    """A newer cert with an unmapped CA (UNKNOWN) supersedes but does not clear the emSign row."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00002", 5, "UNKNOWN", ["a.example.edu"])
    rp.mark_superseded([old, new])
    assert new.verdict is rp.Verdict.UNKNOWN
    assert old.superseded and not old.renewed and old.outstanding


def test_newest_sslcom_coverer_wins() -> None:
    """With two SSL.com replacements the newest is recorded, whatever the input order."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    first = _ca_row("ORDER-00002", 20, "SSLCOM", ["a.example.edu"])
    second = _ca_row("ORDER-00003", 2, "SSLCOM", ["a.example.edu"])
    rp.mark_superseded([second, old, first])
    assert old.replaced_by == "ORDER-00003"
    assert first.replaced_by is None  # OK rows are never marked


def test_older_sslcom_cert_does_not_replace() -> None:
    """Coverage only counts forward in time: an emSign cert newer than the SSL.com one is outstanding."""
    sslcom = _ca_row("ORDER-00001", 60, "SSLCOM", ["a.example.edu"])
    emsign = _ca_row("ORDER-00002", 5, "EMSIGN", ["a.example.edu"])
    rp.mark_superseded([sslcom, emsign])
    assert emsign.replaced_by is None and emsign.outstanding


def test_mark_superseded_is_idempotent_for_replacements() -> None:
    """Re-running after the coverer is gone clears the stale replacement."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00002", 5, "SSLCOM", ["a.example.edu"])
    rp.mark_superseded([old, new])
    rp.mark_superseded([old])
    assert (old.replaced_by, old.replaced_by_ca, old.superseded) == (None, None, False)


def test_migration_counts_and_outstanding_filter() -> None:
    """summarize() leads with outstanding/replaced; outstanding=True lists only the work left."""
    replaced = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    replacement = _ca_row("ORDER-00002", 5, "SSLCOM", ["a.example.edu"])
    maybe = _ca_row("ORDER-00003", 60, "EMSIGN", cn="b.example.edu")
    maybe_new = _ca_row("ORDER-00004", 5, "SSLCOM", cn="b.example.edu")
    renewed_old = _ca_row("ORDER-00005", 60, "EMSIGN", ["c.example.edu"])
    renewed_new = _ca_row("ORDER-00006", 5, "EMSIGN", ["c.example.edu"])
    untouched = _ca_row("ORDER-00007", 30, "EMSIGN", ["d.example.edu"])
    rows = [replaced, replacement, maybe, maybe_new, renewed_old, renewed_new, untouched]
    rp.mark_superseded(rows)
    report = rp.ReplacementReport(criteria=CA_CRITERIA, rows=rows, inspected=True, started_at=NOW)

    summary = report.summarize(rows)
    assert summary["needs_replacing"] == 5
    # The CN-only match (ORDER-00003) stays outstanding; possibly_replaced is a subset of it.
    assert (summary["outstanding"], summary["replaced"], summary["possibly_replaced"]) == (3, 1, 1)
    # outstanding + replaced + superseded-without-replacement partitions needs_replacing.
    renewed = sum(1 for r in rows if r.verdict.needs_replacing and r.renewed and not r.replaced_by)
    assert summary["outstanding"] + summary["replaced"] + renewed == summary["needs_replacing"]
    assert sorted(r.facts.order_number for r in report.select(outstanding=True)) == [
        "ORDER-00003", "ORDER-00006", "ORDER-00007",
    ]
    assert report.select(outstanding=True, include_ok=True) == report.select(outstanding=True)

    by_ca = {b["ca"]: b for b in report.breakdown(rows, "ca")}
    assert (by_ca["EMSIGN"]["valid"], by_ca["EMSIGN"]["outstanding"], by_ca["EMSIGN"]["replaced"]) == (5, 3, 1)
    assert by_ca["SSLCOM"]["ok"] == 2
    assert "possibly_replaced" not in by_ca["EMSIGN"]


def test_row_json_carries_ca_and_replacement() -> None:
    """to_dict() exposes the CA and replacement fields for JSON/CSV consumers."""
    old = _ca_row("ORDER-00001", 60, "EMSIGN", ["a.example.edu"])
    new = _ca_row("ORDER-00002", 5, "SSLCOM", ["a.example.edu"])
    rp.mark_superseded([old, new])
    d = old.to_dict(NOW)
    assert (d["ca"], d["replaced_by"], d["replaced_by_ca"], d["possibly_replaced_by"], d["outstanding"]) == (
        "EMSIGN", "ORDER-00002", "SSLCOM", None, False,
    )


def _ca_routes() -> dict[str, Any]:
    """Build routes where order 2 is an SSL.com cert and order 3 has an unmapped code.

    Returns:
        Path -> payload routes.
    """
    routes = _routes()
    rows = routes[f"{_API}/reports/orders"]["content"]
    rows[1]["productCode"] = SSLCOM_CODE
    rows.append(_order_row(4, productCode="999", orderDate="2026-10-20T00:00:00"))
    return routes


def test_report_labels_rows_by_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_report joins product codes against the catalog once and classifies by CA."""
    sess, api = _session(monkeypatch, _ca_routes())
    report = rp.build_report(sess, CA_CRITERIA, now=NOW)
    got = {r.facts.order_number: (r.facts.ca, r.verdict) for r in report.rows}
    assert got == {
        "ORDER-00001": ("EMSIGN", rp.Verdict.REPLACE),
        "ORDER-00002": ("SSLCOM", rp.Verdict.OK),
        "ORDER-00004": (None, rp.Verdict.UNKNOWN),
    }
    assert api.calls.count(f"{_API}/catalog/products") == 1


def test_catalog_failure_is_fatal_only_when_ca_is_active(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the catalog the CA signal would turn every emSign row into UNKNOWN, so it raises."""
    routes = _ca_routes()
    routes[f"{_API}/catalog/products"] = CertiNextAPIError(503, "down")
    sess, _ = _session(monkeypatch, routes)
    with pytest.raises(CertiNextAPIError):
        rp.build_report(sess, CA_CRITERIA, now=NOW)

    report = rp.build_report(sess, CRITERIA, now=NOW)
    assert [r.facts.ca for r in report.rows] == [None, None, None]
    assert [r.verdict for r in report.rows][:2] == [rp.Verdict.REPLACE, rp.Verdict.OK]


def test_empty_catalog_is_fatal_only_when_ca_is_active(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 2xx catalog with no products would turn every row UNKNOWN: fatal like a failed read.

    External review finding 3: an empty map otherwise gave "0 outstanding".
    """
    routes = _ca_routes()
    routes[f"{_API}/catalog/products"] = {"products": []}
    sess, _ = _session(monkeypatch, routes)
    with pytest.raises(ValueError, match="lists no products"):
        rp.build_report(sess, CA_CRITERIA, now=NOW)
    assert [r.facts.ca for r in rp.build_report(sess, CRITERIA, now=NOW).rows] == [None, None, None]


def test_cli_empty_catalog_exits_1(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """The CLI turns an empty catalog into exit 1 with no report, not a '0 outstanding' summary."""
    routes = _migration_routes()
    routes[f"{_API}/catalog/products"] = {"products": []}
    code, out, _ = run_cli([], routes=routes)
    assert code == 1 and "outstanding" not in out


def test_unmapped_codes_and_unknown_ca_names_are_warned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A partial catalog and a mistyped --ca are named in warnings, not left as quiet 'unknown'."""
    # Replace the module logger outright: capture_logs() misses a logger cached by an earlier test.
    logger = structlog.testing.CapturingLogger()
    monkeypatch.setattr(rp, "log", logger)
    sess, _ = _session(monkeypatch, _ca_routes())
    rp.build_report(sess, CA_CRITERIA.with_overrides(cas=["EMSIGN", "SSL.COM"]), now=NOW)
    warnings = {c.args[0]: c.kwargs for c in logger.calls if c.method_name == "warning"}
    unmapped = warnings["Orders with a product code the catalog does not list; their CA is unknown"]
    assert (unmapped["orders"], unmapped["product_codes"]) == (1, "999")
    assert warnings["Requested CA not named by the product catalog; it matches nothing"]["cas"] == "SSL.COM"

    logger.calls.clear()
    rp.build_report(sess, CRITERIA, now=NOW)  # ca signal off: nothing to warn about
    assert not [c for c in logger.calls if c.method_name == "warning"]


def test_issued_since_filters_on_order_date(monkeypatch: pytest.MonkeyPatch) -> None:
    """issued_since keeps orders placed on or after it (naive = UTC) and drops undated ones."""
    routes = _ca_routes()
    routes[f"{_API}/reports/orders"]["content"].append(_order_row(5, orderDate=None))
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CA_CRITERIA, now=NOW, issued_since=dt.datetime(2026, 10, 20))
    assert [r.facts.order_number for r in report.rows] == ["ORDER-00004"]
    aware = rp.build_report(sess, CA_CRITERIA, now=NOW, issued_since=dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc))
    assert len(aware.rows) == 3


def _cross_scope_routes() -> dict[str, Any]:
    """Build #40's case: emSign order 1 (portal, G-1) replaced by SSL.com order 5 (ACME, G-2).

    Order 2 (ACME, G-2, ``host2``) is out of scope for a portal report and
    covers nothing in it.

    Returns:
        Path -> payload routes.
    """
    routes = _migration_routes()
    order5 = routes[f"{_API}/reports/orders"]["content"][-1]
    order5.update(originator="ACME", groupNumber="G-2")
    return routes


@pytest.mark.parametrize("scope", [{"originators": ["CERTInext"]}, {"groups": ["portal"]}])
def test_scoped_report_sees_replacement_outside_scope_uninspected(
    monkeypatch: pytest.MonkeyPatch, scope: dict[str, list[str]]
) -> None:
    """#40: an out-of-scope SSL.com cert with the same CN still counts, as a possible replacement."""
    sess, api = _session(monkeypatch, _cross_scope_routes())
    report = rp.build_report(sess, CA_CRITERIA, now=NOW, **scope)  # type: ignore[arg-type]
    assert [r.facts.order_number for r in report.rows] == ["ORDER-00001"]
    assert report.rows[0].possibly_replaced_by == "ORDER-00005"
    assert not any("ssl-certificates" in c for c in api.calls)


@pytest.mark.parametrize("scope", [{"originators": ["CERTInext"]}, {"groups": ["portal"]}])
def test_scoped_report_sees_replacement_outside_scope_inspected(
    monkeypatch: pytest.MonkeyPatch, scope: dict[str, list[str]]
) -> None:
    """#40: inspection confirms the out-of-scope replacement and downloads nothing unrelated."""
    sess, api = _session(monkeypatch, _cross_scope_routes())
    totals: list[int] = []
    seen: list[str] = []
    report = rp.build_report(
        sess, CA_CRITERIA, inspect=True, now=NOW, on_total=totals.append,
        on_progress=lambda f: seen.append(f.order_number), **scope,  # type: ignore[arg-type]
    )
    [row] = report.rows
    assert (row.facts.order_number, row.replaced_by, row.replaced_by_ca, row.outstanding) == (
        "ORDER-00001", "ORDER-00005", "SSLCOM", False,
    )
    counts = rp.ReplacementReport.summarize(report.rows)
    assert (counts["outstanding"], counts["replaced"]) == (0, 1)
    assert totals == [1, 2] and seen == ["ORDER-00001", "ORDER-00005"]
    assert not any("ORDER-00002" in c for c in api.calls)


def test_out_of_scope_rows_never_listed_or_counted_as_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    """Out-of-scope certs only feed matching: not listed, and an incomplete one is not reported."""
    routes = _cross_scope_routes()
    routes[f"{_API}/reports/orders"]["content"].append(
        _order_row(6, originator="ACME", certificateExpiryDate=None)
    )
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CA_CRITERIA, now=NOW, originators=["CERTInext"])
    assert [r.facts.order_number for r in report.rows] == ["ORDER-00001"]
    assert report.incomplete == []


def test_possible_coverers_needs_a_shared_name_and_newer_order() -> None:
    """Only a newer out-of-scope cert sharing a name with an in-scope one is worth inspecting."""
    scoped = [_facts(order_number="IN", common_name="a.example.edu", order_date=NOW - dt.timedelta(days=10))]
    newer = _facts(order_number="NEW", common_name="A.example.edu", order_date=NOW - dt.timedelta(days=1))
    older = _facts(order_number="OLD", common_name="a.example.edu", order_date=NOW - dt.timedelta(days=20))
    other = _facts(order_number="OTHER", common_name="b.example.edu", order_date=NOW - dt.timedelta(days=1))
    assert [f.order_number for f in rp._possible_coverers(scoped, [newer, older, other])] == ["NEW"]


def test_possible_coverers_boundaries() -> None:
    """Equal recency is not newer; an undated cert is oldest; an in-scope SAN (not only its CN) counts."""
    when, until = NOW - dt.timedelta(days=10), NOW + dt.timedelta(days=30)
    insp = rp.Inspection("RSA", 2048, "RSA 2048", ["a.example.edu", "b.example.edu"], GOOD_INT, [GOOD_INT, GOOD_ROOT])
    scoped = [_facts(order_number="IN", common_name="a.example.edu", order_date=when, valid_to=until, inspection=insp)]
    tie = _facts(order_number="TIE", common_name="a.example.edu", order_date=when, valid_to=until)
    later_expiry = _facts(
        order_number="LATER", common_name="a.example.edu", order_date=when, valid_to=until + dt.timedelta(days=1),
    )
    undated = _facts(order_number="UNDATED", common_name="a.example.edu", order_date=None)
    by_san = _facts(order_number="BYSAN", common_name="b.example.edu", order_date=NOW - dt.timedelta(days=1))
    picked = rp._possible_coverers(scoped, [tie, later_expiry, undated, by_san])
    assert [f.order_number for f in picked] == ["LATER", "BYSAN"]


def _cross_scope_renewal_routes() -> dict[str, Any]:
    """Build Codex's handoff case: portal emSign order 1 renewed by ACME emSign order 5.

    Returns:
        Path -> payload routes.
    """
    routes = _cross_scope_routes()
    routes[f"{_API}/reports/orders"]["content"][-1].update(productCode=EMSIGN_CODE, issuerCA=BAD_INT)
    return routes


def test_cross_scope_renewal_is_counted_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """A renewal outside the scope takes the work with it: renewed_by points there, and it is outstanding there."""
    sess, _ = _session(monkeypatch, _cross_scope_renewal_routes())
    portal = rp.build_report(sess, CA_CRITERIA, inspect=True, now=NOW, originators=["CERTInext"])
    [row] = portal.rows
    assert (row.renewed, row.renewed_by, row.replaced_by, row.outstanding) == (True, "ORDER-00005", None, False)
    counts = rp.ReplacementReport.summarize(portal.rows)
    assert (counts["needs_replacing"], counts["outstanding"], counts["replaced"]) == (1, 0, 0)

    acme = rp.build_report(sess, CA_CRITERIA, inspect=True, now=NOW, originators=["ACME"])
    acme_out = [r.facts.order_number for r in acme.rows if r.outstanding]
    everything = rp.build_report(sess, CA_CRITERIA, inspect=True, now=NOW)
    all_out = [r.facts.order_number for r in everything.rows if r.outstanding]
    assert acme_out == all_out == ["ORDER-00005"]


def test_cli_scoped_report_shows_renewal_and_coverer_count(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """The table names the out-of-scope renewal and the cache part counts the out-of-scope inspection."""
    code, out, _ = run_cli(
        ["--inspect", "--cache", "--originator", "CERTInext"], routes=_cross_scope_renewal_routes(),
    )
    assert code == 0
    assert "renewed:ORDER-00005" in out
    summary = out.strip().splitlines()[-1]
    assert summary.startswith(
        "0 EMSIGN certificates outstanding; 0 replaced; "
        "1 superseded by newer certificates that also need replacing; 1 of 1 valid"
    )
    assert "0 of 2 inspections from cache (up to 30 days old; 1 of them out-of-scope possible replacements)" in summary

    code, out, _ = run_cli(["--json", "--inspect", "--cache", "--originator", "CERTInext"],
                           routes=_cross_scope_renewal_routes())
    doc = json.loads(out)
    assert doc["certificates"][0]["renewed_by"] == "ORDER-00005"
    assert (doc["cache"]["hits"], doc["cache"]["coverers"]) == (2, 1)


@pytest.mark.parametrize("inspect", [False, True])
def test_issued_since_boundary_and_undated_out_of_scope(monkeypatch: pytest.MonkeyPatch, inspect: bool) -> None:
    """An order placed exactly at --issued-since is listed; older or undated same-CN certs never cover it."""
    routes = _routes()
    rows = routes[f"{_API}/reports/orders"]["content"]
    for n, date in ((5, None), (6, "2026-09-01T00:00:00")):
        rows.append(_order_row(
            n, domainName="host1.example.edu", productCode=SSLCOM_CODE, issuerCA=GOOD_INT, orderDate=date,
        ))
    sess, api = _session(monkeypatch, routes)
    report = rp.build_report(
        sess, CA_CRITERIA, inspect=inspect, now=NOW, issued_since=dt.datetime(2026, 10, 1),
    )
    row = next(r for r in report.rows if r.facts.order_number == "ORDER-00001")
    assert (row.possibly_replaced_by, row.possibly_superseded, row.outstanding) == (None, False, True)
    assert not any(o in c for c in api.calls for o in ("ORDER-00005", "ORDER-00006"))


# ---------------------------------------------------------------------------
# Inspection cache
# ---------------------------------------------------------------------------


def _ssl_calls(api: _FakeApi) -> list[str]:
    """Return the per-certificate requests a fake API saw.

    Args:
        api: The fake API.

    Returns:
        Paths under ``ssl-certificates``.
    """
    return [c for c in api.calls if "ssl-certificates" in c]


def _entries(directory: Path) -> list[Path]:
    """Return the cache entry files in ``directory``.

    Args:
        directory: The cache directory.

    Returns:
        Entry files, sorted.
    """
    return sorted(directory.glob("*.json")) if directory.is_dir() else []


def _snapshot(report: rp.ReplacementReport) -> list[Any]:
    """Reduce a report to comparable per-row values.

    Args:
        report: The report.

    Returns:
        ``(order, verdict, key, sans, chain, ordered_by)`` per row.
    """
    out = []
    for r in report.rows:
        i = r.facts.inspection
        out.append((
            r.facts.order_number, r.verdict, i and i.key_label, i and i.sans, i and i.chain_cas,
            r.facts.ordered_by_name,
        ))
    return out


def test_warm_cache_makes_no_certificate_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A second run reads every certificate from the cache and classifies identically."""
    routes = _routes()
    sess, api = _session(monkeypatch, copy.deepcopy(routes))
    cold = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    assert len(_ssl_calls(api)) == 4
    assert cold.cache and (cold.cache.hits, cold.cache.misses, cold.cache.writes) == (0, 2, 2)
    assert len(_entries(tmp_path)) == 2

    sess, api = _session(monkeypatch, copy.deepcopy(routes))
    warm = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path), workers=4)
    assert _ssl_calls(api) == []
    assert any("reports/orders" in c for c in api.calls)  # order status stays live
    assert warm.cache and (warm.cache.hits, warm.cache.misses, warm.cache.writes) == (2, 0, 0)
    assert all(r.facts.from_cache for r in warm.rows)
    assert _snapshot(warm) == _snapshot(cold)


def test_cache_is_ignored_without_inspection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Issuer-only runs neither read nor write the cache."""
    sess, _ = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, now=NOW, cache=rp.InspectionCache(tmp_path))
    assert report.cache is None
    assert _entries(tmp_path) == []


def test_expired_entries_are_refetched_and_pruned(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Entries older than max age are misses, and prune() deletes them."""
    t0 = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
    sess, _ = _session(monkeypatch, _routes())
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path, clock=lambda: t0))
    assert len(_entries(tmp_path)) == 2

    assert DEFAULT_MAX_AGE == dt.timedelta(days=30)  # ADR 0021
    day = dt.timedelta(days=1)
    old = rp.InspectionCache(tmp_path, clock=lambda: t0 + DEFAULT_MAX_AGE + day)
    assert old.get("ORDER-00001", "SERIAL-1") is None
    fresh = rp.InspectionCache(tmp_path, clock=lambda: t0 + DEFAULT_MAX_AGE - day)
    assert fresh.get("ORDER-00001", "SERIAL-1") is not None
    assert old.prune() == 2
    assert _entries(tmp_path) == []


def test_refresh_ignores_entries_but_rewrites_them(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """--refresh-cache downloads everything again and stores the new copies."""
    sess, _ = _session(monkeypatch, _routes())
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    sess, api = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path, refresh=True))
    assert len(_ssl_calls(api)) == 4
    assert report.cache and (report.cache.hits, report.cache.writes, report.cache.refreshed) == (0, 2, True)


def test_failures_and_unkeyable_rows_are_not_cached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """API errors, rate-limit give-ups, unparseable or chainless downloads, and serial-less rows leave no entry."""
    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00001/certificate"]["chainPem"] = None
    routes[f"{_API}/ssl-certificates/ORDER-00002"] = CertiNextAPIError(500, "boom")
    sess, _ = _session(monkeypatch, routes)
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    assert _entries(tmp_path) == []

    routes = _routes()
    routes[f"{_API}/ssl-certificates/ORDER-00001"] = [CertiNextRateLimitError(429, "slow", retry_after=1)]
    routes[f"{_API}/ssl-certificates/ORDER-00002/certificate"]["certificatePem"] = "not a certificate"
    sess, _ = _session(monkeypatch, routes)
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, sleep=lambda _s: None, cache=rp.InspectionCache(tmp_path))
    assert _entries(tmp_path) == []

    routes = _routes()
    for row in routes[f"{_API}/reports/orders"]["content"]:
        row["certificateSerialNumber"] = None
    sess, _ = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    assert _entries(tmp_path) == []
    assert report.cache and report.cache.misses == 2 and report.rows[0].facts.error is None


def test_new_serial_is_a_miss(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A reissue or rekey (same order, new serial) is downloaded, never served stale."""
    sess, _ = _session(monkeypatch, _routes())
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    routes = _routes()
    routes[f"{_API}/reports/orders"]["content"][0]["certificateSerialNumber"] = "SERIAL-1-REKEY"
    sess, api = _session(monkeypatch, routes)
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    assert _ssl_calls(api) == [
        f"{_API}/ssl-certificates/ORDER-00001", f"{_API}/ssl-certificates/ORDER-00001/certificate",
    ]
    assert report.cache and report.cache.hits == 1


@pytest.mark.parametrize("damage", ["garbage", "bad-pem", "other-cert"])
def test_damaged_entry_is_a_miss_not_an_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str) -> None:
    """Unreadable JSON, a payload that no longer parses, or a mismatched entry is downloaded afresh."""
    sess, _ = _session(monkeypatch, _routes())
    rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(tmp_path))
    cache = rp.InspectionCache(tmp_path)
    path = cache._path("ORDER-00001", "SERIAL-1")
    entry = json.loads(path.read_text(encoding="utf-8"))
    if damage == "garbage":
        path.write_text("{not json", encoding="utf-8")
    elif damage == "bad-pem":
        entry["download"]["certificatePem"] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        path.write_text(json.dumps(entry), encoding="utf-8")
    else:
        entry["serial"] = "SERIAL-9"
        path.write_text(json.dumps(entry), encoding="utf-8")

    sess, api = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=cache)
    assert len(_ssl_calls(api)) == 2
    assert report.rows[0].facts.error is None and not report.rows[0].facts.from_cache
    assert cache.get("ORDER-00001", "SERIAL-1") is not None  # rewritten


def test_unwritable_cache_is_not_fatal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A cache path that cannot be created costs only the saving, not the report."""
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    sess, _ = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(blocker / "cache"))
    assert report.summarize(report.rows)["errors"] == 0
    assert report.cache and report.cache.writes == 0


def test_unlistable_cache_dir_is_not_fatal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A cache directory that exists but cannot be listed skips pruning, not the report."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    real_iterdir = Path.iterdir

    def denied(self: Path) -> Any:
        """Refuse to list the cache directory; list anything else normally."""
        if self == cache_dir:
            raise PermissionError(13, "Permission denied", str(self))
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", denied)
    sess, _ = _session(monkeypatch, _routes())
    report = rp.build_report(sess, CRITERIA, inspect=True, now=NOW, cache=rp.InspectionCache(cache_dir))
    assert report.summarize(report.rows)["errors"] == 0
    assert report.cache and report.cache.writes > 0


def test_concurrent_puts_leave_only_whole_entries(tmp_path: Path) -> None:
    """Many threads writing (including the same key) never leave a partial file behind."""
    cache = rp.InspectionCache(tmp_path)
    payload = _download(ec.generate_private_key(ec.SECP256R1()), bad=True)

    def writer(n: int) -> None:
        """Write a mix of shared and per-thread keys."""
        for i in range(20):
            cache.put("ORDER-SHARED", "S", payload, {"name": f"t{n}", "email": None})
            cache.put(f"ORDER-{n}", f"S{i}", payload, {"name": None, "email": None})

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    files = _entries(tmp_path)
    assert len(files) == 8 * 20 + 1
    assert all(json.loads(f.read_text(encoding="utf-8"))["version"] == 1 for f in files)
    assert not list(tmp_path.glob("*.tmp"))
    # Distinct keys never contend. On Windows a same-key write can still lose
    # to a replace in flight after retries, which costs only that write.
    assert cache.writes >= 8 * 20 + 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def run_cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Callable[..., tuple[int, str, str]]:
    """Run ``certinext replacement-report`` against the fake API.

    Pins "now", points ``CERTINEXT_CONFIG`` at a temp file (with optional
    contents), points the per-user cache directory into ``tmp_path``, and
    patches the command's session.

    Returns:
        A ``run(argv, routes=None, config=None) -> (exit, stdout, stderr)`` callable.
    """
    monkeypatch.setattr(rp, "_utcnow", lambda: NOW)
    monkeypatch.setattr("certinext.cli.replacement_report.cache_dir", lambda: tmp_path / "user-cache")

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
        ["--json", "--all", "--group-by", "originator"], config=G3_CONFIG
    )
    assert code == 0
    doc = json.loads(out)
    assert doc["summary"]["needs_replacing"] == 1
    assert doc["criteria"]["issuers"] == [BAD_INT]
    assert doc["criteria"]["chain_cas"] == []
    assert doc["criteria"]["cas"] == []
    assert [c["order_number"] for c in doc["certificates"]] == ["ORDER-00001", "ORDER-00002"]
    assert doc["certificates"][0]["days_left"] == (dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc) - NOW).days
    assert {b["originator"] for b in doc["breakdown"]} == {"CERTInext", "ACME"}


def test_cli_table_uses_configured_criteria(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """The [replacement] table drives classification; the summary line follows the table."""
    code, out, _ = run_cli([], config=G3_CONFIG + 'key_types = ["EC"]\n')
    assert code == 0
    assert "ORDER-00001" in out and "ORDER-00002" not in out
    assert "1 of 2 valid certificates need replacing; 0 conflicts to review" in out
    assert "not inspected; use --inspect" in out


def test_cli_default_run_classifies_by_ca(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """With no config, the CA signal decides, and no --inspect hint is shown (the CA needs none)."""
    code, out, _ = run_cli(["--json"], routes=_ca_routes())
    assert code == 0
    doc = json.loads(out)
    assert doc["criteria"]["cas"] == ["EMSIGN"]
    assert {c["order_number"]: c["ca"] for c in doc["certificates"]} == {"ORDER-00001": "EMSIGN", "ORDER-00004": None}

    code, out, _ = run_cli([], routes=_ca_routes())
    assert "not inspected" not in out


def test_cli_flag_overrides_config(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--issuer replaces the configured issuer list for one run."""
    code, out, _ = run_cli(
        ["--issuer", GOOD_INT, "--json"], config=G3_CONFIG
    )
    assert code == 0
    assert [c["order_number"] for c in json.loads(out)["certificates"]] == ["ORDER-00002"]


def test_cli_csv_with_inspection(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--csv writes parseable rows to stdout and the summary to stderr."""
    code, out, err = run_cli(
        ["--csv", "--inspect", "--all", "--issuer", BAD_INT, "--chain-ca", BAD_ROOT], config=NO_CA_CONFIG
    )
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


def test_cli_incomplete_orders_exit_1(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """An issued order that could not be classified is listed in JSON and makes the run exit 1."""
    routes = _routes()
    routes[f"{_API}/reports/orders"]["content"].append(_order_row(4, certificateExpiryDate=None))
    code, out, _ = run_cli(["--json"], routes=routes)
    assert code == 1
    doc = json.loads(out)
    assert doc["summary"]["incomplete"] == 1
    assert doc["incomplete"][0]["order_number"] == "ORDER-00004"

    code, out, _ = run_cli([], routes=routes)
    assert code == 1
    assert "1 issued orders could not be classified" in out


def test_cli_latest_only_warns_about_unknown_sans(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """Uninspected --latest-only keeps CN-only matches, marks them 'maybe', and warns on stderr."""
    routes = _routes()
    routes[f"{_API}/reports/orders"]["content"].append(
        _order_row(4, domainName="host1.example.edu", orderDate="2026-10-15T00:00:00")
    )
    code, out, err = run_cli(["--latest-only", "--all"], routes=routes)
    assert code == 0
    assert "ORDER-00001" in out and "maybe" in out
    assert "--latest-only kept them" in err and "--latest-only kept them" not in out


@pytest.mark.parametrize(
    ("fmt", "check"),
    [
        (["--json"], lambda text: json.loads(text)["summary"]["needs_replacing"] == 1),
        (["--csv"], lambda text: [r["order_number"] for r in csv.DictReader(io.StringIO(text))] == ["ORDER-00001"]),
        ([], lambda text: "ORDER-00001" in text and "need replacing" in text and "\x1b[" not in text),
    ],
)
def test_cli_output_writes_file(
    run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path,
    fmt: list[str], check: Callable[[str], bool],
) -> None:
    """--output puts the data in a UTF-8 file, leaves stdout empty, and shows the summary on stderr."""
    target = tmp_path / "report.out"
    code, out, err = run_cli([*fmt, "--output", str(target)], config=G3_CONFIG)
    assert code == 0
    assert out == ""
    assert check(target.read_text(encoding="utf-8"))
    assert "need replacing" in err


def test_cli_output_unopenable_falls_back_to_stdout(
    run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that cannot be opened after the report is built doesn't lose it: stdout, then exit 1."""
    def locked(*_a: Any, **_kw: Any) -> Any:
        """Stand in for ``open`` on a file another program holds locked."""
        raise PermissionError("locked")

    monkeypatch.setattr("certinext.cli.replacement_report.open", locked, raising=False)
    code, out, _ = run_cli(
        ["--json", "-o", str(tmp_path / "report.json")], config=G3_CONFIG
    )
    assert code == 1
    assert json.loads(out)["summary"]["needs_replacing"] == 1


def test_cli_help_mentions_json(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """--json is a root option, so the command's own help has to point at it."""
    monkeypatch.setenv("COLUMNS", "200")
    with contextlib.suppress(SystemExit):
        cli_main(["replacement-report", "--help"])
    assert "--json" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argv", "config"),
    [
        (["--csv", "--json"], None),
        (["--output", "no-such-dir/report.json"], None),
        (["--inspect", "--workers", "0"], None),
        (["--inspect", "--workers", "17"], None),
        (["--disable-signal", "issuer", "--disable-signal", "key", "--disable-signal", "chain"], NO_CA_CONFIG),
        (["--key-type", "ECDSA"], None),
        ([], '[replacement]\nkey_types = "EC"\n'),
        (["--cache"], None),
        (["--refresh-cache"], None),
        (["--inspect", "--no-cache", "--refresh-cache"], None),
        (["--inspect", "--no-cache", "--cache-dir", "cache"], None),
        (["--inspect", "--no-cache", "--cache-max-age", "3"], None),
        (["--cache-max-age", "3"], None),
        (["--inspect", "--cache-max-age", "0"], None),
        (["--disable-signal", "ca"], None),
        (["--issued-since", "11/16/2026"], None),
    ],
)
def test_cli_usage_and_config_errors_exit_2(
    run_cli: Callable[..., tuple[int, str, str]], argv: list[str], config: str | None
) -> None:
    """Conflicting outputs, a bad --output path, no enabled signal, bad flags and a bad config all exit 2.

    Also cache flags without --inspect, --no-cache combined with a flag that implies --cache,
    a zero --cache-max-age, and a non-ISO --issued-since.
    """
    code, _, _ = run_cli(argv, config=config)
    assert code == 2


class _Tty(io.StringIO):
    """A stdin stand-in that claims to be a terminal."""

    def isatty(self) -> bool:
        """Report a terminal."""
        return True


def test_cli_json_has_start_end_and_cache_fields(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """generated_at is kept (as the end time) beside started_at and ended_at; the cache block says off."""
    code, out, _ = run_cli(["--json", "--inspect"])
    assert code == 0
    doc = json.loads(out)
    assert doc["started_at"] == NOW.isoformat()
    assert doc["generated_at"] == doc["ended_at"] >= doc["started_at"]
    assert doc["cache"] == {"enabled": False}


def test_cli_cache_off_without_a_terminal(run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path) -> None:
    """With neither --cache nor --no-cache and no terminal, the run stays live and never prompts."""
    code, _, err = run_cli(["--json", "--inspect"])
    assert code == 0
    assert "[y/N]" not in err
    assert not (tmp_path / "user-cache").exists()


@pytest.mark.parametrize(("answer", "enabled"), [("y\n", True), ("yes\n", True), ("\n", False), ("", False)])
def test_cli_prompts_for_the_cache_on_a_terminal(
    run_cli: Callable[..., tuple[int, str, str]], monkeypatch: pytest.MonkeyPatch,
    answer: str, enabled: bool,
) -> None:
    """On a terminal the user is asked; only an explicit yes turns it on (Enter and EOF mean no)."""
    monkeypatch.setattr("sys.stdin", _Tty(answer))
    code, out, err = run_cli(["--json", "--inspect"])
    assert code == 0
    assert "[y/N]" in err and "[y/N]" not in out
    assert json.loads(out)["cache"]["enabled"] is enabled


def test_cli_cache_flags_skip_the_prompt(
    run_cli: Callable[..., tuple[int, str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """--cache and --no-cache answer the question, so a terminal is never asked."""
    monkeypatch.setattr("sys.stdin", _Tty(""))
    for flag, enabled in (("--cache", True), ("--no-cache", False)):
        code, out, err = run_cli(["--json", "--inspect", flag])
        assert code == 0 and "[y/N]" not in err
        assert json.loads(out)["cache"]["enabled"] is enabled


def test_cli_cache_dir_and_summary(run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path) -> None:
    """--cache-dir implies --cache, keeps production entries apart, and the summary shows cache use."""
    target = tmp_path / "mine"
    code, _, _ = run_cli(["--inspect", "--all", "--cache-dir", str(target)])
    assert code == 0
    assert len(_entries(target / "production")) == 2
    code, out, _ = run_cli(["--inspect", "--all", "--cache-dir", str(target)])
    assert code == 0
    assert "2 of 2 inspections from cache (up to 30 days old)" in out

    code, out, _ = run_cli(["--json", "--inspect", "--refresh-cache", "--cache-dir", str(target)])
    cache = json.loads(out)["cache"]
    assert (cache["hits"], cache["writes"], cache["refreshed"]) == (0, 2, True)
    assert cache["dir"] == str(target / "production")


def test_cli_default_cache_dir_splits_sandbox(
    run_cli: Callable[..., tuple[int, str, str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Sandbox entries go to their own directory, so they can never answer for production."""
    original = _session

    def sandbox_session(mp: pytest.MonkeyPatch, routes: dict[str, Any]) -> tuple[CertiNextSession, _FakeApi]:
        """Like :func:`_session`, flagged as sandbox."""
        sess, api = original(mp, routes)
        sess.sandbox = True
        return sess, api

    monkeypatch.setitem(globals(), "_session", sandbox_session)
    code, _, _ = run_cli(["--inspect", "--cache"])
    assert code == 0
    base = tmp_path / "user-cache" / "replacement-inspect"
    assert len(_entries(base / "sandbox")) == 2 and not (base / "production").exists()


def test_cli_cache_dir_that_is_a_file_exits_2(run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path) -> None:
    """A --cache-dir naming a file is rejected before the report is built."""
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    code, _, _ = run_cli(["--inspect", "--cache-dir", str(blocker)])
    assert code == 2


# ---------------------------------------------------------------------------
# CLI: CA migration (ADR 0021)
# ---------------------------------------------------------------------------


def _migration_routes(*, replaced: bool = True) -> dict[str, Any]:
    """Build routes for the emSign -> SSL.com CLI tests.

    Order 1 is emSign (``host1``), order 2 is SSL.com (``host2``), and, when
    ``replaced``, order 5 is a newer SSL.com certificate for ``host1``.

    Args:
        replaced: Whether to add the SSL.com replacement for order 1.

    Returns:
        Path -> payload routes.
    """
    routes = _routes()
    rows = routes[f"{_API}/reports/orders"]["content"]
    rows[1]["productCode"] = SSLCOM_CODE
    if replaced:
        rows.append(_order_row(
            5, domainName="host1.example.edu", productCode=SSLCOM_CODE, issuerCA=GOOD_INT,
            orderDate="2026-10-15T00:00:00", certificateExpiryDate="2027-04-01T00:00:00",
        ))
        routes[f"{_API}/ssl-certificates/ORDER-00005"] = {"orderId": "ORDER-00005", "status": "issued"}
        routes[f"{_API}/ssl-certificates/ORDER-00005/certificate"] = _download(
            rsa.generate_private_key(65537, 2048), bad=False, sans=["host1.example.edu"]
        )
    return routes


def test_cli_table_shows_ca_and_possible_replacement(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """Uninspected, a same-CN SSL.com cert is 'maybe:<order>' and the row still counts as outstanding."""
    code, out, _ = run_cli([], routes=_migration_routes())
    assert code == 0
    assert "EMSIGN" in out and "maybe:ORDER-00005" in out
    assert out.strip().splitlines()[-1] == (
        "1 EMSIGN certificates outstanding (1 possibly replaced; confirm with --inspect); "
        "0 replaced; 1 of 3 valid certificates need replacing"
    )


def test_cli_inspected_json_and_csv_carry_replacement(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """With SANs known the replacement is confirmed, in JSON, CSV and the table."""
    code, out, _ = run_cli(["--json", "--inspect", "--all"], routes=_migration_routes())
    assert code == 0
    doc = json.loads(out)
    by_order = {c["order_number"]: c for c in doc["certificates"]}
    old = by_order["ORDER-00001"]
    assert (old["ca"], old["replaced_by"], old["replaced_by_ca"], old["outstanding"]) == (
        "EMSIGN", "ORDER-00005", "SSLCOM", False,
    )
    assert (doc["summary"]["outstanding"], doc["summary"]["replaced"]) == (0, 1)

    code, out, _ = run_cli(["--csv", "--inspect"], routes=_migration_routes())
    row = next(csv.DictReader(io.StringIO(out)))
    assert (row["ca"], row["replaced_by"], row["replaced_by_ca"], row["possibly_replaced_by"]) == (
        "EMSIGN", "ORDER-00005", "SSLCOM", "",
    )

    code, out, _ = run_cli(["--inspect"], routes=_migration_routes())
    assert "ORDER-00005" in out and "maybe:" not in out
    assert "0 EMSIGN certificates outstanding; 1 replaced; 1 of 3" in out


def test_cli_outstanding_lists_only_work_left(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--outstanding drops confirmed replacements (and ignores --all); CN-only matches stay listed."""
    code, out, _ = run_cli(["--outstanding", "--all", "--inspect"], routes=_migration_routes())
    assert code == 0
    assert "(no certificates match)" in out
    # The summary still counts the whole population: the replacement shows as progress.
    assert "0 EMSIGN certificates outstanding; 1 replaced; 1 of 3 valid" in out

    code, out, _ = run_cli(["--outstanding", "--all"], routes=_migration_routes())
    assert code == 0
    assert "ORDER-00001" in out and "maybe:ORDER-00005" in out

    code, out, _ = run_cli(["--outstanding", "--json"], routes=_migration_routes(replaced=False))
    doc = json.loads(out)
    assert [c["order_number"] for c in doc["certificates"]] == ["ORDER-00001"]
    s = doc["summary"]
    assert (s["outstanding"], s["replaced"], s["needs_replacing"], s["valid"]) == (1, 0, 1, 2)
    assert doc["summary_scope"] == {"latest_only": False, "expiring_within": None}


def test_cli_outstanding_summary_and_breakdown_keep_replacements(
    run_cli: Callable[..., tuple[int, str, str]],
) -> None:
    """--group-by with --outstanding still counts confirmed replacements (rc7 bug: always 0)."""
    code, out, _ = run_cli(
        ["--outstanding", "--inspect", "--json", "--group-by", "ca"], routes=_migration_routes()
    )
    assert code == 0
    doc = json.loads(out)
    assert doc["certificates"] == []
    assert (doc["summary"]["outstanding"], doc["summary"]["replaced"]) == (0, 1)
    by_ca = {b["ca"]: b for b in doc["breakdown"]}
    assert by_ca["EMSIGN"]["replaced"] == 1


def test_cli_outstanding_warning_names_the_flag_used(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """The 'maybe' warning names --outstanding, not --latest-only, when only --outstanding was given."""
    code, _, err = run_cli(["--outstanding"], routes=_migration_routes())
    assert code == 0
    assert "so --outstanding kept them" in err and "--latest-only" not in err
    _, _, err = run_cli(["--outstanding", "--latest-only"], routes=_migration_routes())
    assert "so --latest-only and --outstanding kept them" in err


def test_cli_scoped_summary_says_so(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--expiring-within / --latest-only narrow the counts, and the summary line says which."""
    code, out, _ = run_cli(["--expiring-within", "3650", "--latest-only"], routes=_migration_routes())
    assert code == 0
    assert out.strip().splitlines()[-1].endswith(
        "counts cover only certificates not superseded and expiring within 3650 days"
    )
    code, out, _ = run_cli([], routes=_migration_routes())
    assert "counts cover only" not in out


def test_cli_superseded_emsign_is_counted_separately(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """An emSign cert renewed as emSign is neither outstanding nor replaced; the summary says so."""
    routes = _migration_routes(replaced=False)
    routes[f"{_API}/reports/orders"]["content"].append(_order_row(
        6, domainName="host1.example.edu", orderDate="2026-10-15T00:00:00",
        certificateExpiryDate="2027-04-01T00:00:00",
    ))
    routes[f"{_API}/ssl-certificates/ORDER-00006"] = {"orderId": "ORDER-00006", "status": "issued"}
    routes[f"{_API}/ssl-certificates/ORDER-00006/certificate"] = _download(
        rsa.generate_private_key(65537, 2048), bad=False, sans=["host1.example.edu"]
    )
    code, out, _ = run_cli(["--inspect"], routes=routes)
    assert code == 0
    assert (
        "1 EMSIGN certificates outstanding; 0 replaced; "
        "1 superseded by newer certificates that also need replacing; 2 of 3"
    ) in out


def test_cli_ca_flag_replaces_config(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--ca (any case) replaces the CA list: here SSL.com certs are the ones flagged."""
    code, out, _ = run_cli(["--ca", "sslcom", "--json"], routes=_migration_routes())
    assert code == 0
    doc = json.loads(out)
    assert doc["criteria"]["cas"] == ["SSLCOM"]
    assert sorted(c["order_number"] for c in doc["certificates"]) == ["ORDER-00002", "ORDER-00005"]


def test_cli_issued_since_and_group_by_ca(run_cli: Callable[..., tuple[int, str, str]]) -> None:
    """--issued-since keeps orders placed on or after the date; --group-by ca counts per CA."""
    code, out, _ = run_cli(
        ["--issued-since", "2026-10-15", "--all", "--json"], routes=_migration_routes()
    )
    assert code == 0
    assert [c["order_number"] for c in json.loads(out)["certificates"]] == ["ORDER-00005"]

    code, out, _ = run_cli(["--all", "--group-by", "ca", "--json"], routes=_migration_routes())
    by_ca = {b["ca"]: b for b in json.loads(out)["breakdown"]}
    assert (by_ca["EMSIGN"]["valid"], by_ca["SSLCOM"]["ok"]) == (1, 2)


def _backdate(directory: Path, days: int) -> None:
    """Make every cache entry under ``directory`` look ``days`` days old.

    Args:
        directory: A cache environment directory.
        days: How old to make the entries.
    """
    when = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    for path in _entries(directory):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["fetched_at"] = when
        path.write_text(json.dumps(data), encoding="utf-8")


def test_cli_cache_default_is_30_days_and_max_age_overrides(
    run_cli: Callable[..., tuple[int, str, str]], tmp_path: Path
) -> None:
    """A 20-day-old entry is a hit by default; --cache-max-age 3 makes it a miss and prunes it."""
    target = tmp_path / "c"
    run_cli(["--inspect", "--cache-dir", str(target)])
    _backdate(target / "production", 20)

    code, out, _ = run_cli(["--json", "--inspect", "--cache-dir", str(target)])
    cache = json.loads(out)["cache"]
    assert (cache["hits"], cache["max_age_days"]) == (2, 30)

    _backdate(target / "production", 20)
    code, out, _ = run_cli(["--inspect", "--all", "--cache-dir", str(target), "--cache-max-age", "3"])
    assert code == 0
    assert "0 of 2 inspections from cache (up to 3 days old)" in out
    code, out, _ = run_cli(["--json", "--inspect", "--cache-dir", str(target), "--cache-max-age", "3"])
    assert json.loads(out)["cache"]["max_age_days"] == 3


def test_cli_cache_max_age_implies_cache(
    run_cli: Callable[..., tuple[int, str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """--cache-max-age alone turns the cache on without asking."""
    monkeypatch.setattr("sys.stdin", _Tty(""))
    code, out, err = run_cli(["--json", "--inspect", "--cache-max-age", "10"])
    assert code == 0 and "[y/N]" not in err
    assert json.loads(out)["cache"]["max_age_days"] == 10


@pytest.mark.parametrize(
    ("argv", "config", "warned"),
    [
        (["--chain-ca", BAD_ROOT], NO_CA_CONFIG, True),
        (["--chain-ca", BAD_ROOT, "--cache-max-age", "7"], NO_CA_CONFIG, False),
        (["--chain-ca", BAD_ROOT, "--disable-signal", "chain", "--issuer", BAD_INT], NO_CA_CONFIG, False),
        ([], None, False),
    ],
)
def test_cli_warns_when_chain_signal_meets_a_long_cache(
    run_cli: Callable[..., tuple[int, str, str]], argv: list[str], config: str | None, warned: bool
) -> None:
    """Only the chain signal can go stale in the cache, so only it (past 7 days) warns."""
    code, out, err = run_cli(["--inspect", "--cache", *argv], config=config)
    assert code == 0
    assert ("chain signal is on" in err) is warned
    assert "chain signal is on" not in out
