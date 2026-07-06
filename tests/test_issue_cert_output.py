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

"""Tests for certinext-issue-cert output flags and stderr prompting.

Covers the ``--cert-out`` / ``--chain-out`` / ``--fullchain-out`` /
``--der-out`` / ``--all-formats-out`` flags
(:func:`certinext.issue_certificate_cli._write_outputs`) and the
:func:`certinext._cli.prompt_stderr` helper that keeps interactive prompts
off stdout so piped certificate output stays clean.

Test certificate data is generated at module load time using the
``cryptography`` library so that binary-format round-trips (DER parse)
serve as real structural assertions, not just byte-equality checks against
hand-crafted blobs.
"""

import argparse
import datetime
import io
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certinext._cli import prompt_stderr
from certinext.issue_certificate_cli import _stem_from_domain, _write_outputs, build_parser
from certinext.ssl_certificates import CertificateDownload

# ---------------------------------------------------------------------------
# Module-level test certificate chain
# ---------------------------------------------------------------------------

_TEST_DOMAIN = "test.example.com"
_NOT_BEFORE = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)


def _make_test_chain() -> tuple[str, str, str, bytes]:
    """Generate a 3-level test cert chain (root CA → intermediate → leaf).

    Returns:
        Tuple of ``(leaf_pem, int_pem, root_pem, leaf_der)``
        where all PEM strings are stripped (no trailing newline) and
        ``leaf_der`` is the DER-encoded leaf certificate.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    int_key = ec.generate_private_key(ec.SECP256R1())
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _TEST_DOMAIN)])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(int_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .sign(int_key, hashes.SHA256())
    )

    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    int_pem = int_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    root_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    return leaf_pem, int_pem, root_pem, leaf_der


_LEAF_PEM, _INT_PEM, _ROOT_PEM, _LEAF_DER = _make_test_chain()

# Public constants used directly in test assertions.  Stripped PEM strings
# (no trailing newline) so that LEAF + "\n" equals the normalised single-cert
# file that _write_outputs produces via (dl.certificate_pem or "").strip() + "\n".
LEAF = _LEAF_PEM
INT1 = _INT_PEM
INT2 = _ROOT_PEM
# Correct leaf-first signing order: leaf, intermediate, root.
BUNDLE = LEAF + "\n" + INT1 + "\n" + INT2 + "\n"
# The order CertiNext actually returns (GitLab #4): root jumps ahead of the
# intermediate. Sorting must reorder this back to BUNDLE.
SCRAMBLED = LEAF + "\n" + INT2 + "\n" + INT1 + "\n"

FAKE_DER: bytes = _LEAF_DER


# ---------------------------------------------------------------------------
# FakeOrder
# ---------------------------------------------------------------------------


class FakeOrder:
    """Stand-in for SslOrder exposing download_certificate() and download_certificate_der().

    Returns canned values supplied at construction time, so tests control
    exactly which parts are present and can inject real cryptographic bytes.
    """

    def __init__(
        self,
        data: dict[str, Any],
        der: bytes = FAKE_DER,
        domain: str | None = _TEST_DOMAIN,
    ) -> None:
        """
        Args:
            data: Raw dict passed through to :class:`CertificateDownload`.
            der: Bytes returned by :meth:`download_certificate_der`.
            domain: Value exposed as the ``domain`` attribute (used by
                ``--all-formats-out`` to derive the output filename stem).
        """
        self._data = data
        self._der = der
        self.domain = domain

    def download_certificate(self) -> CertificateDownload:
        """Return the canned :class:`CertificateDownload`."""
        return CertificateDownload.model_validate(self._data)

    def download_certificate_der(self) -> bytes:
        """Return the canned DER bytes."""
        return self._der


# ---------------------------------------------------------------------------
# _args helper
# ---------------------------------------------------------------------------


def _args(**overrides: Any) -> argparse.Namespace:
    """Build a Namespace with all output destinations defaulting to None.

    Args:
        overrides: Output-flag attributes to set (e.g. ``cert_out="x.pem"``).

    Returns:
        Namespace with ``output``, ``cert_out``, ``chain_out``,
        ``fullchain_out``, ``der_out``, and ``all_formats_out`` attributes.
    """
    ns = argparse.Namespace(
        output=None, cert_out=None, chain_out=None, fullchain_out=None,
        der_out=None, all_formats_out=None, raw_chain=False,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


# ---------------------------------------------------------------------------
# prompt_stderr
# ---------------------------------------------------------------------------


def test_prompt_stderr_keeps_stdout_clean(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prompt text goes to stderr and the typed line is returned."""
    monkeypatch.setattr("sys.stdin", io.StringIO("yes\n"))
    answer = prompt_stderr("Continue? [y/N]: ")
    captured = capsys.readouterr()
    assert answer == "yes"
    assert captured.out == ""
    assert "Continue? [y/N]: " in captured.err


def test_prompt_stderr_raises_eoferror_on_closed_stdin(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed stdin propagates EOFError so callers can default the answer."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(EOFError):
        prompt_stderr("Continue? [y/N]: ")


# ---------------------------------------------------------------------------
# Parser flags
# ---------------------------------------------------------------------------


def test_parser_accepts_output_part_flags() -> None:
    """--cert-out/--chain-out/--fullchain-out parse into the expected dests."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args(
        ["--cert-out", "c.pem", "--chain-out", "ch.pem", "--fullchain-out", "fc.pem"]
    )
    assert args.cert_out == "c.pem"
    assert args.chain_out == "ch.pem"
    assert args.fullchain_out == "fc.pem"


def test_parser_output_part_flags_default_to_none() -> None:
    """The PEM part flags default to None so stdout behavior is unchanged."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args([])
    assert args.cert_out is None
    assert args.chain_out is None
    assert args.fullchain_out is None


def test_parser_accepts_der_flag() -> None:
    """--der-out parses into the expected dest."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args(["--der-out", "cert.der"])
    assert args.der_out == "cert.der"


def test_parser_der_flag_defaults_to_none() -> None:
    """--der-out defaults to None so existing stdout behavior is unchanged."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args([])
    assert args.der_out is None


def test_parser_accepts_all_formats_out_flag() -> None:
    """--all-formats-out parses into the expected dest."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args(["--all-formats-out", "/tmp/certs"])
    assert args.all_formats_out == "/tmp/certs"


def test_parser_all_formats_out_defaults_to_none() -> None:
    """--all-formats-out defaults to None so stdout behavior is unchanged."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args([])
    assert args.all_formats_out is None


def test_parser_raw_chain_defaults_false_and_sets_true() -> None:
    """--raw-chain is a store_true flag defaulting to False."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    assert build_parser(cfg).parse_args([]).raw_chain is False
    assert build_parser(cfg).parse_args(["--raw-chain"]).raw_chain is True


def test_help_text_is_ascii() -> None:
    """--help text must be pure ASCII so it never crashes on a non-UTF-8 console.

    A U+2192 arrow in a help string previously raised UnicodeEncodeError when
    --help was printed to a cp1252 (Windows) pipe, because cp1252 cannot encode
    that character. Keeping the help text ASCII avoids the whole class of
    console-encoding failures regardless of locale.
    """
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    help_text = build_parser(cfg).format_help()
    non_ascii = sorted({ch for ch in help_text if not ch.isascii()})
    assert help_text.isascii(), f"non-ASCII characters in --help text: {non_ascii!r}"


def test_help_flag_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """--help prints usage (including --raw-chain) and exits 0."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    with pytest.raises(SystemExit) as excinfo:
        build_parser(cfg).parse_args(["--help"])
    assert excinfo.value.code == 0
    assert "--raw-chain" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _stem_from_domain
# ---------------------------------------------------------------------------


def test_stem_from_domain_passthrough() -> None:
    """A plain domain is returned unchanged."""
    assert _stem_from_domain("example.com") == "example.com"


def test_stem_from_domain_sanitizes_wildcard() -> None:
    """* is replaced with 'wildcard' so the stem is shell-glob safe."""
    assert _stem_from_domain("*.example.com") == "wildcard.example.com"


def test_stem_from_domain_handles_none() -> None:
    """None falls back to 'certificate'."""
    assert _stem_from_domain(None) == "certificate"


# ---------------------------------------------------------------------------
# _write_outputs — PEM paths
# ---------------------------------------------------------------------------


def test_write_outputs_stdout_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    """With no destination flags the raw bundle is printed to stdout."""
    _write_outputs(FakeOrder({}), _args(), BUNDLE)  # type: ignore[arg-type]
    assert capsys.readouterr().out == BUNDLE


def test_write_outputs_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--output writes the raw bundle to the file and nothing to stdout."""
    out = tmp_path / "bundle.pem"
    _write_outputs(FakeOrder({}), _args(output=str(out)), BUNDLE)  # type: ignore[arg-type]
    assert out.read_text() == BUNDLE
    # Unconfigured structlog prints log lines to stdout in tests; the contract
    # is that no certificate content reaches stdout.
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out


def test_write_outputs_part_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Each part flag writes its slice of the JSON download, leaf-first, with one trailing newline."""
    order = FakeOrder({"certificatePem": LEAF + "\n", "chainPem": [INT1, INT2 + "\n"]})
    cert = tmp_path / "cert.pem"
    chain = tmp_path / "chain.pem"
    fullchain = tmp_path / "fullchain.pem"
    args = _args(cert_out=str(cert), chain_out=str(chain), fullchain_out=str(fullchain))
    _write_outputs(order, args, BUNDLE)  # type: ignore[arg-type]
    assert cert.read_text() == LEAF + "\n"
    assert chain.read_text() == INT1 + "\n" + INT2 + "\n"
    assert fullchain.read_text() == LEAF + "\n" + INT1 + "\n" + INT2 + "\n"
    # Part flags are an explicit destination, so no PEM goes to stdout.
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out


def test_write_outputs_part_flags_combine_with_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--output and part flags can be combined; each gets its own content."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": [INT1]})
    out = tmp_path / "bundle.pem"
    cert = tmp_path / "cert.pem"
    _write_outputs(order, _args(output=str(out), cert_out=str(cert)), BUNDLE)  # type: ignore[arg-type]
    assert out.read_text() == BUNDLE
    assert cert.read_text() == LEAF + "\n"
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out


def test_write_outputs_missing_leaf_is_fatal(tmp_path: Path) -> None:
    """--cert-out with no end-entity certificate in the download exits 1."""
    order = FakeOrder({"chainPem": [INT1]})
    with pytest.raises(SystemExit) as excinfo:
        _write_outputs(order, _args(cert_out=str(tmp_path / "cert.pem")), BUNDLE)  # type: ignore[arg-type]
    assert excinfo.value.code == 1


def test_write_outputs_empty_fullchain_is_fatal(tmp_path: Path) -> None:
    """--fullchain-out with an empty download exits 1."""
    order = FakeOrder({})
    with pytest.raises(SystemExit) as excinfo:
        _write_outputs(order, _args(fullchain_out=str(tmp_path / "fc.pem")), BUNDLE)  # type: ignore[arg-type]
    assert excinfo.value.code == 1


def test_write_outputs_empty_chain_is_warning_not_error(tmp_path: Path) -> None:
    """--chain-out with no intermediates writes an empty file (root-signed leaf)."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": []})
    chain = tmp_path / "chain.pem"
    _write_outputs(order, _args(chain_out=str(chain)), BUNDLE)  # type: ignore[arg-type]
    assert chain.read_text() == ""


def test_write_outputs_unwritable_path_is_fatal(tmp_path: Path) -> None:
    """An unwritable destination path exits 1 instead of raising OSError."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": []})
    missing_dir = tmp_path / "no-such-dir" / "cert.pem"
    with pytest.raises(SystemExit) as excinfo:
        _write_outputs(order, _args(cert_out=str(missing_dir)), BUNDLE)  # type: ignore[arg-type]
    assert excinfo.value.code == 1


# ---------------------------------------------------------------------------
# _write_outputs — chain sorting (default) vs --raw-chain
# ---------------------------------------------------------------------------


def test_write_outputs_stdout_sorts_scrambled_bundle(capsys: pytest.CaptureFixture[str]) -> None:
    """By default a scrambled bundle is re-sorted to leaf-first signing order on stdout."""
    _write_outputs(FakeOrder({}), _args(), SCRAMBLED)  # type: ignore[arg-type]
    assert capsys.readouterr().out == BUNDLE


def test_write_outputs_output_file_sorts_scrambled_bundle(tmp_path: Path) -> None:
    """--output writes the re-sorted bundle, not the raw API order."""
    out = tmp_path / "bundle.pem"
    _write_outputs(FakeOrder({}), _args(output=str(out)), SCRAMBLED)  # type: ignore[arg-type]
    assert out.read_text() == BUNDLE


def test_write_outputs_raw_chain_preserves_stdout_order(capsys: pytest.CaptureFixture[str]) -> None:
    """--raw-chain emits the bundle exactly as received, unsorted."""
    _write_outputs(FakeOrder({}), _args(raw_chain=True), SCRAMBLED)  # type: ignore[arg-type]
    assert capsys.readouterr().out == SCRAMBLED


def test_write_outputs_fullchain_sorts_by_default(tmp_path: Path) -> None:
    """--fullchain-out re-orders an out-of-order JSON chain into signing order."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": [INT2, INT1]})
    fc = tmp_path / "fullchain.pem"
    _write_outputs(order, _args(fullchain_out=str(fc)), SCRAMBLED)  # type: ignore[arg-type]
    assert fc.read_text() == BUNDLE


def test_write_outputs_fullchain_raw_chain_preserves_api_order(tmp_path: Path) -> None:
    """--fullchain-out --raw-chain concatenates the JSON fields in API order."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": [INT2, INT1]})
    fc = tmp_path / "fullchain.pem"
    _write_outputs(order, _args(fullchain_out=str(fc), raw_chain=True), SCRAMBLED)  # type: ignore[arg-type]
    assert fc.read_text() == LEAF + "\n" + INT2 + "\n" + INT1 + "\n"


def test_write_outputs_chain_out_sorts_intermediates(tmp_path: Path) -> None:
    """--chain-out emits intermediates in signing order, dropping the leaf and root position."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": [INT2, INT1]})
    chain = tmp_path / "chain.pem"
    _write_outputs(order, _args(chain_out=str(chain)), SCRAMBLED)  # type: ignore[arg-type]
    assert chain.read_text() == INT1 + "\n" + INT2 + "\n"


def test_write_outputs_all_formats_out_sorts_bundle(tmp_path: Path) -> None:
    """--all-formats-out writes the re-sorted PEM bundle."""
    _write_outputs(FakeOrder({}), _args(all_formats_out=str(tmp_path)), SCRAMBLED)  # type: ignore[arg-type]
    assert (tmp_path / f"{_TEST_DOMAIN}.pem").read_text() == BUNDLE


def test_write_outputs_chain_sort_missing_cryptography_is_fatal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When sorting is required but cryptography is unavailable, exit 1 with guidance."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated missing cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SystemExit) as excinfo:
        _write_outputs(FakeOrder({}), _args(), SCRAMBLED)  # type: ignore[arg-type]
    assert excinfo.value.code == 1


def test_write_outputs_raw_chain_works_without_cryptography(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """--raw-chain never needs cryptography: it emits the raw bundle even if absent."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("simulated missing cryptography")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    _write_outputs(FakeOrder({}), _args(raw_chain=True), SCRAMBLED)  # type: ignore[arg-type]
    assert capsys.readouterr().out == SCRAMBLED


# ---------------------------------------------------------------------------
# _write_outputs — binary path: --der-out
# ---------------------------------------------------------------------------


def test_write_outputs_der_out_writes_parseable_der(tmp_path: Path) -> None:
    """--der-out writes valid DER: the file round-trips through load_der_x509_certificate."""
    der_file = tmp_path / "cert.der"
    _write_outputs(FakeOrder({}), _args(der_out=str(der_file)), BUNDLE)  # type: ignore[arg-type]
    written = der_file.read_bytes()
    assert written == FAKE_DER
    cert = x509.load_der_x509_certificate(written)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == _TEST_DOMAIN



def test_write_outputs_binary_suppresses_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A binary output flag suppresses the stdout PEM bundle."""
    der = tmp_path / "cert.der"
    _write_outputs(FakeOrder({}), _args(der_out=str(der)), BUNDLE)  # type: ignore[arg-type]
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out


def test_write_outputs_binary_and_pem_combine(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--der-out and --cert-out can be combined; each gets its own content."""
    order = FakeOrder({"certificatePem": LEAF, "chainPem": []})
    der = tmp_path / "cert.der"
    cert = tmp_path / "cert.pem"
    _write_outputs(order, _args(der_out=str(der), cert_out=str(cert)), BUNDLE)  # type: ignore[arg-type]
    assert der.read_bytes() == FAKE_DER
    assert cert.read_text() == LEAF + "\n"
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out


def test_write_outputs_binary_unwritable_path_warns_and_continues(tmp_path: Path) -> None:
    """An unwritable --der-out path logs a warning but does not raise or exit."""
    missing_dir = tmp_path / "no-such-dir" / "cert.der"
    _write_outputs(FakeOrder({}), _args(der_out=str(missing_dir)), BUNDLE)  # type: ignore[arg-type]
    assert not missing_dir.exists()


# ---------------------------------------------------------------------------
# _write_outputs — --all-formats-out
# ---------------------------------------------------------------------------


def test_write_outputs_all_formats_out_writes_pem_and_der(tmp_path: Path) -> None:
    """--all-formats-out writes .pem and .der files named by domain."""
    _write_outputs(FakeOrder({}), _args(all_formats_out=str(tmp_path)), BUNDLE)  # type: ignore[arg-type]
    assert (tmp_path / f"{_TEST_DOMAIN}.pem").exists()
    assert (tmp_path / f"{_TEST_DOMAIN}.der").exists()


def test_write_outputs_all_formats_out_pem_content(tmp_path: Path) -> None:
    """The .pem file written by --all-formats-out is the raw PEM bundle."""
    _write_outputs(FakeOrder({}), _args(all_formats_out=str(tmp_path)), BUNDLE)  # type: ignore[arg-type]
    assert (tmp_path / f"{_TEST_DOMAIN}.pem").read_text() == BUNDLE


def test_write_outputs_all_formats_out_der_is_parseable(tmp_path: Path) -> None:
    """The .der file written by --all-formats-out round-trips through load_der_x509_certificate."""
    _write_outputs(FakeOrder({}), _args(all_formats_out=str(tmp_path)), BUNDLE)  # type: ignore[arg-type]
    der_bytes = (tmp_path / f"{_TEST_DOMAIN}.der").read_bytes()
    cert = x509.load_der_x509_certificate(der_bytes)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == _TEST_DOMAIN



def test_write_outputs_all_formats_out_wildcard_domain(tmp_path: Path) -> None:
    """--all-formats-out sanitises a wildcard domain in the filename stem."""
    order = FakeOrder({}, domain="*.example.com")
    _write_outputs(order, _args(all_formats_out=str(tmp_path)), BUNDLE)  # type: ignore[arg-type]
    assert (tmp_path / "wildcard.example.com.pem").exists()
    assert (tmp_path / "wildcard.example.com.der").exists()


def test_write_outputs_all_formats_out_suppresses_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--all-formats-out suppresses the default stdout PEM bundle."""
    _write_outputs(FakeOrder({}), _args(all_formats_out=str(tmp_path)), BUNDLE)  # type: ignore[arg-type]
    assert "-----BEGIN CERTIFICATE-----" not in capsys.readouterr().out
