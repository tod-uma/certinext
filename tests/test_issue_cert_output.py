"""Tests for certinext-issue-cert output flags and stderr prompting.

Covers the ``--cert-out`` / ``--chain-out`` / ``--fullchain-out`` /
``--der-out`` / ``--pkcs7-out`` flags
(:func:`certinext.issue_certificate_cli._write_outputs`) and the
:func:`certinext._cli.prompt_stderr` helper that keeps interactive prompts
off stdout so piped certificate output stays clean.
"""

import argparse
import io
from pathlib import Path
from typing import Any

import pytest

from certinext._cli import prompt_stderr
from certinext.issue_certificate_cli import _write_outputs, build_parser
from certinext.ssl_certificates import CertificateDownload

LEAF = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----"
INT1 = "-----BEGIN CERTIFICATE-----\nint1\n-----END CERTIFICATE-----"
INT2 = "-----BEGIN CERTIFICATE-----\nint2\n-----END CERTIFICATE-----"
BUNDLE = LEAF + "\n" + INT1 + "\n" + INT2 + "\n"

# Minimal valid-looking binary blobs for DER (X.509 SEQUENCE tag) and PKCS#7.
FAKE_DER = b"\x30\x82\x01\x00" + b"\x00" * 256
FAKE_PKCS7 = b"\x30\x82\x02\x00" + b"\x00" * 512


class FakeOrder:
    """Stand-in for SslOrder exposing download_certificate(), download_certificate_der(),
    and download_certificate_pkcs7().

    Returns canned values supplied at construction time, so tests control
    exactly which parts are present.
    """

    def __init__(
        self,
        data: dict[str, Any],
        der: bytes = FAKE_DER,
        pkcs7: bytes = FAKE_PKCS7,
    ) -> None:
        """
        Args:
            data: Raw dict passed through to :class:`CertificateDownload`.
            der: Bytes returned by :meth:`download_certificate_der`.
            pkcs7: Bytes returned by :meth:`download_certificate_pkcs7`.
        """
        self._data = data
        self._der = der
        self._pkcs7 = pkcs7

    def download_certificate(self) -> CertificateDownload:
        """Return the canned :class:`CertificateDownload`."""
        return CertificateDownload(self._data)

    def download_certificate_der(self) -> bytes:
        """Return the canned DER bytes."""
        return self._der

    def download_certificate_pkcs7(self) -> bytes:
        """Return the canned PKCS#7 bytes."""
        return self._pkcs7


def _args(**overrides: Any) -> argparse.Namespace:
    """Build a Namespace with all output destinations defaulting to None.

    Args:
        overrides: Output-flag attributes to set (e.g. ``cert_out="x.pem"``).

    Returns:
        Namespace with ``output``, ``cert_out``, ``chain_out``,
        ``fullchain_out``, ``der_out``, and ``pkcs7_out`` attributes.
    """
    ns = argparse.Namespace(
        output=None, cert_out=None, chain_out=None, fullchain_out=None,
        der_out=None, pkcs7_out=None,
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
    """The new flags default to None so stdout behavior is unchanged."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args([])
    assert args.cert_out is None
    assert args.chain_out is None
    assert args.fullchain_out is None


def test_parser_accepts_der_pkcs7_flags() -> None:
    """--der-out and --pkcs7-out parse into the expected dests."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args(["--der-out", "cert.der", "--pkcs7-out", "cert.p7b"])
    assert args.der_out == "cert.der"
    assert args.pkcs7_out == "cert.p7b"


def test_parser_der_pkcs7_flags_default_to_none() -> None:
    """Binary output flags default to None so existing stdout behavior is unchanged."""
    cfg = {"requestor_name": "Jane", "requestor_phone": "+12075551234"}
    args = build_parser(cfg).parse_args([])
    assert args.der_out is None
    assert args.pkcs7_out is None


# ---------------------------------------------------------------------------
# _write_outputs
# ---------------------------------------------------------------------------


def test_write_outputs_stdout_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    """With no destination flags the raw bundle is printed to stdout."""
    order = FakeOrder({})
    _write_outputs(order, _args(), BUNDLE)  # type: ignore[arg-type]
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
# Binary output: --der-out / --pkcs7-out
# ---------------------------------------------------------------------------


def test_write_outputs_der_out_writes_bytes(tmp_path: Path) -> None:
    """--der-out writes the DER bytes returned by download_certificate_der()."""
    der = tmp_path / "cert.der"
    _write_outputs(FakeOrder({}), _args(der_out=str(der)), BUNDLE)  # type: ignore[arg-type]
    assert der.read_bytes() == FAKE_DER


def test_write_outputs_pkcs7_out_writes_bytes(tmp_path: Path) -> None:
    """--pkcs7-out writes the PKCS#7 bytes returned by download_certificate_pkcs7()."""
    p7b = tmp_path / "cert.p7b"
    _write_outputs(FakeOrder({}), _args(pkcs7_out=str(p7b)), BUNDLE)  # type: ignore[arg-type]
    assert p7b.read_bytes() == FAKE_PKCS7


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


def test_write_outputs_binary_unwritable_path_is_fatal(tmp_path: Path) -> None:
    """An unwritable --der-out path exits 1 instead of raising OSError."""
    missing_dir = tmp_path / "no-such-dir" / "cert.der"
    with pytest.raises(SystemExit) as excinfo:
        _write_outputs(FakeOrder({}), _args(der_out=str(missing_dir)), BUNDLE)  # type: ignore[arg-type]
    assert excinfo.value.code == 1
