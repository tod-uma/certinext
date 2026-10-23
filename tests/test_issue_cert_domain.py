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

"""Tests for how `certinext issue-cert` picks the primary domain and SANs."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from structlog.testing import capture_logs

from certinext.cli import issue_cert
from certinext.cli import main as cli_main
from certinext.cli.issue_cert import _resolve_domain_and_sans
from certinext.csr import CsrInfo
from tests.test_csr import _make_csr


def _info(cn: str | None, sans: list[str]) -> CsrInfo:
    """Build a CsrInfo with only the fields domain resolution reads.

    Args:
        cn: Common Name, or ``None`` for a CN-less CSR.
        sans: DNS SANs as :func:`~certinext.csr.parse_csr` would return them.

    Returns:
        A :class:`CsrInfo`.
    """
    return CsrInfo(common_name=cn, email=None, locality=None, state=None,
                   organization=None, sans=sans)


def test_cn_is_primary_without_domain() -> None:
    """The CSR's CN is the primary domain when --domain is absent."""
    assert _resolve_domain_and_sans(_info("a.example.edu", ["b.example.edu"]), None, None) == (
        "a.example.edu", ["b.example.edu"],
    )


def test_no_cn_with_domain_drops_primary_from_sans() -> None:
    """A CN-less CSR works with --domain, and the primary is not repeated as a SAN."""
    info = _info(None, ["a.example.edu", "b.example.net"])
    assert _resolve_domain_and_sans(info, "A.example.edu", None) == (
        "A.example.edu", ["b.example.net"],
    )


def test_no_cn_without_domain_exits() -> None:
    """A CN-less CSR without --domain is a usage error."""
    with pytest.raises(SystemExit):
        _resolve_domain_and_sans(_info(None, ["a.example.edu"]), None, None)


def test_explicit_sans_override_csr_sans() -> None:
    """Explicit --san values replace the CSR's SANs, and dropped CSR names draw a warning."""
    info = _info(None, ["a.example.edu", "b.example.net", "c.example.org"])
    with capture_logs() as logs:
        result = _resolve_domain_and_sans(info, "a.example.edu", ["c.example.org"])
    assert result == ("a.example.edu", ["c.example.org"])
    assert [e["dropped"] for e in logs if e["log_level"] == "warning"] == ["b.example.net"]


def test_no_cn_domain_not_in_csr_exits() -> None:
    """A CN-less CSR cannot be ordered under a --domain the CSR does not contain."""
    with pytest.raises(SystemExit):
        _resolve_domain_and_sans(_info(None, ["a.example.edu"]), "b.example.edu", None)


def test_no_cn_no_sans_exits() -> None:
    """A CSR with neither a CN nor DNS SANs has no name --domain could match."""
    with pytest.raises(SystemExit):
        _resolve_domain_and_sans(_info(None, []), "b.example.edu", None)


def test_explicit_san_not_in_csr_exits() -> None:
    """An explicit --san the CSR does not contain is rejected before ordering."""
    info = _info(None, ["a.example.edu", "b.example.net"])
    with pytest.raises(SystemExit):
        _resolve_domain_and_sans(info, "a.example.edu", ["c.example.org"])


def test_domain_override_dropping_cn_warns() -> None:
    """A --domain that replaces the CN keeps the order but warns that the CN is left out."""
    info = _info("y.example.edu", ["x.example.edu"])
    with capture_logs() as logs:
        result = _resolve_domain_and_sans(info, "x.example.edu", None)
    assert result == ("x.example.edu", [])
    assert [e["dropped"] for e in logs if e["log_level"] == "warning"] == ["y.example.edu"]


def test_duplicate_sans_are_collapsed() -> None:
    """SANs differing only in case are sent once, keeping the first spelling."""
    info = _info("a.example.edu", ["b.example.edu", "B.example.edu"])
    assert _resolve_domain_and_sans(info, None, None) == ("a.example.edu", ["b.example.edu"])


class _OrderPlaced(Exception):
    """Raised by the fake order creator to stop the command before the workflow phase."""


def _run_issue_cert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, csr_pem: str, *extra: str
) -> tuple[int, list[dict[str, Any]]]:
    """Run ``certinext issue-cert`` offline and record any order-creation call.

    The session, keyring and config file are stubbed out, and order creation
    is replaced by a fake that records its keyword arguments and stops the
    command, so nothing reaches the network.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: Per-test temporary directory for the CSR and config file.
        csr_pem: PEM-encoded CSR to submit.
        *extra: Additional command-line arguments.

    Returns:
        ``(exit_code, create_calls)`` where ``create_calls`` holds the keyword
        arguments of each ``_create_order`` call.
    """
    for var in ("CERTINEXT_PROFILE", "CERTINEXT_REQUESTOR_NAME", "CERTINEXT_REQUESTOR_EMAIL",
                "CERTINEXT_REQUESTOR_PHONE", "CERTINEXT_PREVETTING_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CERTINEXT_CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.setattr(issue_cert, "session", lambda ctx: MagicMock())
    monkeypatch.setattr(issue_cert, "keyring_get", lambda *a: None)

    calls: list[dict[str, Any]] = []

    def fake_create(sess: object, values: object, **kwargs: Any) -> None:
        calls.append(kwargs)
        raise _OrderPlaced

    monkeypatch.setattr(issue_cert, "_create_order", fake_create)
    csr_path = tmp_path / "req.csr"
    csr_path.write_text(csr_pem)
    argv = ["issue-cert", str(csr_path), "--no-domain-check", "--prevetting-token", "tok",
            "--requestor-name", "Test User", "--requestor-email", "test@example.edu",
            "--requestor-phone", "+12075550100", *extra]
    try:
        code = cli_main(argv)
    except _OrderPlaced:
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    return code, calls


def test_cli_no_cn_csr_orders_named_domain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A CN-less CSR reaches order creation with --domain as primary and the other SANs."""
    csr = _make_csr(cn=None, sans=["a.example.edu", "b.example.net"])
    code, calls = _run_issue_cert(monkeypatch, tmp_path, csr, "--domain", "a.example.edu")
    assert code == 0
    assert len(calls) == 1
    assert calls[0]["domain"] == "a.example.edu"
    assert calls[0]["sans"] == ["b.example.net"]
    assert calls[0]["csr"] == csr


def test_cli_no_cn_csr_domain_not_in_csr_places_no_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A --domain absent from a CN-less CSR exits before any order is created."""
    csr = _make_csr(cn=None, sans=["a.example.edu"])
    code, calls = _run_issue_cert(monkeypatch, tmp_path, csr, "--domain", "b.example.edu")
    assert code != 0
    assert calls == []
