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

"""CLI flags for multi-CA (SSL.com) work: domains, ca-validation, list-certificates, issue-cert.

Every API call goes through a MagicMock session patched into the command
module, so these tests check what the CLI asks the library for and how it
renders the answer, not the wire.
"""

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import structlog

from certinext._keyring import keyring_service
from certinext.cli import issue_cert
from certinext.cli import main as cli_main
from certinext.cli.issue_cert import _leaf_issuer, _preflight_coverage, resolve_order_defaults
from certinext.exceptions import CertiNextAPIError
from certinext.models.accounts import OrgCaValidation
from certinext.models.domains import DcvInfo
from certinext.models.orders import OrderRecord
from tests.test_csr import _make_csr

_SSLCOM_DCV: dict[str, Any] = {
    "dcvMethod": "dns-persist",
    "validatedBy": "SSLCOM",
    "caStatus": "VALIDATED",
    "optionId": "opt-persist",
    "recordName": "_validation-persist.example.edu",
    "recordValue": "ssl.com; accounturi=https://example.invalid/acct/1",
    "options": [
        {
            "optionId": "opt-txt", "method": "dns-txt",
            "recordName": "_pki-validation.example.edu", "recordValue": "abc123",
            "coversName": "example.edu", "exactName": True,
        },
        {
            "optionId": "opt-persist", "method": "dns-persist",
            "recordName": "_validation-persist.example.edu",
            "recordValue": "ssl.com; accounturi=https://example.invalid/acct/1",
            "coversName": "example.edu", "exactName": False,
            "expiresAt": "2027-01-01T00:00:00Z",
        },
    ],
}

_CA_VALIDATION: dict[str, Any] = {
    "organizationNumber": "ORG-001",
    "ca": "sslcom",
    "status": "VALIDATED",
    "enabled": True,
    "subscriberAgreementAccepted": True,
    "levels": [
        {"level": "OV", "status": "VALIDATED", "usable": True, "validTill": "2027-12-05T00:00:00"},
        {"level": "EV", "status": "NOT_SUBMITTED", "usable": False},
    ],
    "readiness": {
        "ready": True,
        "evReady": False,
        "missing": [],
        "evMissing": ["Business category"],
        "softMissing": [],
        "current": {"contactName": "Jane Placeholder", "contactPhone": "+12075550100"},
    },
    "contact": {"name": "Jane Placeholder", "email": "jane@example.invalid"},
}


@pytest.fixture(autouse=True)
def _uncached_structlog(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep every module logger uncached while these tests run.

    ``setup_logging`` (run by every ``cli_main`` call) configures
    ``cache_logger_on_first_use=True``. A module logger first used under
    that config, such as ``issue_cert.log`` from the whole-command
    issue-cert tests here, stays bound for the rest of the process —
    :func:`structlog.reset_defaults` cannot undo it — and later
    :func:`structlog.testing.capture_logs` tests in other modules then see
    no events. So ``structlog.configure`` is wrapped to force caching off,
    and the config is reset before and after each test.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Yields:
        Nothing; resets before and after the test.
    """
    real_configure = structlog.configure

    def configure_uncached(*args: Any, **kwargs: Any) -> None:
        """Pass through to ``structlog.configure`` with caching disabled."""
        kwargs["cache_logger_on_first_use"] = False
        real_configure(*args, **kwargs)

    monkeypatch.setattr(structlog, "configure", configure_uncached)
    structlog.reset_defaults()
    yield
    structlog.reset_defaults()


@pytest.fixture
def sess(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch a MagicMock session into every command module these tests drive.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        The shared MagicMock session.
    """
    mock = MagicMock()
    for module in ("domains", "ca_validation", "list_certificates"):
        monkeypatch.setattr(f"certinext.cli.{module}.session", lambda ctx, **kw: mock)
    return mock


# --- domains ---------------------------------------------------------------


def test_domains_list_validated_by(sess: MagicMock) -> None:
    """``--validated-by`` reaches ``get_list`` and nothing else is added."""
    sess.domain.get_list.return_value = []
    assert cli_main(["domains", "list", "--validated-by", "SSLCOM"]) == 0
    sess.domain.get_list.assert_called_once_with(validated_by="SSLCOM")


def test_domains_list_without_flag_sends_no_filter(sess: MagicMock) -> None:
    """Without ``--validated-by`` the call is unchanged from before."""
    sess.domain.get_list.return_value = []
    assert cli_main(["domains", "list"]) == 0
    sess.domain.get_list.assert_called_once_with()


@pytest.mark.parametrize("cmd", ["get", "get-dcv", "verify-dcv"])
def test_name_commands_pass_validated_by(sess: MagicMock, cmd: str) -> None:
    """Name lookups forward ``--validated-by`` to ``domain.get``."""
    sess.domain.get.return_value.get_dcv.return_value = DcvInfo.from_wire(_SSLCOM_DCV)
    assert cli_main(["domains", cmd, "example.edu", "--validated-by", "SSLCOM"]) == 0
    sess.domain.get.assert_called_once_with("example.edu", validated_by="SSLCOM")


def test_verify_dcv_option_id(sess: MagicMock) -> None:
    """``--option-id`` is passed to ``Domain.verify``."""
    assert cli_main(["domains", "verify-dcv", "dom-1", "--option-id", "opt-txt"]) == 0
    sess.domain.get.return_value.verify.assert_called_once_with(option_id="opt-txt")


def test_verify_dcv_default_has_no_option(sess: MagicMock) -> None:
    """Without ``--option-id`` verify gets ``None`` (the selected option)."""
    assert cli_main(["domains", "verify-dcv", "dom-1"]) == 0
    sess.domain.get.return_value.verify.assert_called_once_with(option_id=None)


def test_create_ca(sess: MagicMock) -> None:
    """``--ca`` becomes the ``ca`` keyword of ``domain.create``."""
    assert cli_main(["domains", "create", "example.edu", "--ca", "SSLCOM"]) == 0
    sess.domain.create.assert_called_once_with("example.edu", ca="SSLCOM")


def test_create_ca_twice_is_a_usage_error(sess: MagicMock) -> None:
    """``--ca`` plus ``ca=...`` is refused before any API call."""
    assert cli_main(["domains", "create", "example.edu", "ca=EMSIGN", "--ca", "SSLCOM"]) == 2
    sess.domain.create.assert_not_called()


def _named(name: str, ca: str) -> MagicMock:
    """Build a stand-in domain record with a name and a CA.

    Args:
        name: The domain name.
        ca: The record's CA (``Domain.ca``).

    Returns:
        A MagicMock carrying ``name`` and ``ca``.
    """
    rec = MagicMock()
    rec.name, rec.ca = name, ca
    return rec


@pytest.mark.parametrize(
    "argv",
    [["domains", "verify-dcv", "example.edu"], ["domains", "deactivate", "example.edu", "--yes"]],
)
def test_write_refuses_name_held_under_two_cas(
    sess: MagicMock, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    """A write on a name with one record per CA is a usage error, not an emSign default."""
    sess.domain.get_list.return_value = [_named("example.edu", "EMSIGN"), _named("Example.edu", "SSLCOM")]
    assert cli_main(argv) == 2
    assert "EMSIGN, SSLCOM" in capsys.readouterr().err
    sess.domain.get.assert_not_called()
    for rec in sess.domain.get_list.return_value:
        rec.verify.assert_not_called()
        rec.deactivate.assert_not_called()


def test_verify_dcv_single_name_match_is_used(sess: MagicMock) -> None:
    """One record for the name: it is verified directly, with no second lookup."""
    only = _named("example.edu", "SSLCOM")
    sess.domain.get_list.return_value = [_named("other.edu", "EMSIGN"), only]
    assert cli_main(["domains", "verify-dcv", "example.edu"]) == 0
    only.verify.assert_called_once_with(option_id=None)
    sess.domain.get.assert_not_called()


def test_verify_dcv_unknown_name_falls_through_to_get(sess: MagicMock) -> None:
    """No match: the library lookup runs so its not-found error is the one reported."""
    sess.domain.get_list.return_value = []
    assert cli_main(["domains", "verify-dcv", "example.edu"]) == 0
    sess.domain.get.assert_called_once_with("example.edu", validated_by=None)


def test_get_dcv_sslcom_options_table(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """The human form lists every option, stars the selected one and hides emSign fields."""
    sess.domain.get.return_value.get_dcv.return_value = DcvInfo.from_wire(_SSLCOM_DCV)
    assert cli_main(["domains", "get-dcv", "dom-1"]) == 0
    out = capsys.readouterr().out
    assert "Validation options" in out
    assert "_pki-validation.example.edu" in out
    lines = [ln for ln in out.splitlines() if "opt-persist" in ln and "DNS-PERSIST" in ln]
    assert lines and lines[0].lstrip().startswith("*")
    assert "token" not in out.split("Validation options")[0]
    assert "SSLCOM" in out


def test_get_dcv_emsign_hides_sslcom_fields(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """An emSign DCV shows its token and no empty SSL.com rows or options table."""
    sess.domain.get.return_value.get_dcv.return_value = DcvInfo.from_wire(
        {"dcvMethod": "dns-txt", "txtToken": "tok-123"}
    )
    assert cli_main(["domains", "get-dcv", "dom-1"]) == 0
    out = capsys.readouterr().out
    assert "tok-123" in out
    assert "record_name" not in out
    assert "Validation options" not in out


def test_get_dcv_json_is_full_dump(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """``--json`` keeps the whole model dump, options included."""
    sess.domain.get.return_value.get_dcv.return_value = DcvInfo.from_wire(_SSLCOM_DCV)
    assert cli_main(["domains", "--json", "get-dcv", "dom-1"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [o["option_id"] for o in data["options"]] == ["opt-txt", "opt-persist"]
    assert data["validated_by"] == "SSLCOM"


# --- ca-validation ---------------------------------------------------------


def _ca_val() -> OrgCaValidation:
    """Build the sample validation through the same path the accessor uses."""
    return OrgCaValidation.model_validate(_CA_VALIDATION)


def test_ca_validation_human(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """The human form shows levels and missing items but no contact data."""
    sess.accounts.get_ca_validation.return_value = _ca_val()
    assert cli_main(["ca-validation", "ORG-001"]) == 0
    out = capsys.readouterr().out
    sess.accounts.get_ca_validation.assert_called_once_with("ORG-001", ca="SSLCOM")
    sess.accounts.sync_ca_validation.assert_not_called()
    assert "VALIDATED" in out and "NOT_SUBMITTED" in out
    assert "Missing for EV: Business category" in out
    assert "Jane" not in out and "2075550100" not in out


def test_ca_validation_json_has_no_pii(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """JSON carries readiness flags and lists but never the contact block."""
    sess.accounts.get_ca_validation.return_value = _ca_val()
    assert cli_main(["ca-validation", "ORG-001", "--json"]) == 0
    raw = capsys.readouterr().out
    data = json.loads(raw)
    assert data["ready"] is True and data["ev_missing"] == ["Business category"]
    assert "Jane" not in raw and "example.invalid" not in raw


def test_ca_validation_json_drops_level_extras(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """An unknown key inside a level row (e.g. a contact) never reaches ``--json``."""
    payload = json.loads(json.dumps(_CA_VALIDATION))
    payload["levels"][0]["contactEmail"] = "jane@example.invalid"
    val = OrgCaValidation.model_validate(payload)
    assert "contactEmail" not in json.dumps(val.model_dump(mode="json"))
    sess.accounts.get_ca_validation.return_value = val
    assert cli_main(["ca-validation", "ORG-001", "--json"]) == 0
    assert "example.invalid" not in capsys.readouterr().out


def test_ca_validation_sync(sess: MagicMock) -> None:
    """``--sync`` calls the sync endpoint instead of the plain read."""
    sess.accounts.sync_ca_validation.return_value = _ca_val()
    assert cli_main(["ca-validation", "ORG-001", "--sync"]) == 0
    sess.accounts.sync_ca_validation.assert_called_once_with("ORG-001", ca="SSLCOM")
    sess.accounts.get_ca_validation.assert_not_called()


# --- list-certificates -----------------------------------------------------


def _orders() -> list[OrderRecord]:
    """Two orders: one emSign product code, one SSL.com."""
    return [
        OrderRecord.model_validate({"orderNumber": "ORD-1", "productCode": "970", "commonName": "a.example.edu"}),
        OrderRecord.model_validate({"orderNumber": "ORD-2", "productCode": "1011", "commonName": "b.example.edu"}),
    ]


def test_list_certificates_ca_column(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """Each row's CA comes from the catalog map by product code."""
    sess.orders.get_list.return_value = _orders()
    sess.catalog.ca_by_product_code.return_value = {"970": "EMSIGN", "1011": "SSLCOM"}
    assert cli_main(["list-certificates", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["ca"] for r in rows] == ["EMSIGN", "SSLCOM"]


def test_list_certificates_catalog_failure_blanks_ca(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """A catalog error leaves the CA blank but still lists the orders."""
    sess.orders.get_list.return_value = _orders()
    sess.catalog.ca_by_product_code.side_effect = CertiNextAPIError(503, "down")
    assert cli_main(["list-certificates"]) == 0
    out = capsys.readouterr().out
    assert "ORD-1" in out and "ORD-2" in out and "2 certificate(s)" in out


def test_list_certificates_empty_skips_catalog(sess: MagicMock) -> None:
    """No orders means no catalog read."""
    sess.orders.get_list.return_value = []
    assert cli_main(["list-certificates"]) == 0
    sess.catalog.ca_by_product_code.assert_not_called()


# --- issue-cert ------------------------------------------------------------

_REQUIRED = {"requestor_name": "Pat", "requestor_phone": "+12075550100"}


def test_resolve_ca_from_config_is_uppercased() -> None:
    """A stored profile ``ca`` is used and normalised."""
    assert resolve_order_defaults({**_REQUIRED, "ca": " sslcom "}).ca == "SSLCOM"


def test_resolve_ca_cli_beats_config() -> None:
    """``--ca`` overrides the stored value."""
    assert resolve_order_defaults({**_REQUIRED, "ca": "EMSIGN"}, ca="sslcom").ca == "SSLCOM"


def test_resolve_ca_default_none() -> None:
    """With no source the pre-flight is off."""
    assert resolve_order_defaults(dict(_REQUIRED)).ca is None


@pytest.mark.parametrize("blank", ["", " ", "\t"])
def test_resolve_blank_ca_is_rejected(blank: str) -> None:
    """A blank ``--ca`` is an error, never a silent override of the stored CA."""
    with pytest.raises(ValueError, match="--ca"):
        resolve_order_defaults({**_REQUIRED, "ca": "SSLCOM"}, ca=blank)


class _OrderPlaced(Exception):
    """Raised by the fake order creator to stop issue-cert before the workflow phase."""


def _issue_cert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *extra: str,
    config: str = "",
    uncovered: list[str] | None = None,
    env: dict[str, str] | None = None,
    keyring_get: Any = None,
    prevetting_token: str | None = "tok",
) -> tuple[int, MagicMock, list[dict[str, Any]]]:
    """Run ``certinext issue-cert`` end to end, offline, up to order creation.

    The session is a MagicMock whose ``domain.uncovered_names`` returns
    ``uncovered``; the config file holds ``config``; order creation is a fake
    that records its keyword arguments and stops the command.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
        tmp_path: Per-test directory for the CSR and config file.
        *extra: Additional command-line arguments.
        config: TOML written to the config file.
        uncovered: What the pre-flight's coverage read reports as uncovered.
        env: Environment variables set after the certinext ones are cleared.
        keyring_get: Replacement for the keyring read (default: finds nothing).
        prevetting_token: ``--prevetting-token`` value, or None to omit the
            flag so the keyring is consulted.

    Returns:
        ``(exit_code, session_mock, create_calls)``.
    """
    for var in ("CERTINEXT_PROFILE", "CERTINEXT_REQUESTOR_NAME", "CERTINEXT_REQUESTOR_EMAIL",
                "CERTINEXT_REQUESTOR_PHONE", "CERTINEXT_PREVETTING_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    for var, value in (env or {}).items():
        monkeypatch.setenv(var, value)
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(config)
    monkeypatch.setenv("CERTINEXT_CONFIG", str(cfg_path))
    mock = MagicMock()
    mock.domain.uncovered_names.return_value = uncovered or []
    monkeypatch.setattr(issue_cert, "session", lambda ctx: mock)
    monkeypatch.setattr(issue_cert, "keyring_get", keyring_get or (lambda *a: None))
    calls: list[dict[str, Any]] = []

    def fake_create(sess: object, values: object, **kwargs: Any) -> None:
        calls.append(kwargs)
        raise _OrderPlaced

    monkeypatch.setattr(issue_cert, "_create_order", fake_create)
    csr_path = tmp_path / "req.csr"
    csr_path.write_text(_make_csr(cn="a.example.edu", sans=["a.example.edu", "b.example.edu"]))
    token = ["--prevetting-token", prevetting_token] if prevetting_token else []
    argv = ["issue-cert", str(csr_path), "--no-domain-check", *token,
            "--requestor-name", "Test User", "--requestor-email", "test@example.edu",
            "--requestor-phone", "+12075550100", *extra]
    try:
        code = cli_main(argv)
    except _OrderPlaced:
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    return code, mock, calls


def test_cli_blank_ca_flag_does_not_skip_configured_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``--ca " "`` with a stored CA is a usage error before any API read or order."""
    code, mock, calls = _issue_cert(
        monkeypatch, tmp_path, "--ca", " ", config='[defaults]\nca = "SSLCOM"\n',
    )
    assert code == 2
    mock.domain.uncovered_names.assert_not_called()
    assert calls == []


def test_cli_ca_flag_refuses_uncovered_names(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``--ca`` checks the CN and SANs from the CSR and refuses before ordering."""
    code, mock, calls = _issue_cert(monkeypatch, tmp_path, "--ca", "sslcom", uncovered=["b.example.edu"])
    assert code == 1
    mock.domain.uncovered_names.assert_called_once_with(["a.example.edu", "b.example.edu"], "SSLCOM")
    assert calls == []


def test_cli_configured_ca_runs_preflight_then_orders(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A profile ``ca`` alone turns the pre-flight on; covered names reach order creation."""
    code, mock, calls = _issue_cert(monkeypatch, tmp_path, config='[defaults]\nca = "sslcom"\n')
    assert code == 0
    mock.domain.uncovered_names.assert_called_once_with(["a.example.edu", "b.example.edu"], "SSLCOM")
    assert len(calls) == 1


def test_cli_skip_preflight_skips_configured_ca(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``--skip-preflight`` is the way to turn a stored CA's check off."""
    code, mock, calls = _issue_cert(
        monkeypatch, tmp_path, "--skip-preflight", config='[defaults]\nca = "SSLCOM"\n',
    )
    assert code == 0
    mock.domain.uncovered_names.assert_not_called()
    assert len(calls) == 1


def test_cli_env_profile_owns_saved_defaults_and_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With ``CERTINEXT_PROFILE`` set, saves and keyring reads use that profile, not the default."""
    saved: list[str | None] = []
    services: list[str] = []
    monkeypatch.setattr(issue_cert, "_maybe_save_defaults", lambda values, profile: saved.append(profile))

    def recording_keyring_get(svc: str, key: str) -> None:
        services.append(svc)

    code, _mock, calls = _issue_cert(
        monkeypatch, tmp_path, "--save-defaults",
        env={"CERTINEXT_PROFILE": "sslcom"}, keyring_get=recording_keyring_get, prevetting_token=None,
    )
    assert code == 0 and len(calls) == 1
    assert saved == ["sslcom"]
    assert services == [keyring_service("certinext", "sslcom")]


def test_preflight_passes() -> None:
    """Every name covered: no exit, CN and SANs checked together."""
    s = MagicMock()
    s.domain.uncovered_names.return_value = []
    _preflight_coverage(s, "SSLCOM", "example.edu", ["www.example.edu"])
    s.domain.uncovered_names.assert_called_once_with(["example.edu", "www.example.edu"], "SSLCOM")


def test_preflight_no_cn_csr() -> None:
    """A no-CN CSR checks only its SANs."""
    s = MagicMock()
    s.domain.uncovered_names.return_value = []
    _preflight_coverage(s, "SSLCOM", None, ["a.example.edu"])
    s.domain.uncovered_names.assert_called_once_with(["a.example.edu"], "SSLCOM")


def test_preflight_uncovered_exits_1() -> None:
    """An uncovered name stops the run before any order exists."""
    s = MagicMock()
    s.domain.uncovered_names.return_value = ["www.example.edu"]
    with pytest.raises(SystemExit) as info:
        _preflight_coverage(s, "SSLCOM", "example.edu", ["www.example.edu"])
    assert info.value.code == 1


def test_preflight_api_error_exits_1() -> None:
    """A failed domain read is fatal, not a silent pass."""
    s = MagicMock()
    s.domain.uncovered_names.side_effect = CertiNextAPIError(500, "boom")
    with pytest.raises(SystemExit) as info:
        _preflight_coverage(s, "SSLCOM", "example.edu", None)
    assert info.value.code == 1


def _pem_chain() -> str:
    """Build a CA and a leaf it signed, returned chain-first to prove order doesn't matter.

    Returns:
        A PEM bundle: CA certificate, then leaf.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA R1")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.edu")]))
        .issuer_name(ca_name).public_key(leaf_key.public_key())
        .serial_number(2).not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    enc = serialization.Encoding.PEM
    return ca_cert.public_bytes(enc).decode() + leaf.public_bytes(enc).decode()


def test_leaf_issuer_finds_leaf_in_any_order() -> None:
    """The issuer CN comes from the non-CA certificate even when it isn't first."""
    assert _leaf_issuer(_pem_chain()) == "Test Issuing CA R1"


def test_leaf_issuer_garbage_is_none() -> None:
    """Unparseable input never raises."""
    assert _leaf_issuer("not a pem") is None
