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
from typing import Any
from unittest.mock import MagicMock

import pytest
import structlog

from certinext.cli import main as cli_main
from certinext.cli.issue_cert import _leaf_issuer, _preflight_coverage, resolve_order_defaults
from certinext.exceptions import CertiNextAPIError
from certinext.models.accounts import OrgCaValidation
from certinext.models.domains import DcvInfo
from certinext.models.orders import OrderRecord

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
def _uncached_structlog() -> Iterator[None]:
    """Reset structlog around each test so no module logger gets cached.

    ``setup_logging`` (run by every ``cli_main`` call) configures
    ``cache_logger_on_first_use=True``. A module logger first used under
    that config, such as ``issue_cert.log`` from the pre-flight tests here,
    stays bound for the rest of the process, and later
    :func:`structlog.testing.capture_logs` tests in other modules then see
    no events. Defaults never cache.

    Yields:
        Nothing; resets before and after the test.
    """
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
