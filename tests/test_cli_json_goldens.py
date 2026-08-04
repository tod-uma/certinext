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

"""Golden-file tests for the ``--json`` output of every data-producing command.

Phase 4, step 6: these pin the 0.3.x ``--json`` format as a *regression
guard, not a contract* (ADR 0004) — nothing audited in UMS parses it, but
phase 1's ``as_dict()`` raw-payload identity makes parity nearly free, so an
accidental format change should fail loudly. A deliberate change is allowed:
regenerate with ``pytest --update-goldens`` and note it in the migration
guide.

Each test fakes the API at the :meth:`CertiNextClient.get` boundary with
canned payloads, so the full accessor/model/rendering stack runs for real.
"""

import copy
from typing import Any, Callable

import pytest

from certinext import healthcheck as hc
from certinext.cli import main as cli_main
from certinext.session import CertiNextSession
from tests.conftest import (
    FAR_FUTURE_VALID_TILL,
    SAMPLE_DCV_PENDING_WITH_TOKEN,
    SAMPLE_DOMAIN_DATA,
    SAMPLE_DOMAIN_DATA_2,
    SAMPLE_DOMAIN_DETAIL_DATA,
)

_API = "/api/certinext/v2"
_DOMAIN_ID = SAMPLE_DOMAIN_DATA["domainId"]

_ME = {"accountNumber": "42", "accountName": "University of Maine System", "accountType": "ENTERPRISE"}
_GROUPS = {"groups": [{"groupNumber": "g1", "groupName": "IT"}]}
_ORG_LIST = {
    "organizations": [
        {
            "organizationNumber": "ORG-001",
            "organizationName": "University of Maine System",
            "organizationLocality": "Bangor",
            "organizationCountryCode": "US",
            "organizationPostalCode": "04401",
            "organizationStatusId": "1",
            "isPreVettingOrg": "1",
        }
    ]
}
# Merged into the org by the lazy detail fetch that as_dict() triggers.
_ORG_DETAIL = {
    "organizationNumber": "ORG-001",
    "validationStatusId": "1",
    "validationFor": "2",
    "subscriberAgreement": {"signed": True, "signerName": "Jane Doe"},
    "orgRepresentatives": [{"name": "Jane Doe"}],
    "domains": ["maine.edu"],
}
_ORDERS = {
    "orders": [
        {
            "orderNumber": "ORD-001",
            "requestNumber": "REQ-001",
            "productCode": "955",
            "orderStatus": "Order Fulfilled",
            "certificateStatus": "issued",
            "domainName": "maine.edu",
            "validTill": FAR_FUTURE_VALID_TILL,
        },
        {
            "orderNumber": "ORD-002",
            "requestNumber": "REQ-002",
            "productCode": "970",
            "orderStatus": "Order Fulfilled",
            "certificateStatus": "issued",
            "domainName": "sub.maine.edu",
            "validTill": FAR_FUTURE_VALID_TILL,
        },
    ],
    "totalPages": 1,
}
_LEDGER = {
    "ledger": [
        {
            "date": "2026-05-01",
            "description": "DV SSL Certificate #1",
            "orderNumber": "ORD-001",
            "type": "NEW_ORDER",
            "debit": "50.00",
            "credit": None,
        },
        {
            "date": "2026-05-02",
            "description": "Account credit",
            "orderNumber": None,
            "type": "CREDIT",
            "debit": None,
            "credit": "100.00",
        },
    ],
    "totalPages": 1,
}

# The standard route table: both sample domains, detail + DCV for the first.
_ROUTES: dict[str, Any] = {
    f"{_API}/auth/me": _ME,
    f"{_API}/groups": _GROUPS,
    f"{_API}/organizations": _ORG_LIST,
    f"{_API}/organizations/ORG-001": _ORG_DETAIL,
    f"{_API}/domains": [dict(SAMPLE_DOMAIN_DATA), dict(SAMPLE_DOMAIN_DATA_2)],
    f"{_API}/domains/{_DOMAIN_ID}": dict(SAMPLE_DOMAIN_DETAIL_DATA),
    # tokenExpiry included deliberately: proves the --json path serializes
    # DcvInfo.token_expiry (a datetime) without crashing json.dumps().
    f"{_API}/domains/{_DOMAIN_ID}/dcv": {**SAMPLE_DCV_PENDING_WITH_TOKEN, "tokenExpiry": "2026-08-01T00:00:00Z"},
    f"{_API}/reports/orders": _ORDERS,
    f"{_API}/reports/ledger": _LEDGER,
}


class _FakeApi:
    """Exact-path router standing in for :meth:`CertiNextClient.get`.

    Accessor pagination terminates naturally because every canned list is
    shorter than a page (domains) or carries ``totalPages: 1`` (reports).
    """

    def __init__(self, routes: dict[str, Any]) -> None:
        """
        Args:
            routes: Mapping of exact API path to the parsed-JSON payload
                to return. Payloads are deep-copied on the way out so a
                command that mutates a response can't leak into another test.
        """
        self._routes = routes

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Return the canned payload for ``path``, ignoring query params.

        Args:
            path: API path relative to the base URL.
            params: Ignored; pagination terminates via payload shape.

        Returns:
            The canned parsed-JSON payload.

        Raises:
            AssertionError: If no route is registered for ``path``.
        """
        if path not in self._routes:
            raise AssertionError(f"unexpected GET {path}")
        return copy.deepcopy(self._routes[path])


@pytest.fixture
def run_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Callable[[str, list[str]], str]:
    """Run a subcommand against the canned API and return its stdout.

    The returned callable patches ``session`` (ADR 0009's shared session
    helper) in the named command module to hand back a real
    :class:`CertiNextSession` whose HTTP ``get`` is the canned router,
    invokes :func:`certinext.cli.main`, asserts exit code 0, and returns
    captured stdout.

    Returns:
        A ``run(module, argv) -> stdout`` callable.
    """

    def run(module: str, argv: list[str]) -> str:
        """Invoke ``certinext {argv}`` with the fake API behind ``module``.

        Args:
            module: Module name under ``certinext.cli`` whose ``session`` to patch.
            argv: Full CLI argument list.

        Returns:
            The command's captured stdout.
        """
        sess = CertiNextSession(client_id="test", client_secret="secret")
        monkeypatch.setattr(sess._client, "get", _FakeApi(_ROUTES).get)
        monkeypatch.setattr(f"certinext.cli.{module}.session", lambda ctx, **kwargs: sess)
        assert cli_main(argv) == 0
        return capsys.readouterr().out

    return run


def test_accounts_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``accounts --json`` emits the account/groups/organizations bundle."""
    golden("json/accounts.json", run_json("accounts", ["accounts", "--json"]))


def test_ledger_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``ledger --json`` emits the raw ledger records."""
    golden("json/ledger.json", run_json("ledger", ["ledger", "--json"]))


def test_list_certificates_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``list-certificates --json`` emits the raw order records."""
    golden(
        "json/list-certificates.json",
        run_json("list_certificates", ["list-certificates", "--json"]),
    )


def test_pending_dcv_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``pending-dcv --json`` emits only the domains still needing DCV."""
    golden("json/pending-dcv.json", run_json("pending_dcv", ["pending-dcv", "--json"]))


def test_domain_cert_count_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``domain-cert-count --json`` emits the per-domain count rows."""
    golden(
        "json/domain-cert-count.json",
        run_json("domain_cert_count", ["domain-cert-count", "--json"]),
    )


def test_parent_dcv_status_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``parent-dcv-status --no-ns-check --json`` emits status/expiry rows.

    ``--no-ns-check`` keeps the test offline; the fixture expiry is the
    far-future sentinel so ``expiring_soon`` stays False for any test run
    this side of 2069.
    """
    golden(
        "json/parent-dcv-status.json",
        run_json(
            "parent_dcv_status",
            ["parent-dcv-status", "--no-ns-check", "--json"],
        ),
    )


def test_domains_list_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``domains --json list`` emits the raw domain payloads."""
    golden("json/domains-list.json", run_json("domains", ["domains", "--json", "list"]))


def test_domains_get_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``domains --json get <id>`` emits the single-domain detail payload."""
    golden(
        "json/domains-get.json",
        run_json("domains", ["domains", "--json", "get", _DOMAIN_ID]),
    )


def test_domains_get_dcv_json(run_json: Callable[[str, list[str]], str], golden: Callable[[str, str], None]) -> None:
    """``domains --json get-dcv <id>`` emits the DCV method/token payload."""
    golden(
        "json/domains-get-dcv.json",
        run_json("domains", ["domains", "--json", "get-dcv", _DOMAIN_ID]),
    )


def test_healthcheck_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    golden: Callable[[str, str], None],
) -> None:
    """``healthcheck --json`` emits the probe-result dicts and exits 0 on PASS.

    The probe run itself is stubbed (its network behavior is covered by
    test_probes/test_healthcheck); this golden pins the JSON rendering and
    the exit-code path through the CLI.
    """
    results = [
        hc.ProbeResult(
            name="accounts.me",
            tier=1,
            endpoint="GET /auth/me",
            outcome=hc.Outcome.PASS,
            count=None,
            duration_ms=12.0,
        ),
        hc.ProbeResult(
            name="domain.get_list",
            tier=1,
            endpoint="GET /domains",
            outcome=hc.Outcome.PASS,
            count=2,
            duration_ms=34.0,
        ),
    ]
    sess = CertiNextSession(client_id="test", client_secret="secret")
    monkeypatch.setattr("certinext.cli.healthcheck.session", lambda ctx, **kwargs: sess)
    monkeypatch.setattr(hc, "run", lambda _sess, quick=False, on_result=None: results)
    with pytest.raises(SystemExit) as excinfo:
        cli_main(["healthcheck", "--json"])
    assert excinfo.value.code == 0
    golden("json/healthcheck.json", capsys.readouterr().out)
