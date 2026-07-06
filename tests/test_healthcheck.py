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

"""Tests for the certinext-healthcheck read-only API probe."""

from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import httpx
from pydantic import BaseModel, ValidationError

from certinext.exceptions import (
    CertiNextAPIError,
    CertiNextNotFoundError,
    CertiNextRateLimitError,
)
from certinext.healthcheck_cli import (
    REGISTRY,
    Outcome,
    Probe,
    ProbeResult,
    classify,
    exit_code,
    render_summary,
    render_table,
    run,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _probe(
    call: Callable[[Any, dict], Any],
    *,
    name: str = "test.probe",
    tier: int = 1,
    requires: tuple[str, ...] = (),
    count_of: Callable[[Any], int | None] | None = None,
    empty_is_suspect: bool = False,
) -> Probe:
    """Build a Probe wrapping an arbitrary call for classification tests."""
    return Probe(
        name=name, tier=tier, endpoint="GET /x", call=call,
        requires=requires, count_of=count_of, empty_is_suspect=empty_is_suspect,
    )


def _raise(exc: Exception) -> Callable[[Any, dict], Any]:
    """Return a probe call that raises ``exc`` when invoked."""
    def _call(_session: Any, _ctx: dict) -> Any:
        raise exc
    return _call


def _classify(call: Callable[[Any, dict], Any], **kwargs: Any) -> ProbeResult:
    """Run ``classify`` over a one-off probe with an empty context."""
    return classify(_probe(call, **kwargs), MagicMock(), {})


# ---------------------------------------------------------------------------
# One test per outcome
# ---------------------------------------------------------------------------


class TestClassifyOutcomes:
    """classify() maps each call result/exception to the correct outcome."""

    def test_pass_with_count(self):
        """A non-empty list result is PASS with the element count recorded."""
        result = _classify(lambda s, c: ["a", "b", "c"], count_of=len)
        assert result.outcome == Outcome.PASS
        assert result.count == 3

    def test_pass_scalar_result(self):
        """A scalar (non-countable) 2xx result is PASS with count None."""
        result = _classify(lambda s, c: object())
        assert result.outcome == Outcome.PASS
        assert result.count is None

    def test_empty_when_suspect(self):
        """An empty list is EMPTY when the probe marks empty as suspect."""
        result = _classify(lambda s, c: [], count_of=len, empty_is_suspect=True)
        assert result.outcome == Outcome.EMPTY
        assert result.count == 0

    def test_empty_list_passes_when_not_suspect(self):
        """An empty list is PASS for probes where empty is legitimate."""
        result = _classify(lambda s, c: [], count_of=len, empty_is_suspect=False)
        assert result.outcome == Outcome.PASS

    def test_denied_on_401(self):
        """A 401 API error is DENIED."""
        result = _classify(_raise(CertiNextAPIError(401, {"title": "Unauthorized"})))
        assert result.outcome == Outcome.DENIED
        assert result.http_status == 401

    def test_denied_on_403(self):
        """A 403 API error is DENIED."""
        result = _classify(_raise(CertiNextAPIError(403, {"title": "Forbidden"})))
        assert result.outcome == Outcome.DENIED
        assert result.http_status == 403

    def test_denied_on_token_runtime_error(self):
        """A token RuntimeError naming invalid_client is DENIED (no status code)."""
        result = _classify(_raise(RuntimeError(
            "Token request failed: 401 Unauthorized\nBody: '{\"error\": \"invalid_client\"}'"
        )))
        assert result.outcome == Outcome.DENIED
        assert result.http_status is None

    def test_network_on_non_auth_token_runtime_error(self):
        """A token RuntimeError without auth markers is NETWORK."""
        result = _classify(_raise(RuntimeError(
            "Token endpoint returned non-JSON (status 200)"
        )))
        assert result.outcome == Outcome.NETWORK

    def test_not_found_on_404(self):
        """A 404 (CertiNextNotFoundError) is NOT_FOUND."""
        result = _classify(_raise(CertiNextNotFoundError(404, {"title": "Not Found"})))
        assert result.outcome == Outcome.NOT_FOUND
        assert result.http_status == 404

    def test_server_bug_on_422_captures_raw_body(self):
        """A 422 is SERVER_BUG with the raw RFC 7807 body preserved verbatim."""
        body = {"type": "about:blank", "title": "Unprocessable Entity", "status": 422}
        result = _classify(_raise(CertiNextAPIError(422, body)))
        assert result.outcome == Outcome.SERVER_BUG
        assert result.http_status == 422
        assert result.detail == body

    def test_server_bug_extracts_ems_code(self):
        """SERVER_BUG surfaces the EMS code when the body carries one."""
        result = _classify(_raise(CertiNextAPIError(422, {"detail": "EMS-921: CSR malformed"})))
        assert result.outcome == Outcome.SERVER_BUG
        assert result.ems_code == "EMS-921"

    def test_server_bug_on_500(self):
        """A 500 is SERVER_BUG."""
        result = _classify(_raise(CertiNextAPIError(500, "Internal Server Error")))
        assert result.outcome == Outcome.SERVER_BUG
        assert result.http_status == 500

    def test_rate_limited_on_429(self):
        """A 429 is RATE_LIMITED and is not exit-affecting."""
        result = _classify(_raise(CertiNextRateLimitError(429, {"title": "Too Many"}, retry_after=30.0)))
        assert result.outcome == Outcome.RATE_LIMITED
        assert result.http_status == 429

    def test_network_on_connection_error(self):
        """An httpx ConnectError (no HTTP response) is NETWORK."""
        result = _classify(_raise(httpx.ConnectError("connection refused")))
        assert result.outcome == Outcome.NETWORK

    def test_network_on_timeout(self):
        """An httpx ReadTimeout is NETWORK."""
        result = _classify(_raise(httpx.ReadTimeout("timed out")))
        assert result.outcome == Outcome.NETWORK

    def test_server_bug_on_validation_error(self):
        """A pydantic ValidationError (2xx with drifted shape) is SERVER_BUG, not PASS.

        ValidationError subclasses ValueError, so this guards the catch order in
        classify(): shape drift must not be misread as a benign parse note.
        """

        class _Shape(BaseModel):
            count: int

        try:
            _Shape.model_validate({"count": "not-an-int"})
            raise AssertionError("model_validate must raise")
        except ValidationError as exc:
            err = exc

        result = _classify(_raise(err))
        assert result.outcome == Outcome.SERVER_BUG
        assert "shape drift" in result.message

    def test_skipped_when_required_input_missing(self):
        """A Tier-2 probe whose input is absent is SKIPPED — the call never runs."""
        def _boom(_s: Any, _c: dict) -> Any:
            raise AssertionError("call must not run when input is missing")

        result = classify(_probe(_boom, tier=2, requires=("order_id",)), MagicMock(), {})
        assert result.outcome == Outcome.SKIPPED

    def test_value_error_after_2xx_is_pass_with_note(self):
        """A ValueError (raised after a 2xx parse) is PASS — the endpoint responded."""
        result = _classify(_raise(ValueError("Unexpected DCV method 'CNAME'")))
        assert result.outcome == Outcome.PASS
        assert "parse note" in result.message


# ---------------------------------------------------------------------------
# Exit code mapping
# ---------------------------------------------------------------------------


class TestExitCode:
    """exit_code() reflects exit-affecting outcomes and the --strict flag."""

    def _result(self, outcome: str) -> ProbeResult:
        return ProbeResult(name="p", tier=1, endpoint="GET /x", outcome=outcome)

    def test_zero_when_all_pass(self):
        """exit_code is 0 when every probe passes or is skipped/rate-limited."""
        results = [self._result(o) for o in (Outcome.PASS, Outcome.SKIPPED, Outcome.RATE_LIMITED)]
        assert exit_code(results) == 0

    def test_one_on_server_bug(self):
        """A SERVER_BUG makes the exit code non-zero."""
        results = [self._result(Outcome.PASS), self._result(Outcome.SERVER_BUG)]
        assert exit_code(results) == 1

    def test_one_on_denied(self):
        """A DENIED makes the exit code non-zero."""
        assert exit_code([self._result(Outcome.DENIED)]) == 1

    def test_one_on_network(self):
        """A NETWORK failure makes the exit code non-zero."""
        assert exit_code([self._result(Outcome.NETWORK)]) == 1

    def test_empty_is_clean_without_strict(self):
        """EMPTY does not affect the exit code unless --strict is set."""
        assert exit_code([self._result(Outcome.EMPTY)]) == 0

    def test_empty_fails_with_strict(self):
        """EMPTY makes the exit code non-zero under --strict."""
        assert exit_code([self._result(Outcome.EMPTY)], strict=True) == 1


# ---------------------------------------------------------------------------
# End-to-end run() over a mocked session
# ---------------------------------------------------------------------------


def _ok_session() -> MagicMock:
    """Build a mocked session where every probe succeeds and feeds context."""
    sess = MagicMock()
    sess.accounts.me.return_value = {"accountNumber": "5912517854"}
    sess.accounts.list_groups.return_value = [MagicMock()]

    org = MagicMock()
    org.organization_number = "ORG-1"
    sess.accounts.list_organizations.return_value = [org]

    product = MagicMock()
    product.product_code = "842"
    category = MagicMock()
    category.products = [product]
    sess.catalog.list_products.return_value = [category]

    domain = MagicMock()
    domain.id = "DOM-1"
    sess.domain.get_list.return_value = [domain]

    sess.ledger.get_page.return_value = [MagicMock()]

    order = MagicMock()
    order.order_number = "ORD-1"
    sess.orders.get_page.return_value = [order]

    sess.accounts.get_organization.return_value = MagicMock()
    sess.catalog.get_custom_fields.return_value = []
    sess.domain.get.return_value = MagicMock()

    ssl_order = MagicMock()
    ssl_order.status = "issued"
    sess.ssl.get.return_value = ssl_order
    return sess


def _by_name(results: list[ProbeResult]) -> dict[str, str]:
    """Map probe name -> outcome for assertion convenience."""
    return {r.name: r.outcome for r in results}


class TestRun:
    """run() orchestrates the registry, feeds context, and skips correctly."""

    def test_happy_path_all_pass(self):
        """Every probe passes when the session returns well-formed data."""
        results = run(_ok_session())
        assert len(results) == len(REGISTRY)
        assert all(r.outcome == Outcome.PASS for r in results)
        assert exit_code(results) == 0

    def test_quick_runs_tier_1_only(self):
        """--quick runs only Tier-1 probes."""
        results = run(_ok_session(), quick=True)
        assert all(r.tier == 1 for r in results)
        assert len(results) == sum(1 for p in REGISTRY if p.tier == 1)

    def test_domain_outage_is_selective(self):
        """A 422 on /domains is SERVER_BUG; dependent Tier-2 domain probes SKIPPED.

        This mirrors the live production scenario the probe is built to catch:
        domain.get_list fails while accounts/catalog/orders/ledger stay healthy.
        """
        sess = _ok_session()
        sess.domain.get_list.side_effect = CertiNextAPIError(
            422, {"title": "Unprocessable Entity", "status": 422}
        )
        outcomes = _by_name(run(sess))

        assert outcomes["domain.get_list"] == Outcome.SERVER_BUG
        for dependent in (
            "domain.get",
            "domain.get_dcv",
            "domain.last_dcv_attempt",
            "domain.dcv_attempt_history",
        ):
            assert outcomes[dependent] == Outcome.SKIPPED
        # Unrelated endpoints are unaffected.
        assert outcomes["accounts.me"] == Outcome.PASS
        assert outcomes["catalog.list_products"] == Outcome.PASS
        assert outcomes["orders.get_page"] == Outcome.PASS
        assert outcomes["ssl.get"] == Outcome.PASS
        assert exit_code(run(sess)) == 1

    def test_empty_domain_list_is_empty_outcome(self):
        """An empty /domains list is EMPTY (suspect masked-failure)."""
        sess = _ok_session()
        sess.domain.get_list.return_value = []
        outcomes = _by_name(run(sess))
        assert outcomes["domain.get_list"] == Outcome.EMPTY
        # No domain context, so domain Tier-2 probes are skipped.
        assert outcomes["domain.get_dcv"] == Outcome.SKIPPED


class TestRenderers:
    """The table and summary renderers produce output without crashing."""

    def test_summary_counts_outcomes(self):
        """render_summary tallies outcomes in the fixed order."""
        results = run(_ok_session())
        summary = render_summary(results)
        assert summary == f"PASS {len(REGISTRY)}"

    def test_table_includes_every_probe(self):
        """render_table lists a row for every probe."""
        results = run(_ok_session())
        table = render_table(results)
        for probe in REGISTRY:
            assert probe.name in table

    def test_to_dict_excludes_payload(self):
        """ProbeResult.to_dict drops the raw payload but keeps the detail body."""
        body = {"status": 422, "detail": "boom"}
        result = ProbeResult(
            name="p", tier=1, endpoint="GET /x", outcome=Outcome.SERVER_BUG,
            detail=body, payload=["secret"],
        )
        d = result.to_dict()
        assert "payload" not in d
        assert d["detail"] == body
