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

"""Read-only health & coverage probe engine for the CertiNext API.

``certinext healthcheck`` exercises (nearly) every CertiNext **read** endpoint
the library exposes, classifies each result, and reports what works and what
doesn't for the credentials it was given. It is provably safe to run against
production: it only ever issues GETs and never mutates.

This module holds the probe registry, classification, and rendering — the
operations layer. The CLI command in :mod:`certinext.cli` is a thin wrapper,
so a TUI or MCP server can reuse :func:`run` / :func:`exit_code` directly.

Two tiers of probes run in order:

- **Tier 1** needs no input and always runs (auth canary, groups, organizations,
  catalog, domains, ledger, orders).
- **Tier 2** needs an ID derived from a Tier-1 result (a specific organization,
  product, domain, or order). When that input is unavailable a Tier-2 probe is
  reported ``SKIPPED`` rather than ``FAIL``.

Each probe yields one outcome: ``PASS``, ``EMPTY``, ``DENIED``, ``NOT_FOUND``,
``SERVER_BUG``, ``RATE_LIMITED``, ``NETWORK``, or ``SKIPPED``. The process exits
non-zero when any probe is ``DENIED``, ``NOT_FOUND``, ``SERVER_BUG`` or
``NETWORK`` (add ``EMPTY`` with ``--strict``).
"""

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from certinext.exceptions import CertiNextAPIError, CertiNextRateLimitError
from certinext.session import CertiNextSession

log = structlog.get_logger()


class Outcome:
    """Namespace of the probe outcome strings.

    Using plain string constants (rather than ``enum.StrEnum``, which is 3.11+)
    keeps the values trivially JSON-serialisable and matches the Python 3.10
    floor of the rest of the library.
    """

    PASS = "PASS"
    EMPTY = "EMPTY"
    DENIED = "DENIED"
    NOT_FOUND = "NOT_FOUND"
    SERVER_BUG = "SERVER_BUG"
    RATE_LIMITED = "RATE_LIMITED"
    NETWORK = "NETWORK"
    SKIPPED = "SKIPPED"


# Outcomes that make the process exit non-zero. RATE_LIMITED is transient and
# SKIPPED/EMPTY/PASS are not failures (EMPTY only fails under --strict).
_FAILING = frozenset({Outcome.DENIED, Outcome.NOT_FOUND, Outcome.SERVER_BUG, Outcome.NETWORK})

# Fixed display order for the one-line summary.
_SUMMARY_ORDER = (
    Outcome.PASS,
    Outcome.EMPTY,
    Outcome.DENIED,
    Outcome.NOT_FOUND,
    Outcome.SERVER_BUG,
    Outcome.RATE_LIMITED,
    Outcome.NETWORK,
    Outcome.SKIPPED,
)


def _count(payload: Any) -> int | None:
    """Return ``len(payload)`` for list/tuple payloads, else ``None``.

    Used as the ``count_of`` extractor for probes that return a collection.
    Scalar payloads (single objects, dicts) are not countable and return
    ``None`` so they are never classified ``EMPTY``.

    Args:
        payload: The value returned by a probe call.

    Returns:
        The element count for a list/tuple, otherwise ``None``.
    """
    return len(payload) if isinstance(payload, (list, tuple)) else None


@dataclass
class ProbeResult:
    """The outcome of running a single probe.

    Attributes:
        name: Probe identifier, e.g. ``"domain.get_list"``.
        tier: ``1`` (no input) or ``2`` (derived input).
        endpoint: Human-readable endpoint description, e.g. ``"GET /domains"``.
        outcome: One of the :class:`Outcome` constants.
        http_status: HTTP status code when the failure carried one, else ``None``.
        ems_code: CertiNext ``EMS-xxx`` code from an RFC 7807 body, if present.
        count: Element count for collection results, else ``None``.
        detail: Raw RFC 7807 problem body (dict or text) for ``SERVER_BUG``;
            ``None`` for other outcomes.
        duration_ms: Wall-clock time spent in the probe call, in milliseconds.
        message: Short human-readable note (error string or classification note).
        payload: The raw value the probe returned on success, used to feed the
            Tier-2 context. Excluded from :meth:`to_dict` and from the rendered
            output; not part of equality.
    """

    name: str
    tier: int
    endpoint: str
    outcome: str
    http_status: int | None = None
    ems_code: str | None = None
    count: int | None = None
    detail: Any = None
    duration_ms: float | None = None
    message: str = ""
    payload: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of this result.

        Excludes :attr:`payload` (which may hold live library objects). The
        raw RFC 7807 ``detail`` body is preserved verbatim for ``SERVER_BUG``
        results so callers can diagnose the underlying error.

        Returns:
            A dict with every field except ``payload``.
        """
        return {
            "name": self.name,
            "tier": self.tier,
            "endpoint": self.endpoint,
            "outcome": self.outcome,
            "http_status": self.http_status,
            "ems_code": self.ems_code,
            "count": self.count,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "message": self.message,
        }


@dataclass(frozen=True)
class Probe:
    """A single read-only endpoint check.

    Attributes:
        name: Stable identifier used in the report and history snapshots.
        tier: ``1`` for no-input probes, ``2`` for derived-input probes.
        endpoint: Human-readable endpoint description for the report.
        call: Callable ``(session, ctx) -> payload`` that performs the GET.
        requires: Context keys that must be present (and truthy) before this
            probe runs; when any is missing the probe is reported ``SKIPPED``.
        count_of: Optional extractor returning an element count from the
            payload (drives ``EMPTY`` detection); ``None`` means not countable.
        empty_is_suspect: When ``True``, a 2xx result with ``count == 0`` is
            classified ``EMPTY`` rather than ``PASS`` (a masked-failure guard
            for the unfiltered domain list — see the module's classification
            notes).
    """

    name: str
    tier: int
    endpoint: str
    call: Callable[[CertiNextSession, dict[str, Any]], Any]
    requires: tuple[str, ...] = ()
    count_of: Callable[[Any], int | None] | None = None
    empty_is_suspect: bool = False


# Ordered probe registry. Tier 1 first so Tier 2 can consume the context they
# populate. The registry references ONLY read calls — no create/verify/cancel/
# revoke method appears here, which enforces the read-only guarantee by
# construction.
REGISTRY: tuple[Probe, ...] = (
    # --- Tier 1: no input required ---
    Probe("accounts.me", 1, "GET /auth/me", lambda s, c: s.accounts.me()),
    Probe("accounts.list_groups", 1, "GET /groups",
          lambda s, c: s.accounts.list_groups(), count_of=_count),
    Probe("accounts.list_organizations", 1, "GET /organizations",
          lambda s, c: s.accounts.list_organizations(), count_of=_count),
    Probe("catalog.list_products", 1, "GET /catalog/products",
          lambda s, c: s.catalog.list_products(), count_of=_count),
    Probe("domain.get_list", 1, "GET /domains",
          lambda s, c: s.domain.get_list(), count_of=_count, empty_is_suspect=True),
    Probe("ledger.get_page", 1, "GET /reports/ledger",
          lambda s, c: s.ledger.get_page(page=1), count_of=_count),
    Probe("orders.get_page", 1, "GET /reports/orders",
          lambda s, c: s.orders.get_page(page=1), count_of=_count),
    # --- Tier 2: derived input (SKIPPED when input is unavailable) ---
    Probe("accounts.get_organization", 2, "GET /organizations/{id}",
          lambda s, c: s.accounts.get_organization(c["org_id"]), requires=("org_id",)),
    Probe("catalog.get_custom_fields", 2, "GET /catalog/products/{code}/custom-fields",
          lambda s, c: s.catalog.get_custom_fields(c["product_code"]),
          requires=("product_code",), count_of=_count),
    Probe("domain.get", 2, "GET /domains/{id}",
          lambda s, c: s.domain.get(c["domain_id"]), requires=("domain_id",)),
    Probe("domain.get_dcv", 2, "GET /domains/{id}/dcv",
          lambda s, c: c["domain"].get_dcv(), requires=("domain",)),
    Probe("domain.last_dcv_attempt", 2, "GET /domains/{id}/dcv/attempts/last",
          lambda s, c: c["domain"].last_dcv_attempt(), requires=("domain",)),
    Probe("domain.dcv_attempt_history", 2, "GET /domains/{id}/dcv/attempts",
          lambda s, c: c["domain"].dcv_attempt_history(), requires=("domain",)),
    Probe("ssl.get", 2, "GET /ssl-certificates/{id}",
          lambda s, c: s.ssl.get(c["order_id"]), requires=("order_id",)),
    Probe("ssl.download_certificate", 2, "GET /ssl-certificates/{id}/certificate",
          lambda s, c: c["issued_ssl_order"].download_certificate(),
          requires=("issued_ssl_order",)),
)


def _finish(
    probe: Probe,
    start: float,
    outcome: str,
    *,
    http_status: int | None = None,
    ems_code: str | None = None,
    count: int | None = None,
    detail: Any = None,
    message: str = "",
    payload: Any = None,
) -> ProbeResult:
    """Build a :class:`ProbeResult`, stamping the elapsed time.

    Args:
        probe: The probe that produced this result.
        start: ``time.perf_counter()`` value captured before the call.
        outcome: The classified :class:`Outcome` constant.
        http_status: HTTP status code, when the outcome carried one.
        ems_code: CertiNext EMS code, when present.
        count: Element count for collection payloads.
        detail: Raw RFC 7807 body for ``SERVER_BUG`` outcomes.
        message: Short human-readable note.
        payload: Raw success payload (used for Tier-2 context feeding).

    Returns:
        A populated :class:`ProbeResult`.
    """
    return ProbeResult(
        name=probe.name,
        tier=probe.tier,
        endpoint=probe.endpoint,
        outcome=outcome,
        http_status=http_status,
        ems_code=ems_code,
        count=count,
        detail=detail,
        duration_ms=round((time.perf_counter() - start) * 1000, 1),
        message=message,
        payload=payload,
    )


def classify(probe: Probe, session: CertiNextSession, ctx: dict[str, Any]) -> ProbeResult:
    """Run one probe and classify its outcome.

    This is the single try/except that every probe passes through. Since 1.0,
    :class:`CertiNextAPIError` subclasses plain ``Exception`` (not the
    transport error type), so API and transport failures are disjoint
    hierarchies. One ordering constraint remains: pydantic's
    ``ValidationError`` subclasses ``ValueError``, so it must be caught
    before the ``KeyError``/``ValueError`` parse-note clause.

    Classification:

    - 401/403 → ``DENIED``; 404 → ``NOT_FOUND``; 422 or 5xx → ``SERVER_BUG``
      (raw body captured); any other unexpected non-2xx → ``SERVER_BUG``.
    - 429 → ``RATE_LIMITED`` (not exit-affecting).
    - An ``httpx`` transport error (timeout, connection failure — no usable
      HTTP response) → ``NETWORK``.
    - A pydantic ``ValidationError`` means a 2xx response whose body no
      longer matches our models — shape drift is a vendor signal, not a
      network failure → ``SERVER_BUG``.
    - A token ``RuntimeError`` from :mod:`certinext.auth` carries no status
      code; ``DENIED`` when its message names ``401``/``403``/``invalid_client``,
      otherwise ``NETWORK`` (token endpoint unreachable or returned non-JSON).
    - ``KeyError``/``ValueError`` come from a 2xx response the client couldn't
      fully parse (e.g. an unexpected DCV method), so the endpoint *works* —
      classified ``PASS`` with a note.
    - Otherwise 2xx: ``EMPTY`` when the count is 0 and the probe marks empty as
      suspect, else ``PASS``.

    Args:
        probe: The probe to run.
        session: An authenticated :class:`~certinext.CertiNextSession`.
        ctx: The accumulated run context for Tier-2 input lookup.

    Returns:
        A :class:`ProbeResult` describing the outcome. Never raises for an API,
        network, or auth failure — those are *results*, not crashes.
    """
    missing = [k for k in probe.requires if not ctx.get(k)]
    if missing:
        return ProbeResult(
            name=probe.name, tier=probe.tier, endpoint=probe.endpoint,
            outcome=Outcome.SKIPPED, message=f"missing input: {', '.join(missing)}",
        )

    start = time.perf_counter()
    try:
        payload = probe.call(session, ctx)
    except CertiNextRateLimitError as exc:
        return _finish(probe, start, Outcome.RATE_LIMITED, http_status=exc.status_code,
                       ems_code=exc.ems_code, message=str(exc))
    except CertiNextAPIError as exc:
        status = exc.status_code
        if status in (401, 403):
            outcome = Outcome.DENIED
        elif status == 404:
            outcome = Outcome.NOT_FOUND
        else:
            # 422, 5xx, and any other unexpected non-2xx on a read endpoint.
            outcome = Outcome.SERVER_BUG
        detail = exc.body if outcome == Outcome.SERVER_BUG else None
        return _finish(probe, start, outcome, http_status=status, ems_code=exc.ems_code,
                       detail=detail, message=str(exc))
    except httpx.HTTPError as exc:
        return _finish(probe, start, Outcome.NETWORK, message=f"{type(exc).__name__}: {exc}")
    except ValidationError as exc:
        # A 2xx response whose shape no longer matches our models: the vendor
        # changed the payload, not the network. Must precede ValueError below.
        return _finish(probe, start, Outcome.SERVER_BUG,
                       message=f"response shape drift: {exc}")
    except RuntimeError as exc:
        msg = str(exc)
        denied = any(marker in msg for marker in ("401", "403", "invalid_client"))
        return _finish(probe, start, Outcome.DENIED if denied else Outcome.NETWORK, message=msg)
    except (KeyError, ValueError) as exc:
        # Raised after a 2xx response (the client couldn't fully parse the body).
        # The endpoint responded, so it works; surface the parse note.
        return _finish(probe, start, Outcome.PASS,
                       message=f"2xx response; client-side parse note: {exc}")

    count = probe.count_of(payload) if probe.count_of else None
    outcome = Outcome.EMPTY if (count == 0 and probe.empty_is_suspect) else Outcome.PASS
    return _finish(probe, start, outcome, count=count, payload=payload)


def _feed_context(ctx: dict[str, Any], probe: Probe, payload: Any) -> None:
    """Populate the run context from a successful probe payload.

    Extracts the IDs and objects that Tier-2 probes require, reading only the
    list-response fields that are always present (never a lazy-loading detail
    property — see :class:`~certinext.accounts.Organization`).

    Args:
        ctx: The run context to mutate in place.
        probe: The probe whose payload is being consumed.
        payload: The raw success payload (may be empty/None — ignored then).
    """
    if not payload:
        return
    name = probe.name
    if name == "accounts.list_organizations":
        org_num = payload[0].organization_number
        if org_num:
            ctx["org_id"] = org_num
    elif name == "catalog.list_products":
        for category in payload:
            if category.products and category.products[0].product_code:
                ctx["product_code"] = category.products[0].product_code
                break
    elif name == "domain.get_list":
        ctx["domain"] = payload[0]
        if payload[0].id:
            ctx["domain_id"] = payload[0].id
    elif name == "orders.get_page":
        if payload[0].order_number:
            ctx["order_id"] = payload[0].order_number
    elif name == "ssl.get":
        # Only an issued order can have its certificate downloaded.
        if getattr(payload, "status", None) == "issued":
            ctx["issued_ssl_order"] = payload


def probe_count(*, quick: bool = False) -> int:
    """Return how many probes :func:`run` will execute for a given scope.

    Lets callers size a progress indicator before ``run`` starts.

    Args:
        quick: When ``True``, count Tier-1 probes only.

    Returns:
        The number of probes ``run(quick=quick)`` will report a result for.
    """
    return sum(1 for probe in REGISTRY if not quick or probe.tier == 1)


def run(
    session: CertiNextSession,
    *,
    quick: bool = False,
    on_result: Callable[[ProbeResult], None] | None = None,
) -> list[ProbeResult]:
    """Run the probe registry and return one result per probe.

    Tier-1 probes run first and feed the context that Tier-2 probes consume;
    Tier-2 probes whose input is unavailable are reported ``SKIPPED``.

    Args:
        session: An authenticated :class:`~certinext.CertiNextSession`.
        quick: When ``True``, run Tier-1 probes only.
        on_result: Optional callback invoked with each :class:`ProbeResult`
            as it completes, e.g. to drive a progress bar.

    Returns:
        A list of :class:`ProbeResult`, in registry order.
    """
    results: list[ProbeResult] = []
    ctx: dict[str, Any] = {}
    for probe in REGISTRY:
        if quick and probe.tier != 1:
            continue
        result = classify(probe, session, ctx)
        if result.outcome in (Outcome.PASS, Outcome.EMPTY):
            _feed_context(ctx, probe, result.payload)
        results.append(result)
        log.debug("probe complete", probe=probe.name, outcome=result.outcome,
                  http=result.http_status, ms=result.duration_ms)
        if on_result is not None:
            on_result(result)
    return results


def exit_code(results: list[ProbeResult], *, strict: bool = False) -> int:
    """Return the process exit code for a set of results.

    Args:
        results: The probe results from :func:`run`.
        strict: When ``True``, also fail on ``EMPTY`` outcomes.

    Returns:
        ``1`` if any result has an exit-affecting outcome, else ``0``.
    """
    failing = set(_FAILING)
    if strict:
        failing.add(Outcome.EMPTY)
    return 1 if any(r.outcome in failing for r in results) else 0


def _short(text: str, limit: int = 70) -> str:
    """Truncate ``text`` to ``limit`` characters with an ellipsis.

    Args:
        text: The string to shorten.
        limit: Maximum length before truncation.

    Returns:
        The original text, or a truncated form ending in ``...``.
    """
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_summary(results: list[ProbeResult]) -> str:
    """Return the one-line outcome tally, e.g. ``"PASS 6 | SERVER_BUG 1 | SKIPPED 3"``.

    Args:
        results: The probe results from :func:`run`.

    Returns:
        A summary string listing only the non-zero outcome counts, in a fixed
        order.
    """
    counts = Counter(r.outcome for r in results)
    return " | ".join(f"{outcome} {counts[outcome]}" for outcome in _SUMMARY_ORDER if counts[outcome])


# Outcome -> rich style for the results table. Failing outcomes red, degraded
# ones yellow, PASS green, SKIPPED dim — scannable at a glance on a TTY;
# styles drop out automatically when output is piped.
_OUTCOME_STYLES = {
    Outcome.PASS: "green",
    Outcome.EMPTY: "yellow",
    Outcome.DENIED: "red",
    Outcome.NOT_FOUND: "red",
    Outcome.SERVER_BUG: "red",
    Outcome.RATE_LIMITED: "yellow",
    Outcome.NETWORK: "red",
    Outcome.SKIPPED: "dim",
}


def results_table(results: list[ProbeResult]) -> Table:
    """Build the human-readable results table as a rich :class:`~rich.table.Table`.

    Args:
        results: The probe results from :func:`run`.

    Returns:
        A rich table with one row per probe, outcome-colored on TTYs.
    """
    table = Table(box=None, pad_edge=False)
    table.add_column("probe")
    table.add_column("tier", justify="right")
    table.add_column("outcome")
    table.add_column("http", justify="right")
    table.add_column("count", justify="right")
    table.add_column("detail")
    for r in results:
        table.add_row(
            r.name,
            str(r.tier),
            r.outcome,
            "" if r.http_status is None else str(r.http_status),
            "" if r.count is None else str(r.count),
            _short(r.message),
            style=_OUTCOME_STYLES.get(r.outcome),
        )
    return table


def render_table(results: list[ProbeResult]) -> str:
    """Return the human-readable results table rendered to plain text.

    Args:
        results: The probe results from :func:`run`.

    Returns:
        The :func:`results_table` output rendered without styling, suitable
        for logs or string assertions.
    """
    console = Console(width=200, no_color=True, force_terminal=False)
    with console.capture() as capture:
        console.print(results_table(results))
    return capture.get().rstrip("\n")
