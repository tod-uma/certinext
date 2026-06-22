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

"""Read-only health & coverage probe for the CertiNext API.

``certinext-healthcheck`` exercises (nearly) every CertiNext **read** endpoint
the library exposes, classifies each result, and prints a scannable report of
what works and what doesn't for the credentials it was given. It is provably
safe to run against production: it only ever issues GETs and never mutates.

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

Usage::

    certinext-healthcheck
    certinext-healthcheck --sandbox -v
    certinext-healthcheck --quick
    certinext-healthcheck --strict
    certinext-healthcheck --json | python -m json.tool
"""

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import requests
import structlog
from tabulate import tabulate

from certinext._cli import (
    _setup_logging,
    add_connection_args,
    add_json_output_arg,
    apply_sandbox,
    build_session,
)
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

    This is the single try/except that every probe passes through. Catch order
    matters: :class:`CertiNextRateLimitError` and :class:`CertiNextAPIError`
    must be caught before :class:`requests.RequestException` (the former are
    subclasses of ``requests.HTTPError``), or API errors would be swallowed as
    network failures.

    Classification:

    - 401/403 → ``DENIED``; 404 → ``NOT_FOUND``; 422 or 5xx → ``SERVER_BUG``
      (raw body captured); any other unexpected non-2xx → ``SERVER_BUG``.
    - 429 → ``RATE_LIMITED`` (not exit-affecting).
    - A ``requests`` connection/timeout error (no HTTP response) → ``NETWORK``.
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
    except requests.RequestException as exc:
        return _finish(probe, start, Outcome.NETWORK, message=f"{type(exc).__name__}: {exc}")
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


def run(session: CertiNextSession, *, quick: bool = False) -> list[ProbeResult]:
    """Run the probe registry and return one result per probe.

    Tier-1 probes run first and feed the context that Tier-2 probes consume;
    Tier-2 probes whose input is unavailable are reported ``SKIPPED``.

    Args:
        session: An authenticated :class:`~certinext.CertiNextSession`.
        quick: When ``True``, run Tier-1 probes only.

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
        The original text, or a truncated form ending in ``…``.
    """
    text = text.replace("\n", " ").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_summary(results: list[ProbeResult]) -> str:
    """Return the one-line outcome tally, e.g. ``"PASS 6 · SERVER_BUG 1 · SKIPPED 3"``.

    Args:
        results: The probe results from :func:`run`.

    Returns:
        A summary string listing only the non-zero outcome counts, in a fixed
        order.
    """
    counts = Counter(r.outcome for r in results)
    return " · ".join(f"{outcome} {counts[outcome]}" for outcome in _SUMMARY_ORDER if counts[outcome])


def render_table(results: list[ProbeResult]) -> str:
    """Return the human-readable results table.

    Args:
        results: The probe results from :func:`run`.

    Returns:
        A ``tabulate``-formatted table string.
    """
    rows = [
        {
            "probe": r.name,
            "tier": r.tier,
            "outcome": r.outcome,
            "http": r.http_status if r.http_status is not None else "",
            "count": r.count if r.count is not None else "",
            "detail": _short(r.message),
        }
        for r in results
    ]
    return tabulate(rows, headers="keys", tablefmt="simple")


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-healthcheck.

    Returns:
        A configured :class:`argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Probe every read-only CertiNext endpoint the library exposes and report "
            "what works for the given credentials. Read-only and safe against production."
        ),
    )
    parser.add_argument(
        "--quick", action="store_true", default=False,
        help="Run Tier-1 probes only (skip derived-input Tier-2 probes)",
    )
    parser.add_argument(
        "--strict", action="store_true", default=False,
        help="Also exit non-zero when a baseline list is unexpectedly empty (EMPTY)",
    )
    add_json_output_arg(parser)
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help=(
            "Increase verbosity: -v shows progress, "
            "-vvv enables debug logging (per-probe results), "
            "-vvvv also enables third-party debug logging (urllib3)"
        ),
    )
    conn = parser.add_argument_group("connection")
    add_connection_args(conn)
    return parser


def main() -> None:
    """Entry point for certinext-healthcheck."""
    try:
        parser = build_parser()
        args = parser.parse_args()
        _setup_logging(args.verbose)
        apply_sandbox(args)
        sess = build_session(args)

        log.info("Running CertiNext health check", scope="tier-1" if args.quick else "all")
        results = run(sess, quick=args.quick)

        if args.output_json:
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            print(render_table(results))
            print()
            print(render_summary(results))

        raise SystemExit(exit_code(results, strict=args.strict))
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
