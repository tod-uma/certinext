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

"""``certinext replacement-report`` — valid certificates that need replacing.

Thin CLI over :mod:`certinext.replacement`: resolves the criteria (built-in
defaults, then ``[replacement]`` in ``config.toml``, then flags), builds the
report, and renders it as a table, JSON, or CSV. Data goes to stdout, or to
the ``--output`` file; progress and logs go to stderr.
"""

import contextlib
import csv
import datetime as dt
import json
import sys
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional, TextIO

import structlog
import typer
from pydantic import ValidationError
from rich.progress import Progress

from certinext import replacement as rp
from certinext._config import ConfigError, cache_dir, replacement_criteria
from certinext._inspection_cache import DEFAULT_MAX_AGE, InspectionCache
from certinext.cli._app import app
from certinext.cli._shared import data_console, err_console, progress_disabled, rows_table, session
from certinext.cli_support import prompt_stderr

log = structlog.get_logger()

# SANs shown in the table before collapsing the rest into "+N".
_TABLE_SANS = 3

# Parallel --inspect downloads. Sequential took ~55 minutes for ~574
# certificates in prod (2026-10-21); the cap keeps a typo from flooding a
# vendor API whose rate limits are undocumented.
_DEFAULT_WORKERS = 4
_MAX_WORKERS = 16

# Subdirectory of the per-user cache dir; --cache-dir replaces both.
_CACHE_SUBDIR = "replacement-inspect"
_MAX_AGE_DAYS = DEFAULT_MAX_AGE.days

# ADR 0019's original bound. Past it, a re-rooted chain may be served from a
# stale entry, which matters only when the chain signal is on (ADR 0021).
_CHAIN_SAFE_DAYS = 7


class _GroupBy(str, Enum):
    """``--group-by`` choices (mirrors :data:`certinext.replacement.GroupBy`)."""

    originator = "originator"
    group = "group"
    issuer = "issuer"
    ca = "ca"


class _SignalName(str, Enum):
    """``--disable-signal`` choices (mirrors :data:`certinext.replacement.Signal`)."""

    ca = "ca"
    issuer = "issuer"
    key = "key"
    chain = "chain"


def _criteria(
    cas: list[str] | None,
    issuers: list[str] | None,
    key_types: list[str] | None,
    chain_cas: list[str] | None,
    disable: list[_SignalName] | None,
) -> rp.ReplacementCriteria:
    """Resolve criteria from config plus per-run flags.

    Args:
        cas: ``--ca`` values, or None to keep config/defaults.
        issuers: ``--issuer`` values, or None to keep config/defaults.
        key_types: ``--key-type`` values, or None.
        chain_cas: ``--chain-ca`` values, or None.
        disable: ``--disable-signal`` values.

    Returns:
        The effective criteria.

    Raises:
        SystemExit: Exit 2 on a bad config file.
        typer.BadParameter: On an invalid flag value, or when no signal is
            left enabled.
    """
    try:
        base = replacement_criteria()
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    try:
        criteria = base.with_overrides(
            cas=cas, issuers=issuers, key_types=key_types, chain_cas=chain_cas,
            disable=[d.value for d in disable or []],
        )
    except ValidationError as exc:
        raise typer.BadParameter("; ".join(e["msg"] for e in exc.errors())) from exc
    if not criteria.active_signals():
        raise typer.BadParameter("every replacement signal is disabled or empty")
    return criteria


def _resolve_cache(
    inspect: bool, cache: bool | None, refresh: bool, directory: Path | None,
    max_age_days: int | None = None,
) -> bool:
    """Decide whether this run uses the inspection cache.

    ``--refresh-cache``, ``--cache-dir`` and ``--cache-max-age`` imply
    ``--cache``. With none of the cache flags, ask on a terminal (Enter
    means no: reusing weeks-old downloads should be a choice) and stay off
    otherwise, so scheduled runs keep reading live.

    Args:
        inspect: Whether ``--inspect`` was given.
        cache: ``--cache`` (True), ``--no-cache`` (False), or neither (None).
        refresh: Whether ``--refresh-cache`` was given.
        directory: The ``--cache-dir`` value, if any.
        max_age_days: The ``--cache-max-age`` value, if any.

    Returns:
        Whether to use the cache.

    Raises:
        typer.BadParameter: On a cache flag without ``--inspect``, or
            ``--no-cache`` with a flag that implies ``--cache``.
    """
    implied = refresh or directory is not None or max_age_days is not None
    if cache is False:
        if implied:
            raise typer.BadParameter(
                "--no-cache cannot be combined with --refresh-cache, --cache-dir or --cache-max-age",
                param_hint="--no-cache",
            )
        return False
    if not inspect:
        if cache or implied:
            raise typer.BadParameter(
                "the cache holds certificate downloads, so it needs --inspect",
                param_hint="--cache",
            )
        return False
    if cache or implied:
        return True
    if not sys.stdin.isatty():
        log.info("Inspection cache off (non-interactive); pass --cache to use it")
        return False
    try:
        answer = prompt_stderr(
            f"Use cached inspections up to {_MAX_AGE_DAYS} days old (faster, may be stale)? [y/N]: "
        )
    except EOFError:
        print(file=sys.stderr)
        return False
    return answer.strip().lower() in ("y", "yes")


def _build_cache(sess: Any, refresh: bool, directory: Path | None, max_age_days: int) -> InspectionCache:
    """Create the inspection cache for this run.

    Production and sandbox entries live in separate subdirectories, so one
    can never answer for the other.

    Args:
        sess: The session (for :attr:`CertiNextSession.sandbox`).
        refresh: Whether ``--refresh-cache`` was given.
        directory: The ``--cache-dir`` value, or None for the default.
        max_age_days: How old an entry may be and still be used; older
            entries are also pruned.

    Returns:
        The cache.
    """
    base = directory if directory is not None else cache_dir() / _CACHE_SUBDIR
    env = "sandbox" if getattr(sess, "sandbox", False) else "production"
    return InspectionCache(
        base.expanduser() / env, refresh=refresh, max_age=dt.timedelta(days=max_age_days)
    )


def _warn_stale_chain(criteria: rp.ReplacementCriteria, max_age_days: int) -> None:
    """Warn on stderr when cached chains may be too old for the chain signal.

    A cache entry is keyed by order and serial, so only the served chain can
    change under it. That matters only when the chain signal is on.

    Args:
        criteria: The effective criteria.
        max_age_days: The effective cache max age.
    """
    if "chain" in criteria.active_signals() and max_age_days > _CHAIN_SAFE_DAYS:
        print(
            f"Warning: the chain signal is on and cached downloads up to {max_age_days} days old "
            "are trusted, so a chain CertiNext re-rooted since then may show its old CAs. "
            "Use --refresh-cache for a live answer.",
            file=sys.stderr,
        )


def _sans_cell(sans: list[str] | None) -> str:
    """Render SANs compactly for the table.

    Args:
        sans: The leaf's DNS SANs, or None when not inspected.

    Returns:
        Up to three names, then ``+N`` for the rest.
    """
    if not sans:
        return ""
    shown = ", ".join(sans[:_TABLE_SANS])
    return f"{shown}, +{len(sans) - _TABLE_SANS}" if len(sans) > _TABLE_SANS else shown


def _table_row(row: rp.ReportRow, report: rp.ReplacementReport, show_errors: bool) -> dict[str, Any]:
    """Build one table row; inspection-only columns appear only when inspected.

    Args:
        row: The report row.
        report: The report (for "now" and whether it was inspected).
        show_errors: Whether to include an ``error`` column.

    Returns:
        An ordered column -> value dict.
    """
    f, i = row.facts, row.facts.inspection
    out: dict[str, Any] = {"verdict": row.verdict.value, "ca": f.ca or "", "common_name": f.common_name}
    if report.inspected:
        out["sans"] = _sans_cell(i.sans if i else None)
        out["key"] = i.key_label if i else ""
    out.update({
        "issuer": f.issuer,
        "valid_to": f.valid_to.date().isoformat(),
        "days": row.days_left(report.started_at),
        "order": f.order_number,
        "origin": f.originator,
        "group": f.group_name or f.group_number,
        "superseded": "yes" if row.superseded else "maybe" if row.possibly_superseded else "",
        "replaced_by": row.replaced_by
        or (f"maybe:{row.possibly_replaced_by}" if row.possibly_replaced_by else ""),
    })
    if report.inspected:
        out["ordered_by"] = f.ordered_by_name
    if show_errors:
        out["error"] = f.error
    return out


def _summary_line(summary: dict[str, int], report: rp.ReplacementReport) -> str:
    """Render the one-line summary.

    Args:
        summary: Output of :meth:`ReplacementReport.summarize`, plus an
            ``incomplete`` count.
        report: The report (for criteria and inspection state).

    Returns:
        Migration progress first, e.g. ``"443 EMSIGN certificates
        outstanding (31 possibly replaced; confirm with --inspect); 51
        replaced; 494 of 552 valid certificates need replacing"``. Possible
        (CN-only) replacements stay in the outstanding count, so it never
        understates the work. The CA names appear only
        when the ``ca`` signal is the only one active. Conflicts are shown
        when more than one signal is active (or any occurred), then unknowns,
        errors, a note on signals that were not evaluated and, when the cache
        was used, how many inspections came from it.
    """
    criteria = report.criteria
    signals = criteria.active_signals()
    label = f"{'/'.join(criteria.cas)} " if signals == ["ca"] else ""
    outstanding_part = f"{summary['outstanding']} {label}certificates outstanding"
    if summary["possibly_replaced"]:
        how = "SANs unknown" if report.inspected else "confirm with --inspect"
        outstanding_part += f" ({summary['possibly_replaced']} possibly replaced; {how})"
    parts = [outstanding_part, f"{summary['replaced']} replaced"]
    # The rest of needs_replacing: renewed by a newer cert that itself still needs replacing.
    renewed = summary["needs_replacing"] - summary["outstanding"] - summary["replaced"]
    if renewed:
        parts.append(f"{renewed} superseded by newer certificates that also need replacing")
    parts.append(f"{summary['needs_replacing']} of {summary['valid']} valid certificates need replacing")
    if len(signals) > 1 or summary["conflict"]:
        parts.append(f"{summary['conflict']} conflicts to review")
    if summary["unknown"]:
        parts.append(f"{summary['unknown']} unknown")
    if summary["errors"]:
        parts.append(f"{summary['errors']} inspection errors")
    if summary["incomplete"]:
        parts.append(f"{summary['incomplete']} issued orders could not be classified")
    if report.cache:
        c = report.cache
        parts.append(
            f"{c.hits} of {c.hits + c.misses} inspections from cache "
            f"(up to {c.max_age.days} days old{'; refreshed' if c.refreshed else ''})"
        )
    line = "; ".join(parts)
    # ca and issuer come from the orders report and catalog; only key/chain need --inspect.
    skipped = [s for s in signals if s not in ("ca", "issuer")]
    if not report.inspected and skipped:
        line += f" ({'/'.join(skipped)} not inspected; use --inspect)"
    return line


def _csv_value(value: Any) -> Any:
    """Flatten a JSON value for a CSV cell.

    Args:
        value: A value from :meth:`ReportRow.to_dict`.

    Returns:
        Lists joined with ``;``, ``None`` as empty, other values unchanged.
    """
    if isinstance(value, list):
        return ";".join(str(v) for v in value)
    return "" if value is None else value


def _check_output(path: Path | None) -> None:
    """Reject an ``--output`` path that cannot work, before the slow part.

    Args:
        path: The ``--output`` value, or None for stdout.

    Raises:
        typer.BadParameter: If the path is a directory or its parent
            directory does not exist.
    """
    if path is None:
        return
    if path.is_dir():
        raise typer.BadParameter(f"{path} is a directory", param_hint="--output")
    if not path.resolve().parent.is_dir():
        raise typer.BadParameter(f"directory {path.resolve().parent} does not exist", param_hint="--output")


def _open_output(path: Path | None) -> TextIO | None:
    """Open the ``--output`` file, falling back to stdout if that fails.

    The report may have taken an hour to build, so a file that cannot be
    opened (locked by Excel, permissions) is logged rather than fatal; the
    caller writes to stdout instead and exits 1.

    Args:
        path: The ``--output`` value, or None for stdout.

    Returns:
        The open file (UTF-8, LF line endings), or None to use stdout.
    """
    if path is None:
        return None
    try:
        return open(path, "w", encoding="utf-8", newline="")
    except OSError as exc:
        log.error("Cannot write output file; writing the report to stdout instead", path=str(path), error=str(exc))
        return None


@app.command()
def replacement_report(
    ctx: typer.Context,
    inspect: bool = typer.Option(
        False, "--inspect",
        help=(
            "Download and parse every certificate: reads SANs (so replacements are "
            "confirmed rather than 'maybe'), evaluates the key and chain signals, and "
            "adds key size and who ordered it. Two requests per certificate."
        ),
    ),
    workers: int = typer.Option(
        _DEFAULT_WORKERS, "--workers", metavar="N", min=1, max=_MAX_WORKERS,
        help="Certificates to download at once with --inspect; a rate limit pauses them all",
    ),
    use_cache: Optional[bool] = typer.Option(
        None, "--cache/--no-cache",
        help=(
            f"With --inspect, reuse certificate downloads up to {_MAX_AGE_DAYS} days old (see "
            "--cache-max-age) and save new ones; order status is always read live. With neither "
            "flag, asks on a terminal and stays off otherwise"
        ),
    ),
    cache_max_age: Optional[int] = typer.Option(
        None, "--cache-max-age", metavar="DAYS", min=1,
        help=(
            f"Trust cached downloads up to DAYS days old (default {_MAX_AGE_DAYS}; implies --cache). "
            "Older entries are deleted, so a short value discards entries a later run could reuse"
        ),
    ),
    refresh_cache: bool = typer.Option(
        False, "--refresh-cache",
        help="Re-download every certificate and rewrite the cache (implies --cache)",
    ),
    cache_directory: Optional[Path] = typer.Option(
        None, "--cache-dir", metavar="DIR",
        help="Keep the cache in DIR instead of the per-user cache directory (implies --cache)",
    ),
    include_ok: bool = typer.Option(
        False, "--all",
        help="Also list certificates that do not need replacing (to measure progress)",
    ),
    latest_only: bool = typer.Option(
        False, "--latest-only",
        help=(
            "Hide certificates superseded by a newer valid certificate covering all their SANs. "
            "SANs need --inspect; CN-only matches are kept and marked 'maybe'"
        ),
    ),
    outstanding: bool = typer.Option(
        False, "--outstanding",
        help=(
            "Only certificates still to replace: no confirmed replacement by a newer passing "
            "certificate and not renewed by a newer one that still needs replacing. CN-only "
            "matches stay listed (replaced_by 'maybe:<order>'). --all has no effect"
        ),
    ),
    issued_since: Optional[dt.datetime] = typer.Option(
        None, "--issued-since", metavar="DATE", formats=["%Y-%m-%d"],
        help="Only orders placed on or after DATE (YYYY-MM-DD, UTC)",
    ),
    originator: Optional[list[str]] = typer.Option(
        None, "--originator", metavar="NAME",
        help="Only orders from this originator (ACME, CERTInext, 'CERTInext API'); repeatable",
    ),
    group: Optional[list[str]] = typer.Option(
        None, "--group", metavar="GROUP",
        help="Only orders in this account group, by number or name; repeatable",
    ),
    expiring_within: Optional[int] = typer.Option(
        None, "--expiring-within", metavar="DAYS", min=1,
        help="Only certificates expiring within DAYS days",
    ),
    group_by: Optional[_GroupBy] = typer.Option(
        None, "--group-by",
        help="Also print counts per originator, group, issuer, or CA",
    ),
    ca: Optional[list[str]] = typer.Option(
        None, "--ca", metavar="CA",
        help="Issuing CA (EMSIGN, SSLCOM) that needs replacing; repeatable, replaces config",
    ),
    issuer: Optional[list[str]] = typer.Option(
        None, "--issuer", metavar="CN",
        help="Issuing-CA common name that needs replacing; repeatable, replaces config",
    ),
    key_type: Optional[list[str]] = typer.Option(
        None, "--key-type", metavar="TYPE",
        help="Key type that needs replacing (EC, RSA, Ed25519, Ed448, DSA); repeatable, replaces config",
    ),
    chain_ca: Optional[list[str]] = typer.Option(
        None, "--chain-ca", metavar="CN",
        help="Distrusted CA common name in the served chain; repeatable, replaces config",
    ),
    disable_signal: Optional[list[_SignalName]] = typer.Option(
        None, "--disable-signal",
        help="Turn a signal off for this run; repeatable",
    ),
    output_csv: bool = typer.Option(
        False, "--csv", help="Write CSV instead of a table (use --json for JSON)",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", metavar="FILE",
        help="Write the table, JSON, or CSV to FILE (UTF-8) instead of stdout",
    ),
) -> None:
    """List currently valid certificates that need replacing after a CA distrust.

    By default every valid emSign certificate needs replacing: the issuing CA
    comes from each order's product code (instant, no download). Criteria
    come from that default, the "replacement" table in config.toml, and the
    flags above. A certificate covered by a newer one that passes the
    criteria (an SSL.com replacement) is shown as replaced; --outstanding
    lists only the work left. Output is a table, or JSON with --json, or CSV
    with --csv. Read-only. --inspect can reuse a per-user cache of earlier
    downloads (--cache); the summary says how many inspections came from it.
    Exits 1 if any certificate could not be inspected or any issued order
    could not be classified.
    """
    if output_csv and ctx.obj.output_json:
        raise typer.BadParameter("--csv and --json are mutually exclusive")
    _check_output(output)
    if cache_directory is not None and cache_directory.expanduser().is_file():
        raise typer.BadParameter(f"{cache_directory} is a file", param_hint="--cache-dir")
    criteria = _criteria(ca, issuer, key_type, chain_ca, disable_signal)
    # Before session(): a credential prompt must not interleave with this one.
    caching = _resolve_cache(inspect, use_cache, refresh_cache, cache_directory, cache_max_age)
    max_age_days = cache_max_age if cache_max_age is not None else _MAX_AGE_DAYS
    if caching:
        _warn_stale_chain(criteria, max_age_days)
    sess = session(ctx)
    cache = _build_cache(sess, refresh_cache, cache_directory, max_age_days) if caching else None

    log.info(
        "Building replacement report", inspect=inspect,
        signals=",".join(criteria.active_signals()),
        workers=workers if inspect else None,
        cache=str(cache.directory) if cache else None,
        issued_since=issued_since.date().isoformat() if issued_since else None,
    )
    try:
        with Progress(console=err_console, disable=progress_disabled(ctx.obj.verbose)) as progress:
            task = progress.add_task("Inspecting certificates", total=None, visible=inspect)
            report = rp.build_report(
                sess, criteria, inspect=inspect, originators=originator, groups=group,
                issued_since=issued_since,
                on_total=lambda n: progress.update(task, total=n),
                on_progress=lambda _f: progress.advance(task), workers=workers, cache=cache,
            )
    except ImportError as exc:
        log.error("Cannot inspect certificates", error=str(exc))
        raise SystemExit(1) from exc

    population = report.population(
        latest_only=latest_only, expiring_within=expiring_within, outstanding=outstanding
    )
    rows = report.select(
        include_ok=include_ok, latest_only=latest_only, expiring_within=expiring_within,
        outstanding=outstanding,
    )
    summary = report.summarize(population)
    summary["incomplete"] = len(report.incomplete)
    breakdown = report.breakdown(population, group_by.value) if group_by else None

    if (latest_only or outstanding) and summary["possibly_superseded"]:
        print(
            f"Warning: {summary['possibly_superseded']} certificates share a common name with a "
            "newer certificate, but their SANs are unknown, so --latest-only kept them "
            "(marked 'maybe'). Use --inspect to check SAN coverage.",
            file=sys.stderr,
        )

    fh = _open_output(output)
    with fh or contextlib.nullcontext(sys.stdout) as out:
        if ctx.obj.output_json:
            ended = (report.ended_at or report.started_at).isoformat()
            doc: dict[str, Any] = {
                # generated_at predates started_at/ended_at; kept as the end time.
                "generated_at": ended,
                "started_at": report.started_at.isoformat(),
                "ended_at": ended,
                "inspected": report.inspected,
                "criteria": criteria.model_dump(),
                "cache": report.cache.to_dict() if report.cache else {"enabled": False},
                "summary": summary,
                "certificates": [r.to_dict(report.started_at) for r in rows],
                "incomplete": [asdict(i) for i in report.incomplete],
            }
            if breakdown is not None:
                doc["breakdown"] = breakdown
            print(json.dumps(doc, indent=2), file=out)
        elif output_csv:
            dicts = [r.to_dict(report.started_at) for r in rows]
            if dicts:
                writer = csv.DictWriter(out, fieldnames=list(dicts[0]), lineterminator="\n")
                writer.writeheader()
                writer.writerows({k: _csv_value(v) for k, v in d.items()} for d in dicts)
            if breakdown:
                err_console.print(rows_table(breakdown))
        else:
            console = data_console(fh)
            if rows:
                show_errors = any(r.facts.error for r in rows)
                console.print(rows_table([_table_row(r, report, show_errors) for r in rows]))
                print(file=out)
            else:
                print("(no certificates match)\n", file=out)
            if breakdown:
                console.print(rows_table(breakdown))
                print(file=out)
            print(_summary_line(summary, report), file=out)

    # The summary always reaches the terminal: CSV has no room for it, and
    # with --output the data went to a file.
    if output_csv or fh:
        print(_summary_line(summary, report), file=sys.stderr)
    if fh:
        log.info("Report written", path=str(output))

    if (output and not fh) or summary["errors"] or summary["incomplete"]:
        raise SystemExit(1)
