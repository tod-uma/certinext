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
report, and renders it as a table, JSON, or CSV. Data goes to stdout;
progress and logs go to stderr.
"""

import csv
import json
import sys
from enum import Enum
from typing import Any, Optional

import structlog
import typer
from pydantic import ValidationError
from rich.progress import Progress

from certinext import replacement as rp
from certinext._config import ConfigError, replacement_criteria
from certinext.cli._app import app
from certinext.cli._shared import data_console, err_console, progress_disabled, rows_table, session

log = structlog.get_logger()

# SANs shown in the table before collapsing the rest into "+N".
_TABLE_SANS = 3


class _GroupBy(str, Enum):
    """``--group-by`` choices (mirrors :data:`certinext.replacement.GroupBy`)."""

    originator = "originator"
    group = "group"
    issuer = "issuer"


class _SignalName(str, Enum):
    """``--disable-signal`` choices (mirrors :data:`certinext.replacement.Signal`)."""

    issuer = "issuer"
    key = "key"
    chain = "chain"


def _criteria(
    issuers: list[str] | None,
    key_types: list[str] | None,
    chain_cas: list[str] | None,
    disable: list[_SignalName] | None,
) -> rp.ReplacementCriteria:
    """Resolve criteria from config plus per-run flags.

    Args:
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
            issuers=issuers, key_types=key_types, chain_cas=chain_cas,
            disable=[d.value for d in disable or []],
        )
    except ValidationError as exc:
        raise typer.BadParameter("; ".join(e["msg"] for e in exc.errors())) from exc
    if not criteria.active_signals():
        raise typer.BadParameter("every replacement signal is disabled or empty")
    return criteria


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
    out: dict[str, Any] = {"verdict": row.verdict.value, "common_name": f.common_name}
    if report.inspected:
        out["sans"] = _sans_cell(i.sans if i else None)
        out["key"] = i.key_label if i else ""
    out.update({
        "issuer": f.issuer,
        "valid_to": f.valid_to.date().isoformat(),
        "days": row.days_left(report.generated_at),
        "order": f.order_number,
        "origin": f.originator,
        "group": f.group_name or f.group_number,
        "superseded": "yes" if row.superseded else "",
    })
    if report.inspected:
        out["ordered_by"] = f.ordered_by_name
    if show_errors:
        out["error"] = f.error
    return out


def _summary_line(summary: dict[str, int], report: rp.ReplacementReport) -> str:
    """Render the one-line summary.

    Args:
        summary: Output of :meth:`ReplacementReport.summarize`.
        report: The report (for criteria and inspection state).

    Returns:
        e.g. ``"297 of 573 valid certificates need replacing (0 conflicts)"``,
        plus a note on signals that were not evaluated.
    """
    line = (
        f"{summary['needs_replacing']} of {summary['valid']} valid certificates need "
        f"replacing ({summary['conflict']} conflicts"
    )
    if summary["unknown"]:
        line += f", {summary['unknown']} unknown"
    if summary["errors"]:
        line += f", {summary['errors']} inspection errors"
    line += ")"
    skipped = [s for s in report.criteria.active_signals() if s != "issuer"]
    if not report.inspected and skipped:
        line += f"; {'/'.join(skipped)} not inspected (use --inspect)"
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


@app.command()
def replacement_report(
    ctx: typer.Context,
    inspect: bool = typer.Option(
        False, "--inspect",
        help=(
            "Download and parse every certificate: evaluates the key and chain "
            "signals (so disagreements are detected), and adds SANs, key size, "
            "and who ordered it. Two requests per certificate."
        ),
    ),
    include_ok: bool = typer.Option(
        False, "--all",
        help="Also list certificates that do not need replacing (to measure progress)",
    ),
    latest_only: bool = typer.Option(
        False, "--latest-only",
        help="Hide certificates superseded by a newer valid certificate for the same names",
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
        help="Also print counts per originator, group, or issuer",
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
        False, "--csv", help="Write CSV to stdout instead of a table",
    ),
) -> None:
    """List currently valid certificates that need replacing after a CA distrust.

    By default classifies on the issuing CA alone (instant, from the orders
    report). Criteria come from built-in defaults (the October 2026 eMudhra
    ECC distrust), the "replacement" table in config.toml, and the flags
    above. Read-only. Exits 1 if any certificate could not be inspected.
    """
    if output_csv and ctx.obj.output_json:
        raise typer.BadParameter("--csv and --json are mutually exclusive")
    criteria = _criteria(issuer, key_type, chain_ca, disable_signal)
    sess = session(ctx)

    log.info(
        "Building replacement report", inspect=inspect,
        signals=",".join(criteria.active_signals()),
    )
    try:
        with Progress(console=err_console, disable=progress_disabled(ctx.obj.verbose)) as progress:
            task = progress.add_task("Inspecting certificates", total=None, visible=inspect)
            report = rp.build_report(
                sess, criteria, inspect=inspect, originators=originator, groups=group,
                on_total=lambda n: progress.update(task, total=n),
                on_progress=lambda _f: progress.advance(task),
            )
    except ImportError as exc:
        log.error("Cannot inspect certificates", error=str(exc))
        raise SystemExit(1) from exc

    population = report.population(latest_only=latest_only, expiring_within=expiring_within)
    rows = report.select(include_ok=include_ok, latest_only=latest_only, expiring_within=expiring_within)
    summary = report.summarize(population)
    breakdown = report.breakdown(population, group_by.value) if group_by else None

    if ctx.obj.output_json:
        doc: dict[str, Any] = {
            "generated_at": report.generated_at.isoformat(),
            "inspected": report.inspected,
            "criteria": criteria.model_dump(),
            "summary": summary,
            "certificates": [r.to_dict(report.generated_at) for r in rows],
        }
        if breakdown is not None:
            doc["breakdown"] = breakdown
        print(json.dumps(doc, indent=2))
    elif output_csv:
        dicts = [r.to_dict(report.generated_at) for r in rows]
        if dicts:
            writer = csv.DictWriter(sys.stdout, fieldnames=list(dicts[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows({k: _csv_value(v) for k, v in d.items()} for d in dicts)
        if breakdown:
            err_console.print(rows_table(breakdown))
        print(_summary_line(summary, report), file=sys.stderr)
    else:
        if rows:
            show_errors = any(r.facts.error for r in rows)
            data_console().print(rows_table([_table_row(r, report, show_errors) for r in rows]))
            print()
        else:
            print("(no certificates match)\n")
        if breakdown:
            data_console().print(rows_table(breakdown))
            print()
        print(_summary_line(summary, report))

    if summary["errors"]:
        raise SystemExit(1)
