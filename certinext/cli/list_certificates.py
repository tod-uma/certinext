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

"""``certinext list-certificates`` — list SSL/TLS certificate orders."""

import csv
import json
import sys
from pathlib import Path
from typing import Optional

import structlog
import typer

from certinext._inspection_cache import DEFAULT_MAX_AGE
from certinext.certificate_lookup import CertificateEntry, enrich_sans
from certinext.cli._app import app
from certinext.cli._certificate_cache import _build_cache, _resolve_cache
from certinext.cli._shared import data_console, rows_table, session
from certinext.exceptions import CertiNextAPIError
from certinext.session import CertiNextSession

log = structlog.get_logger()


def _ca_map(sess: CertiNextSession) -> dict[str, str]:
    """Return product code → CA from one catalog read, or ``{}`` if it fails.

    The CA column is a convenience; a catalog outage must not hide the
    certificate list itself.

    Args:
        sess: An authenticated session.

    Returns:
        The :meth:`~certinext.catalog.CatalogAccessor.ca_by_product_code`
        map, or an empty dict after logging a warning.
    """
    try:
        return sess.catalog.ca_by_product_code()
    except CertiNextAPIError as exc:
        log.warning("catalog read failed; CA column left blank", status_code=exc.status_code)
        return {}


@app.command()
def list_certificates(
    ctx: typer.Context,
    status: Optional[str] = typer.Option(
        None,
        "--status",
        metavar="STATUS",
        help=("Filter by certificate status (e.g. issued, expired, pending-dcv, pending-csr, revoked, cancelled)"),
    ),
    sans: bool = typer.Option(False, "--sans", help="Download and show every SAN; reuse --cache if enabled"),
    csv_output: bool = typer.Option(False, "--csv", help="Write CSV to stdout (SANs as a JSON array)"),
    use_cache: Optional[bool] = typer.Option(None, "--cache/--no-cache", help="Reuse replacement-report downloads"),
    refresh_cache: bool = typer.Option(False, "--refresh-cache", help="Refresh downloads; implies --cache"),
    cache_directory: Optional[Path] = typer.Option(None, "--cache-dir", help="Shared cache base; implies --cache"),
    cache_max_age: Optional[int] = typer.Option(
        None, "--cache-max-age", min=1, help="Maximum age in days; implies --cache"
    ),
) -> None:
    """List SSL/TLS certificate orders from the CertiNext orders report.

    The ``ca`` column (and JSON key) names the issuing CA, joined from each
    order's product code through the catalog: the issuer name can't tell,
    because emSign issues from InCommon-branded intermediates.
    """
    if csv_output and ctx.obj.output_json:
        raise typer.BadParameter("--csv and --json are mutually exclusive")
    caching = _resolve_cache(sans, use_cache, refresh_cache, cache_directory, cache_max_age, inspect_option="--sans")
    if cache_directory is not None and cache_directory.expanduser().is_file():
        raise typer.BadParameter("cache directory is a file", param_hint="--cache-dir")
    sess = session(ctx)

    orders = sess.orders.get_list(status=status)
    cas = _ca_map(sess) if orders else {}

    def _ca(product_code: str | None) -> str:
        return cas.get(product_code or "", "")

    entries = [CertificateEntry(o) for o in orders]
    unknown = 0
    if sans:
        cache = (
            _build_cache(sess, refresh_cache, cache_directory, cache_max_age or DEFAULT_MAX_AGE.days)
            if caching
            else None
        )
        try:
            enrich_sans(sess, entries, cache)
        except ImportError as exc:
            print(str(exc), file=sys.stderr)
            raise typer.Exit(1) from exc
        if cache:
            print(
                f"Cache: {sum(e.from_cache for e in entries)} hits, {cache.writes} writes; "
                f"maximum age {cache.max_age.days} days",
                file=sys.stderr,
            )
        unknown = sum(e.sans is None for e in entries)
        if unknown:
            print(f"SANs unknown for {unknown} order(s); see per-row errors where inspection failed", file=sys.stderr)

    records = [
        {
            **o.as_dict(),
            "ca": _ca(o.product_code),
            **({"sans": e.sans, "sans_source": e.as_dict()["sans_source"], "error": e.error} if sans else {}),
        }
        for o, e in zip(orders, entries)
    ]
    rows = [
        {
            **o.to_row(),
            "ca": _ca(o.product_code),
            **({"sans": json.dumps(e.sans), "error": e.error or ""} if sans else {}),
        }
        for o, e in zip(orders, entries)
    ]
    if ctx.obj.output_json:
        print(json.dumps(records, indent=2))
    elif csv_output:
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]) if rows else ["order_number", "sans", "error"])
        writer.writeheader()
        writer.writerows(rows)
    elif not orders:
        label = f" with status '{status}'" if status else ""
        print(f"(no certificates{label})")
    else:
        status_label = f" ({status})" if status else ""
        print(f"Certificates{status_label}:\n")
        data_console().print(rows_table(rows))
        print(f"\n{len(orders)} certificate(s)")
    if any(e.error for e in entries) or (sans and unknown):
        raise typer.Exit(1)
