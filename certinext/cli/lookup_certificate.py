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

"""``certinext lookup-certificate`` - exact certificate lookup with live details."""

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from certinext._inspection_cache import DEFAULT_MAX_AGE
from certinext.certificate_lookup import lookup_certificates
from certinext.cli._app import app
from certinext.cli._certificate_cache import _build_cache, _resolve_cache
from certinext.cli._shared import session


class _Field(str, Enum):
    """Identifiers supported by exact certificate lookup."""

    auto = "auto"
    san = "san"
    cn = "cn"
    order = "order"
    serial = "serial"
    request = "request"
    requestor = "requestor"


@app.command()
def lookup_certificate(
    ctx: typer.Context,
    identifier: str = typer.Argument(..., help="Literal identifier; returns every matching order"),
    field: _Field = typer.Option(_Field.auto, "--field", help="Identifier type; auto also scans SANs"),
    use_cache: Optional[bool] = typer.Option(
        None, "--cache/--no-cache", help="Reuse certificate downloads for SAN/auto; ignored for other fields"
    ),
    refresh_cache: bool = typer.Option(False, "--refresh-cache", help="Refresh downloads; implies --cache"),
    cache_directory: Optional[Path] = typer.Option(None, "--cache-dir", help="Shared cache base; implies --cache"),
    cache_max_age: Optional[int] = typer.Option(
        None, "--cache-max-age", min=1, help="Maximum age in days; implies --cache"
    ),
) -> None:
    """Find certificates by SAN, CN, order, serial, request number or requestor.

    Exact, case-insensitive matching; wildcard names are literal. SAN/auto scans
    all issued rows in the live report, including expired certificates. Details
    are always fetched live; absent contact fields mean unknown availability.
    Requestor search matches a full name or email and reads every order's
    current details; it is excluded from auto and downloads no certificates.
    Exit 1 means partial results; exit 3 means no match without known failures.
    """
    if not identifier.strip():
        raise typer.BadParameter("identifier cannot be blank")
    scanning = field in (_Field.auto, _Field.san)
    caching = _resolve_cache(
        scanning,
        use_cache,
        refresh_cache,
        cache_directory,
        cache_max_age,
        inspect_option="--field san or --field auto",
    )
    if caching and cache_directory is not None and cache_directory.expanduser().is_file():
        raise typer.BadParameter("cache directory is a file", param_hint="--cache-dir")
    sess = session(ctx)
    cache = (
        _build_cache(sess, refresh_cache, cache_directory, cache_max_age or DEFAULT_MAX_AGE.days) if caching else None
    )
    try:
        result = lookup_certificates(sess, identifier, field=field.value, cache=cache)
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        raise typer.Exit(1) from exc
    payload = {
        "matches": [m.as_dict() for m in result.matches],
        "errors": [{"order_number": e.record.order_number, "error": e.error} for e in result.errors],
        "unknown_sans": result.unknown_sans,
        "unknown_requestors": result.unknown_requestors,
        "complete": not result.errors and not result.unknown_sans and not result.unknown_requestors,
        "cache": {
            "enabled": bool(cache),
            "hits": result.cache_hits,
            "misses": result.cache_misses if cache else 0,
            "max_age_days": cache.max_age.days if cache else None,
        },
    }
    print(json.dumps(payload, indent=2))
    if result.errors or result.unknown_sans or result.unknown_requestors:
        print("Lookup is incomplete; unavailable search fields or failed requests may hide matches", file=sys.stderr)
        raise typer.Exit(1)
    if not result.matches:
        raise typer.Exit(3)
