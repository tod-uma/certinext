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

"""``certinext domains`` — manage CertiNext domains (nested subcommands).

Connection flags and ``--json`` are root-level options resolved by
:mod:`certinext.cli._app`'s callback (ADR 0009); this group declares no
callback of its own; the group's subcommand contexts inherit ``ctx.obj``
from the root context, and each subcommand builds its session lazily via
:func:`~certinext.cli._shared.session` so a usage error in the subcommand
line never triggers a credential prompt.
"""

import json
import sys
from enum import Enum
from typing import Any, Optional

import typer

from certinext.cli._app import app
from certinext.cli._shared import (
    data_console,
    pairs_table,
    rows_table,
    session,
)
from certinext.cli_support import prompt_stderr
from certinext.domains import Domain

domains_app = typer.Typer(
    name="domains",
    help="Manage CertiNext domains",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
app.add_typer(domains_app)


def _show_domain(ctx: typer.Context, domain: Domain) -> None:
    """Print one domain as JSON or as its human-readable str form.

    Args:
        ctx: The typer context (for the root ``--json`` flag).
        domain: The domain to display.
    """
    if ctx.obj.output_json:
        print(json.dumps(domain.as_dict(), indent=2))
    else:
        print(domain)


def _show_domains(ctx: typer.Context, domains: list[Domain]) -> None:
    """Print a domain list as JSON or a table.

    Args:
        ctx: The typer context (for the root ``--json`` flag).
        domains: The domains to display.
    """
    if ctx.obj.output_json:
        print(json.dumps([d.as_dict() for d in domains], indent=2))
        return
    if not domains:
        print("(no domains)")
        return
    data_console().print(rows_table([d.to_row() for d in domains]))


def _show_data(ctx: typer.Context, data: dict[str, Any] | list[Any]) -> None:
    """Print an arbitrary payload as JSON, a table, or line-per-item.

    Args:
        ctx: The typer context (for the root ``--json`` flag).
        data: A dict (rendered as key/value rows) or list (rendered as a
            headed table when the items are dicts, one line per item
            otherwise).
    """
    if ctx.obj.output_json:
        print(json.dumps(data, indent=2))
        return
    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            data_console().print(rows_table(data))
        else:
            for item in data:
                print(item)
    else:
        data_console().print(pairs_table(data))


@domains_app.command("list")
def list_domains(
    ctx: typer.Context,
    offset: Optional[int] = typer.Option(None, "--offset", help="Number of records to skip"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Maximum records to return"),
) -> None:
    """List all domains."""
    kwargs: dict[str, Any] = {}
    if offset is not None:
        kwargs["offset"] = offset
    if limit is not None:
        kwargs["limit"] = limit
    _show_domains(ctx, session(ctx).domain.get_list(**kwargs))


@domains_app.command("get")
def get_domain(
    ctx: typer.Context,
    domain_id: str = typer.Argument(
        ..., metavar="NAME_OR_ID", help="Domain name (e.g. maine.edu) or domain ID",
    ),
) -> None:
    """Get a single domain by name or ID."""
    _show_domain(ctx, session(ctx).domain.get(domain_id))


@domains_app.command("create")
def create_domain(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Domain name (e.g. example.com)"),
    extra: Optional[list[str]] = typer.Argument(
        None, metavar="[KEY=VALUE]...",
        help="Additional fields to include in the request body",
    ),
) -> None:
    """Create a new domain."""
    fields: dict[str, str] = {}
    for pair in extra or []:
        key, _, value = pair.partition("=")
        fields[key] = value
    _show_domain(ctx, session(ctx).domain.create(name, **fields))


@domains_app.command("deactivate")
def deactivate_domain(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Deactivate a domain."""
    if not yes:
        confirm = prompt_stderr(f"Deactivate domain '{domain_id}'? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.", file=sys.stderr)
            return
    _show_domain(ctx, session(ctx).domain.get(domain_id).deactivate())


@domains_app.command("get-dcv")
def get_dcv(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
) -> None:
    """Get DCV status for a domain."""
    # mode="json": DcvInfo.token_expiry is a datetime, which the shared
    # _show_data() -> json.dumps() path can't serialize directly.
    _show_data(ctx, session(ctx).domain.get(domain_id).get_dcv().model_dump(mode="json"))


@domains_app.command("verify-dcv")
def verify_dcv(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
) -> None:
    """Trigger DCV verification for a domain."""
    result = session(ctx).domain.get(domain_id).verify()
    print(result)
    if ctx.obj.output_json:
        _show_data(ctx, result.raw)


class _DcvMethod(str, Enum):
    """The DCV methods the API accepts (mirrors the library's Literal type)."""

    dns_txt = "DNS-TXT"
    http_url = "HTTP-URL"


@domains_app.command("change-dcv-method")
def change_dcv_method(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
    method: _DcvMethod = typer.Argument(..., help="DCV method: DNS-TXT or HTTP-URL"),
) -> None:
    """Change the DCV method for a domain."""
    _show_data(ctx, session(ctx).domain.get(domain_id).change_dcv_method(method.value))


@domains_app.command("last-dcv-attempt")
def last_dcv_attempt(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
) -> None:
    """Get the last DCV attempt for a domain."""
    _show_data(ctx, session(ctx).domain.get(domain_id).last_dcv_attempt())


@domains_app.command("dcv-attempt-history")
def dcv_attempt_history(
    ctx: typer.Context,
    domain_id: str = typer.Argument(..., metavar="ID", help="Domain ID"),
) -> None:
    """Get DCV attempt history for a domain."""
    _show_data(ctx, session(ctx).domain.get(domain_id).dcv_attempt_history())
