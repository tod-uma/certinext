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
from certinext.models.domains import DcvInfo

domains_app = typer.Typer(
    name="domains",
    help="Manage CertiNext domains",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
app.add_typer(domains_app)

_VALIDATED_BY_HELP = (
    "Only consider records validated by this CA (e.g. SSLCOM, EMSIGN). An "
    "organization can hold the same name once per CA; without this a name "
    "lookup returns the emSign record and warns."
)


_VALIDATED_BY_WRITE_HELP = (
    "Only consider records validated by this CA (e.g. SSLCOM, EMSIGN). An "
    "organization can hold the same name once per CA; a name with more than "
    "one record is refused unless this (or a domain ID) picks one."
)


def _validated_by_option(help_text: str = _VALIDATED_BY_HELP) -> Any:
    """Build the shared ``--validated-by`` option (one fresh instance per command).

    Args:
        help_text: The option's help; write commands pass their own wording
            because they refuse an ambiguous name instead of falling back.

    Returns:
        A typer option defaulting to ``None``.
    """
    return typer.Option(None, "--validated-by", metavar="CA", help=help_text)


def _lookup(ctx: typer.Context, name_or_id: str, validated_by: str | None) -> Domain:
    """Fetch one domain by name or ID, honouring ``--validated-by`` for names.

    Args:
        ctx: The typer context (for the session).
        name_or_id: A domain name (contains a dot) or an opaque domain ID.
        validated_by: The CA to pick when a name has one record per CA.

    Returns:
        The matching :class:`Domain`.
    """
    return session(ctx).domain.get(name_or_id, validated_by=validated_by)


def _lookup_for_write(
    ctx: typer.Context, name_or_id: str, validated_by: str | None, *, hint: str,
) -> Domain:
    """Fetch the one domain a write command acts on, refusing an ambiguous name.

    :meth:`~certinext.domains.DomainAccessor.get` resolves a name held under
    several CAs to the emSign record with only a warning. That suits reads,
    but a write (verify, deactivate, change method) would then silently act
    on the emSign record when the operator meant SSL.com, so here a name
    with more than one record and no ``validated_by`` is a usage error. IDs,
    a single match and an explicit ``validated_by`` behave as in
    :func:`_lookup`.

    Args:
        ctx: The typer context (for the session and ``ctx.fail``).
        name_or_id: A domain name (contains a dot) or an opaque domain ID.
        validated_by: The CA to pick when a name has one record per CA.
        hint: What the operator should pass instead, for the error message.

    Returns:
        The matching :class:`Domain`.

    Raises:
        click.UsageError: Via ``ctx.fail`` (exit 2) when the name matches
            more than one record and ``validated_by`` is not given.
    """
    if validated_by is None and "." in name_or_id:
        name = name_or_id.lower()
        matches = [d for d in session(ctx).domain.get_list() if (d.name or "").lower() == name]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            cas = ", ".join(sorted(d.ca for d in matches))
            ctx.fail(f"{name_or_id!r} matches {len(matches)} domain records (CAs: {cas}); {hint}")
    return _lookup(ctx, name_or_id, validated_by)


def _show_dcv(ctx: typer.Context, info: DcvInfo) -> None:
    """Print DCV details; non-emSign ``options`` get their own table.

    JSON output is the full model dump, unchanged. The human form shows the
    scalar fields as key/value rows, then one row per validation option
    (method, record name and value, covered name, expiry), marking the
    option CertiNext currently checks with ``*``.

    Args:
        ctx: The typer context (for the root ``--json`` flag).
        info: The parsed DCV details.
    """
    # mode="json": datetimes (token_expiry, expires_at) aren't JSON-serializable raw.
    data = info.model_dump(mode="json")
    if ctx.obj.output_json:
        print(json.dumps(data, indent=2))
        return
    data.pop("options", None)
    if info.is_emsign:
        for key in ("ca_status", "record_name", "record_value", "option_id"):
            data.pop(key, None)
    else:
        for key in ("token", "host", "token_expiry"):
            data.pop(key, None)
    data["validated_by"] = info.ca
    console = data_console()
    console.print(pairs_table(data))
    if info.options:
        print("\nValidation options (* = selected):\n")
        console.print(rows_table([
            {
                "": "*" if o.option_id and o.option_id == info.option_id else "",
                "method": o.method,
                "record_name": o.record_name,
                "record_value": o.record_value,
                "covers": o.covers_name or "",
                "expires": o.expires_at.isoformat() if o.expires_at else "",
                "option_id": o.option_id,
            }
            for o in info.options
        ]))


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
    validated_by: Optional[str] = typer.Option(
        None, "--validated-by", metavar="CA",
        help="Only list records validated by this CA (e.g. SSLCOM, EMSIGN)",
    ),
) -> None:
    """List all domains."""
    kwargs: dict[str, Any] = {}
    if offset is not None:
        kwargs["offset"] = offset
    if limit is not None:
        kwargs["limit"] = limit
    if validated_by is not None:
        kwargs["validated_by"] = validated_by
    _show_domains(ctx, session(ctx).domain.get_list(**kwargs))


@domains_app.command("get")
def get_domain(
    ctx: typer.Context,
    domain_id: str = typer.Argument(
        ..., metavar="NAME_OR_ID", help="Domain name (e.g. maine.edu) or domain ID",
    ),
    validated_by: Optional[str] = _validated_by_option(),
) -> None:
    """Get a single domain by name or ID."""
    _show_domain(ctx, _lookup(ctx, domain_id, validated_by))


@domains_app.command("create")
def create_domain(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Domain name (e.g. example.com)"),
    extra: Optional[list[str]] = typer.Argument(
        None, metavar="[KEY=VALUE]...",
        help="Additional fields to include in the request body",
    ),
    ca: Optional[str] = typer.Option(
        None, "--ca", metavar="CA",
        help=(
            "CA to validate the domain (e.g. SSLCOM, EMSIGN). Omitted: the "
            "account decides. The organization may hold the name once per CA."
        ),
    ),
) -> None:
    """Create a new domain."""
    fields: dict[str, str] = {}
    for pair in extra or []:
        key, _, value = pair.partition("=")
        fields[key] = value
    if ca is not None:
        if "ca" in fields:
            ctx.fail("Give the CA once: --ca or ca=VALUE, not both")
        fields["ca"] = ca
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
    domain = _lookup_for_write(ctx, domain_id, None, hint="pass the domain ID (see 'domains list')")
    _show_domain(ctx, domain.deactivate())


@domains_app.command("get-dcv")
def get_dcv(
    ctx: typer.Context,
    domain_id: str = typer.Argument(
        ..., metavar="NAME_OR_ID", help="Domain name (e.g. maine.edu) or domain ID",
    ),
    validated_by: Optional[str] = _validated_by_option(),
) -> None:
    """Get DCV status for a domain, including every SSL.com validation option."""
    _show_dcv(ctx, _lookup(ctx, domain_id, validated_by).get_dcv())


@domains_app.command("verify-dcv")
def verify_dcv(
    ctx: typer.Context,
    domain_id: str = typer.Argument(
        ..., metavar="NAME_OR_ID", help="Domain name (e.g. maine.edu) or domain ID",
    ),
    validated_by: Optional[str] = _validated_by_option(_VALIDATED_BY_WRITE_HELP),
    option_id: Optional[str] = typer.Option(
        None, "--option-id", metavar="ID",
        help=(
            "SSL.com domains only: check this validation option instead of the "
            "selected one (IDs are listed by get-dcv)"
        ),
    ),
) -> None:
    """Trigger DCV verification for a domain."""
    domain = _lookup_for_write(ctx, domain_id, validated_by, hint="pass --validated-by CA or the domain ID")
    result = domain.verify(option_id=option_id)
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
