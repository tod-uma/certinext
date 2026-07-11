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

"""Shared typer option types and console plumbing for the ``certinext`` CLI.

Each connection flag is declared once here as an ``Annotated`` alias so every
subcommand exposes the same spelling and help text as the 0.3.x scripts
(ADR 0004 flag-compatibility rule). Command bodies stay thin: declare the
shared options, call :func:`connect`, render.

Stream discipline (unchanged from 0.3.x, and load-bearing): stdout carries
data — tables, JSON, PEM; stderr carries everything else — logs, progress,
prompts. Use :func:`data_console` for stdout tables and plain ``print`` for
JSON/PEM; diagnostics go through structlog or :data:`err_console`.
"""

import sys
from typing import Annotated, Any, Optional

import typer
from rich.console import Console
from rich.table import Table

import certinext
from certinext.cli_support import build_session, resolve_connection
from certinext.session import CertiNextSession

# When stdout is piped, rich caps the console at 80 columns and would wrap or
# crop wide data tables. Data output must never be width-mangled, so piped
# consoles get an effectively unlimited width (tables render at content
# width — this does not pad rows).
_PIPE_WIDTH = 4000

# Diagnostics/progress console (stderr). Rich drops styling automatically
# when stderr is not a TTY.
err_console = Console(stderr=True)


def progress_disabled(verbose: int) -> bool:
    """Whether a ``rich.progress.Progress`` bar should be suppressed.

    True at ``-vvv`` and up, since the corresponding debug logs already
    itemize each step a bar would represent, and whenever stderr isn't a
    terminal, so redirected/cron output doesn't get a wall of refresh frames.

    Args:
        verbose: The command's ``-v`` count.

    Returns:
        ``True`` if a progress bar using :data:`err_console` should pass
        ``disable=True``.
    """
    return verbose >= 3 or not err_console.is_terminal


def data_console() -> Console:
    """Return a rich console for *data* output on stdout.

    On a TTY this is a normal auto-sized console (styled tables). When stdout
    is piped or redirected, the console is unstyled and width-uncapped so
    table content is never wrapped or truncated by rich's 80-column default.

    Returns:
        A :class:`rich.console.Console` writing to stdout.
    """
    if sys.stdout.isatty():
        return Console()
    return Console(width=_PIPE_WIDTH, no_color=True)


def rows_table(rows: list[dict[str, Any]]) -> Table:
    """Build a headed rich table from a list of uniform dict rows.

    The replacement for the ``tabulate(rows, headers="keys")`` idiom: column
    order comes from the first row's key order; None values render empty.

    Args:
        rows: Non-empty list of dicts sharing the same keys.

    Returns:
        A borderless :class:`rich.table.Table` ready for a data console.
    """
    table = Table(box=None, pad_edge=False)
    for key in rows[0]:
        table.add_column(str(key))
    for row in rows:
        table.add_row(*("" if value is None else str(value) for value in row.values()))
    return table


def pairs_table(data: dict[str, Any]) -> Table:
    """Build a headerless key/value rich table from a dict.

    The replacement for the ``tabulate(list(data.items()))`` idiom used to
    dump a single record's fields.

    Args:
        data: Mapping of field name to value.

    Returns:
        A borderless, headerless :class:`rich.table.Table`.
    """
    table = Table(box=None, pad_edge=False, show_header=False)
    table.add_column("key")
    table.add_column("value")
    for key, value in data.items():
        table.add_row(str(key), "" if value is None else str(value))
    return table


# --- Shared connection options (one definition, every subcommand) ---------

ProfileOption = Annotated[Optional[str], typer.Option(
    "--profile", metavar="NAME",
    help="Credential profile for keyring lookup (env: CERTINEXT_PROFILE; default: use the default profile)",
)]
SandboxOption = Annotated[bool, typer.Option(
    "--sandbox",
    help="Connect to the CertiNext sandbox API; implies --profile sandbox unless --profile is set",
)]
BaseUrlOption = Annotated[Optional[str], typer.Option(
    "--base-url", metavar="URL",
    help=f"CertiNext base URL (default: {certinext.BASE_URL}, or the profile/sandbox endpoint)",
)]
TokenUrlOption = Annotated[Optional[str], typer.Option(
    "--token-url", metavar="URL",
    help="OAuth2 token endpoint URL (default: derived from the base URL)",
)]
AccountNumberOption = Annotated[Optional[str], typer.Option(
    "--account-number", "--client-id", metavar="ACCT",
    help="CertiNext account number / OAuth2 client_id (env: CERTINEXT_CLIENT_ID)",
)]
ClientSecretOption = Annotated[Optional[str], typer.Option(
    "--client-secret", metavar="SECRET",
    help="OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)",
)]
ScopeOption = Annotated[str, typer.Option(
    "--scope", metavar="SCOPE", help="OAuth2 scope (optional)",
)]

# --- Shared output/verbosity options ---------------------------------------

JsonOption = Annotated[bool, typer.Option(
    "--json", help="Write output as JSON instead of human-readable text",
)]
VerboseOption = Annotated[int, typer.Option(
    "--verbose", "-v", count=True,
    help=(
        "Increase verbosity: -v shows progress, "
        "-vvv enables debug logging, "
        "-vvvv also enables third-party debug logging (httpx)"
    ),
)]

# Names of command groups (like "domains") whose connection/output options
# sit on a group-level callback rather than each leaf command. certinext.cli
# main() consults this to know which subcommand tokens accept those options
# anywhere on the command line, not just immediately after the group name.
# Every module that gives its typer group a shared options callback (instead
# of declaring the options on each leaf command directly) should add its
# name here right after registering the group on ``app``.
ENTITY_GROUP_NAMES: set[str] = set()


def connect(
    *,
    profile: str | None = None,
    sandbox: bool = False,
    base_url: str | None = None,
    token_url: str | None = None,
    account_number: str | None = None,
    client_secret: str | None = None,
    scope: str = "",
    prompt: bool = True,
) -> CertiNextSession:
    """Resolve the endpoint and credentials, and return an authenticated session.

    Chains :func:`certinext.cli_support.resolve_connection` and
    :func:`certinext.cli_support.build_session` — the one-liner every
    subcommand calls after collecting the shared connection options.

    Args:
        profile: ``--profile`` value, or None.
        sandbox: ``--sandbox`` flag.
        base_url: ``--base-url`` value, or None.
        token_url: ``--token-url`` value, or None.
        account_number: ``--account-number`` value, or None.
        client_secret: ``--client-secret`` value, or None.
        scope: ``--scope`` value (commands without the flag pass the default).
        prompt: Forwarded to :func:`~certinext.cli_support.build_session`;
            when False, missing credentials raise
            :exc:`~certinext.cli_support.CredentialsNotFoundError` instead of
            prompting.

    Returns:
        An authenticated :class:`~certinext.session.CertiNextSession`.
    """
    conn = resolve_connection(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
    )
    return build_session(
        conn,
        account_number=account_number,
        client_secret=client_secret,
        scope=scope,
        prompt=prompt,
    )
