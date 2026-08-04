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

"""Console plumbing and re-exported shared options for the ``certinext`` CLI.

The typer option aliases and :func:`connect` live in the public
:mod:`certinext.cli_options` module (so downstream scripts share the exact
flag spellings, per ADR 0004); this module re-exports them for the bundled
CLI's internal use and adds the rendering plumbing that stays private.

Per ADR 0009, the shared options themselves are declared once on the root
``app`` callback (:mod:`certinext.cli._app`), which resolves them into a
:class:`GlobalOptions` on ``ctx.obj``. Command bodies stay thin: accept
``ctx: typer.Context``, call :func:`session` for an authenticated session
(or read ``ctx.obj`` fields directly, e.g. ``ctx.obj.output_json``), render.

Stream discipline (unchanged from 0.3.x, and load-bearing): stdout carries
data — tables, JSON, PEM; stderr carries everything else — logs, progress,
prompts. Use :func:`data_console` for stdout tables and plain ``print`` for
JSON/PEM; diagnostics go through structlog or :data:`err_console`.
"""

import sys
from dataclasses import dataclass
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from certinext.cli_options import (
    AccountNumberOption as AccountNumberOption,
)
from certinext.cli_options import (
    BaseUrlOption as BaseUrlOption,
)
from certinext.cli_options import (
    ClientSecretOption as ClientSecretOption,
)
from certinext.cli_options import (
    JsonOption as JsonOption,
)
from certinext.cli_options import (
    LogFormatOption as LogFormatOption,
)
from certinext.cli_options import (
    LogModeOption as LogModeOption,
)
from certinext.cli_options import (
    ProfileOption as ProfileOption,
)
from certinext.cli_options import (
    SandboxOption as SandboxOption,
)
from certinext.cli_options import (
    ScopeOption as ScopeOption,
)
from certinext.cli_options import (
    TokenUrlOption as TokenUrlOption,
)
from certinext.cli_options import (
    VerboseOption as VerboseOption,
)
from certinext.cli_options import (
    connect as connect,
)
from certinext.cli_support import LogFormat, LogMode
from certinext.session import CertiNextSession

# When stdout is piped, rich caps the console at 80 columns and would wrap or
# crop wide data tables. Data output must never be width-mangled, so piped
# consoles get an effectively unlimited width (tables render at content
# width — this does not pad rows).
_PIPE_WIDTH = 4000

# Diagnostics/progress console (stderr). Rich drops styling automatically
# when stderr is not a TTY.
err_console = Console(stderr=True)


@dataclass
class GlobalOptions:
    """Shared CLI options, resolved once by the root callback (ADR 0009).

    Every command reads these from ``ctx.obj`` instead of redeclaring the
    same ``Annotated`` parameters; commands needing a session call
    :func:`session` rather than :func:`connect` directly.

    Attributes:
        profile: ``--profile`` value, or None.
        sandbox: ``--sandbox`` flag.
        base_url: ``--base-url`` value, or None.
        token_url: ``--token-url`` value, or None.
        account_number: ``--account-number`` value, or None.
        client_secret: ``--client-secret`` value, or None.
        scope: ``--scope`` value.
        output_json: ``--json`` flag.
        verbose: ``-v`` count.
        log_format: ``--log-format`` value.
        log_mode: ``--log-mode`` value.
    """

    profile: str | None
    sandbox: bool
    base_url: str | None
    token_url: str | None
    account_number: str | None
    client_secret: str | None
    scope: str
    output_json: bool
    verbose: int
    log_format: LogFormat
    log_mode: LogMode


def session(ctx: typer.Context, *, prompt: bool = True) -> CertiNextSession:
    """Build an authenticated session from the root callback's stashed options.

    Session-building stays lazy — call this from inside a command body, not
    a group callback — so a usage error in the command line never triggers a
    credential prompt.

    Args:
        ctx: The typer context; ``ctx.obj`` holds a :class:`GlobalOptions`
            (set by the root callback in :mod:`certinext.cli._app`).
        prompt: Forwarded to :func:`connect`; False raises
            :exc:`~certinext.cli_support.CredentialsNotFoundError` instead of
            prompting when credentials are missing.

    Returns:
        An authenticated :class:`~certinext.session.CertiNextSession`.
    """
    opts: GlobalOptions = ctx.obj
    return connect(
        profile=opts.profile, sandbox=opts.sandbox, base_url=opts.base_url,
        token_url=opts.token_url, account_number=opts.account_number,
        client_secret=opts.client_secret, scope=opts.scope, prompt=prompt,
    )


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
