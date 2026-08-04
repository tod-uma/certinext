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

"""The ``certinext`` typer application object (ADR 0004).

Lives in its own module so command modules can import ``app`` to register
themselves without a circular import through :mod:`certinext.cli`.

``pretty_exceptions_enable=False`` is deliberate: typer's rich tracebacks
print local variables by default, which could echo ``--client-secret``
values to the terminal, and their multi-line panels are noise in cron logs.
Unhandled exceptions keep plain Python tracebacks, as in 0.3.x.

Per ADR 0009, the root callback also declares every shared connection/output
option once and resolves them into a :class:`~certinext.cli._shared.GlobalOptions`
on ``ctx.obj`` — command modules no longer redeclare them individually.
"""

from importlib.metadata import version

import typer

from certinext.cli._shared import (
    AccountNumberOption,
    BaseUrlOption,
    ClientSecretOption,
    GlobalOptions,
    JsonOption,
    LogFormatOption,
    ProfileOption,
    SandboxOption,
    ScopeOption,
    TokenUrlOption,
    VerboseOption,
)
from certinext.cli_support import LogFormat, setup_logging

app = typer.Typer(
    name="certinext",
    help="CertiNext certificate management CLI.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

setup_app = typer.Typer(
    name="setup",
    help="Store credentials and issuance defaults for later runs.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
app.add_typer(setup_app)


def _version_callback(show_version: bool) -> None:
    """Print the installed ``certinext`` package version and exit.

    Args:
        show_version: The ``--version`` flag's value; a no-op when falsy so
            this can be used as an eager Typer option callback.

    Raises:
        typer.Exit: Always, when ``show_version`` is truthy — stops Typer
            from proceeding to subcommand parsing.
    """
    if show_version:
        typer.echo(version("certinext"))
        raise typer.Exit()


@app.callback()
def _main(
    ctx: typer.Context,
    version_: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the installed certinext version and exit.",
    ),
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
    scope: ScopeOption = "",
    output_json: JsonOption = False,
    verbose: VerboseOption = 0,
    log_format: LogFormatOption = LogFormat.LOGFMT,
) -> None:
    setup_logging(verbose, log_format=log_format)
    ctx.obj = GlobalOptions(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret, scope=scope,
        output_json=output_json, verbose=verbose, log_format=log_format,
    )
