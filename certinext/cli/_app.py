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
"""

from importlib.metadata import version

import typer

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
    version_: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the installed certinext version and exit.",
    ),
) -> None:
    pass
