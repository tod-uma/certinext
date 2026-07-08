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

"""The consolidated ``certinext`` command-line application (ADR 0004).

One typer app with a subcommand per operation; the 0.3.x script names remain
installed as aliases that pre-select their subcommand (see
:mod:`certinext.cli._aliases`). Command modules are imported here for their
registration side effect on :data:`certinext.cli._app.app`.
"""

import sys

from typer import Abort

try:
    # typer >= 0.21 vendors click as typer._click and no longer depends on
    # the click distribution; ClickException has no public typer re-export.
    from typer._click.exceptions import ClickException
except ModuleNotFoundError:  # pragma: no cover - typer built against real click
    from click.exceptions import ClickException  # type: ignore[no-redef]

# Command modules register themselves on the app at import time.
from certinext.cli import (  # noqa: F401
    accounts,
    domain_cert_count,
    domains,
    healthcheck,
    issue_cert,
    ledger,
    list_certificates,
    parent_dcv_status,
    pending_dcv,
    setup_defaults,
    setup_keyring,
)
from certinext.cli._app import app

__all__ = ["app", "main"]


def main(args: list[str] | None = None) -> int:
    """Run the ``certinext`` app and return the process exit code.

    Runs click in non-standalone mode so the 0.3.x exit-code contract is
    preserved explicitly: usage errors exit 2 (as argparse did), Ctrl+C exits
    130 with ``Aborted.`` on stderr, and a command's ``SystemExit`` (e.g.
    healthcheck's monitoring-relevant codes) propagates untouched.

    Args:
        args: CLI arguments; None reads ``sys.argv[1:]`` (the console-script
            case). Alias entry points pass the subcommand pre-selected.

    Returns:
        The exit code for the process (console-script wrappers call
        ``sys.exit(main())``).
    """
    try:
        result = app(args=args, standalone_mode=False, prog_name="certinext")
    except Abort:
        print("Aborted.", file=sys.stderr)
        return 130
    except ClickException as exc:
        exc.show()
        return exc.exit_code
    return result if isinstance(result, int) else 0
