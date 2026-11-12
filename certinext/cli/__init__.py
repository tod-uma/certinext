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

import httpx
import structlog
from typer import Abort

from certinext.cli_support import log_caught_exception
from certinext.exceptions import TRANSIENT_STATUS_CODES, CertiNextAPIError, CertiNextAuthError

try:
    # typer >= 0.21 vendors click as typer._click and no longer depends on
    # the click distribution; ClickException has no public typer re-export.
    from typer._click.exceptions import ClickException
except ModuleNotFoundError:  # pragma: no cover - typer built against real click
    from click.exceptions import ClickException  # type: ignore[no-redef]

# Command modules register themselves on the app at import time.
from certinext.cli import (  # noqa: F401
    accounts,
    ca_validation,
    domain_cert_count,
    domains,
    healthcheck,
    issue_cert,
    ledger,
    list_certificates,
    parent_dcv_status,
    pending_dcv,
    replacement_report,
    setup_defaults,
    setup_keyring,
)
from certinext.cli._app import app

__all__ = ["app", "main"]

log = structlog.get_logger(__name__)

# Every shared option now lives on the single root callback (ADR 0009), not
# on a per-group callback — so Click would otherwise only accept them before
# the *first* subcommand token (``certinext --sandbox domains get
# maine.edu``). Users expect to type them anywhere (``certinext domains get
# maine.edu --sandbox``) too, so recognized tokens are hoisted to the very
# front of argv regardless of how deep the subcommand chain is.
_VALUE_OPTS = {
    "--profile", "--base-url", "--token-url",
    "--account-number", "--client-id", "--client-secret", "--scope", "--log-format",
    "--log-mode", "--debug-log-path",
}
_FLAG_OPTS = {"--json", "--verbose", "--sandbox"}


def _is_count_flag(token: str) -> bool:
    """True for combined short verbosity flags: ``-v``, ``-vv``, ``-vvv``, ``-vvvv``.

    Args:
        token: A single argv token.

    Returns:
        Whether the token is a ``-v``-only combination.
    """
    return len(token) >= 2 and token[0] == "-" and set(token[1:]) == {"v"}


def _hoist_shared_options(args: list[str]) -> list[str]:
    """Reorder argv so root-level shared options work anywhere on the command line.

    Args:
        args: Raw CLI arguments (``sys.argv[1:]`` or an explicit override).

    Returns:
        A reordered copy of ``args`` with recognized shared options moved to
        the front, ahead of the subcommand chain; relative order of every
        other token is preserved.
    """
    kept: list[str] = []
    hoisted: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        name = token.split("=", 1)[0]
        if name in _VALUE_OPTS:
            if "=" in token:
                hoisted.append(token)
                i += 1
            elif i + 1 < len(args):
                hoisted.extend(args[i:i + 2])
                i += 2
            else:
                hoisted.append(token)
                i += 1
            continue
        if token in _FLAG_OPTS or _is_count_flag(token):
            hoisted.append(token)
            i += 1
            continue
        kept.append(token)
        i += 1

    return hoisted + kept


def main(args: list[str] | None = None) -> int:
    """Run the ``certinext`` app and return the process exit code.

    Runs click in non-standalone mode so the 0.3.x exit-code contract is
    preserved explicitly: usage errors exit 2 (as argparse did), Ctrl+C exits
    130 with ``Aborted.`` on stderr, and a command's ``SystemExit`` (e.g.
    healthcheck's monitoring-relevant codes) propagates untouched.

    A command that lets a CertiNext outage escape (see
    :func:`_vendor_failure`) exits 1 with one log line instead of a
    traceback; 1 is what the uncaught exception exited with anyway. Any other
    exception still propagates with its traceback, since it is a bug.

    Args:
        args: CLI arguments; None reads ``sys.argv[1:]`` (the console-script
            case). Alias entry points pass the subcommand pre-selected.

    Returns:
        The exit code for the process (console-script wrappers call
        ``sys.exit(main())``).
    """
    resolved_args = _hoist_shared_options(sys.argv[1:] if args is None else args)
    try:
        result = app(args=resolved_args, standalone_mode=False, prog_name="certinext")
    except Abort:
        print("Aborted.", file=sys.stderr)
        return 130
    except ClickException as exc:
        exc.show()
        return exc.exit_code
    except (CertiNextAuthError, CertiNextAPIError, httpx.TransportError) as exc:
        failure = _vendor_failure(exc)
        if failure is None:
            raise
        event, summary = failure
        log_caught_exception(log, event, exc, error=summary)
        return 1
    return result if isinstance(result, int) else 0


def _vendor_failure(exc: Exception) -> tuple[str, str] | None:
    """Describe an escaped exception that means CertiNext itself failed.

    Args:
        exc: A token, API, or transport error that no command handled.

    Returns:
        ``(event, summary)`` for the log line: the event says what to do,
        the summary is one line without any HTML error page. ``None`` for an
        API error below 500, which points at the request (a bug or a vendor
        contract change) and keeps its traceback.
    """
    if isinstance(exc, CertiNextAuthError):
        if exc.transient:
            return "CertiNext is unavailable; try again later", exc.summary
        if exc.status_code in (400, 401, 403):
            return "CertiNext refused the credentials; check the profile", exc.summary
        return "CertiNext token request failed", exc.summary
    if isinstance(exc, httpx.TransportError):
        return "Could not reach CertiNext; try again later", str(exc) or type(exc).__name__
    if isinstance(exc, CertiNextAPIError) and exc.status_code >= 500:
        state = "unavailable" if exc.status_code in TRANSIENT_STATUS_CODES else "failing"
        return f"CertiNext is {state}; try again later", f"HTTP {exc.status_code}"
    return None
