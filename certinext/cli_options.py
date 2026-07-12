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

"""Public typer option aliases and session helper for CertiNext CLIs.

The typer-specific companion to :mod:`certinext.cli_support` (which stays
framework-agnostic). Downstream scripts that build typer commands against
CertiNext declare these ``Annotated`` aliases so their connection flags keep
the exact spellings and help text of the bundled ``certinext`` CLI (ADR 0004
flag-compatibility rule), then call :func:`connect` to turn the collected
values into an authenticated session.

Typical use::

    import typer
    from certinext.cli_options import ProfileOption, SandboxOption, connect

    app = typer.Typer()

    @app.command()
    def my_command(profile: ProfileOption = None, sandbox: SandboxOption = False) -> None:
        sess = connect(profile=profile, sandbox=sandbox)
        ...

The bundled CLI's rendering helpers (rich consoles and tables) are internal
and deliberately not exported here.
"""

from typing import Annotated, Optional

import typer

import certinext
from certinext.cli_support import build_session, resolve_connection
from certinext.session import CertiNextSession

# --- Shared connection options (one definition, every command) --------------

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

# --- Shared output/verbosity options ----------------------------------------

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
    command calls after collecting the shared connection options.

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
