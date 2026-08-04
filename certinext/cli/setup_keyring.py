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

"""``certinext setup keyring`` — store API credentials in the OS keychain.

Prompts for a CertiNext client ID and client secret, then stores them under a
profile-specific service name in the system keychain (Windows Credential
Manager on Windows, Keychain on macOS, libsecret/SecretService on Linux).

The default profile uses the service name ``certinext``. Named profiles append
the profile name: ``--profile prod`` uses ``certinext-prod``.

The keyring import is deliberately inside the command (the 0.3.x script could
``sys.exit`` at import time; in the consolidated app that would take every
other subcommand down with it when the ``keyring`` extra is absent).
"""

import getpass

import typer

from certinext._keyring import no_keyring_help
from certinext.cli._app import setup_app


def _service_name(profile: str | None) -> str:
    """Return the keyring service name for the given profile.

    Args:
        profile: Profile name, or None for the default profile.

    Returns:
        The keyring service name string.
    """
    return f"certinext-{profile}" if profile else "certinext"


def _prompt_with_default(prompt: str, default: str | None, secret: bool = False) -> str | None:
    """Prompt the user for a value, returning the default if they press Enter.

    Args:
        prompt: Text shown to the user.
        default: Value returned when the user enters nothing.
        secret: If True, use getpass so the input is not echoed.

    Returns:
        The entered value, or the default, or None if both are empty.
    """
    if secret:
        value = getpass.getpass(prompt)
    else:
        value = input(prompt).strip()
    return value if value else default


@setup_app.command("keyring")
def setup_keyring(ctx: typer.Context) -> None:
    """Interactively store CertiNext credentials in the OS keychain.

    Run once before using scripts or tools that connect to the CertiNext API.
    Switch profiles by setting CERTINEXT_PROFILE (or passing --profile) when
    running the consuming command.
    """
    profile = ctx.obj.profile
    sandbox = ctx.obj.sandbox
    try:
        import keyring
        from keyring.errors import NoKeyringError
    except ImportError:
        raise SystemExit("keyring is not installed. Run: uv pip install certinext[keyring]")

    try:
        if sandbox:
            if profile is None:
                profile = "sandbox"
            else:
                typer.echo(
                    f"Warning: --sandbox is ignored because --profile {profile!r} "
                    f"was given; storing under profile {profile!r}.\n"
                    "  (This tool stores only credentials, not a URL. To make a profile "
                    "use the sandbox endpoint,\n"
                    f"   run: certinext setup defaults --profile {profile} --sandbox)",
                    err=True,
                )

        service = _service_name(profile)
        profile_label = f"profile {profile!r}" if profile else "default profile"

        print("Store CertiNext credentials in the OS keychain.")
        print(f"Service name: {service!r}  ({profile_label})\n")

        current_id = keyring.get_password(service, "CERTINEXT_CLIENT_ID")
        current_secret = keyring.get_password(service, "CERTINEXT_CLIENT_SECRET")

        id_hint = f" [{current_id}]" if current_id else ""
        client_id = _prompt_with_default(f"CertiNext client ID{id_hint}: ", current_id)
        if not client_id:
            raise SystemExit("Client ID is required.")

        secret_hint = " [keep existing]" if current_secret else ""
        client_secret = _prompt_with_default(f"CertiNext client secret{secret_hint}: ", current_secret, secret=True)
        if not client_secret:
            raise SystemExit("Client secret is required.")
        if client_secret == current_secret:
            print("Keeping existing client secret.")

        keyring.set_password(service, "CERTINEXT_CLIENT_ID", client_id)
        keyring.set_password(service, "CERTINEXT_CLIENT_SECRET", client_secret)

        print()
        print("Organization Consent Token (optional - needed for OV/EV orders to skip manual approval).")
        print("Find it in the CertiNext portal: Organization Management > Consent Tokens.")
        current_token = keyring.get_password(service, "CERTINEXT_PREVETTING_TOKEN")
        token_hint = " [keep existing]" if current_token else " (press Enter to skip)"
        prevetting_token = _prompt_with_default(
            f"Prevetting token{token_hint}: ", current_token, secret=True,
        )
        if prevetting_token and prevetting_token != current_token:
            keyring.set_password(service, "CERTINEXT_PREVETTING_TOKEN", prevetting_token)
        elif not prevetting_token and current_token:
            # User pressed Enter with an existing token — keep it; do nothing.
            pass

        print()
        print("Stored:")
        print(f"  CERTINEXT_CLIENT_ID     = {client_id}")
        print(f"  CERTINEXT_CLIENT_SECRET = {'*' * len(client_secret)}")
        if prevetting_token:
            print(f"  CERTINEXT_PREVETTING_TOKEN = {'*' * len(prevetting_token)}")
        elif current_token:
            print("  CERTINEXT_PREVETTING_TOKEN = (kept existing)")
        else:
            print("  CERTINEXT_PREVETTING_TOKEN = (not set - pass --prevetting-token at runtime if needed)")
        print()
        if profile:
            print(f"Run commands with '--profile {profile}' or set CERTINEXT_PROFILE={profile}.")
        else:
            print("Credentials will be used automatically by any script that reads the certinext keyring service.")
    except NoKeyringError:
        typer.echo(
            "Error: no usable OS keyring backend was found.\n\n" + no_keyring_help(),
            err=True,
        )
        raise SystemExit(1)
