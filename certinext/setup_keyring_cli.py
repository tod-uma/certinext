#!/usr/bin/env python3
"""Store CertiNext API credentials in the OS keychain.

Prompts for a CertiNext client ID and client secret, then stores them under a
profile-specific service name in the system keychain (Windows Credential
Manager on Windows, Keychain on macOS, libsecret/SecretService on Linux).

The default profile uses the service name 'certinext'. Named profiles append
the profile name: --profile prod uses 'certinext-prod'.

Run once before using scripts or tools that connect to the CertiNext API.
Switch profiles by setting CERTINEXT_PROFILE (or passing --profile) when
running the consuming script.

Usage:
    certinext-setup-keyring                        # default profile (installed command)
    certinext-setup-keyring --profile prod         # named profile
    certinext-setup-keyring --sandbox              # sandbox profile (shortcut for --profile sandbox)
"""
import argparse
import getpass
import sys

try:
    import keyring
except ImportError:
    sys.exit("keyring is not installed. Run: uv pip install certinext[keyring]")


def _service_name(profile: str | None) -> str:
    """Return the keyring service name for the given profile.

    Args:
        profile: Profile name, or None for the default profile.

    Returns:
        The keyring service name string.
    """
    return f'certinext-{profile}' if profile else 'certinext'


def _current(service: str, key: str) -> str | None:
    """Return the currently stored value for key under service, or None."""
    return keyring.get_password(service, key)


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


def main() -> None:
    """Interactively store CertiNext credentials in the OS keychain."""
    try:
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('--profile', metavar='NAME', default=None,
                            help='Credential profile name (default: use the default profile)')
        parser.add_argument('--sandbox', action='store_true', default=False,
                            help='Store credentials for the sandbox profile (shortcut for --profile sandbox)')
        args = parser.parse_args()

        if args.sandbox:
            if args.profile is None:
                args.profile = "sandbox"

        service = _service_name(args.profile)
        profile_label = f'profile {args.profile!r}' if args.profile else 'default profile'

        print("Store CertiNext credentials in the OS keychain.")
        print(f"Service name: {service!r}  ({profile_label})\n")

        current_id = _current(service, "CERTINEXT_CLIENT_ID")
        current_secret = _current(service, "CERTINEXT_CLIENT_SECRET")

        id_hint = f" [{current_id}]" if current_id else ""
        client_id = _prompt_with_default(f"CertiNext client ID{id_hint}: ", current_id)
        if not client_id:
            sys.exit("Client ID is required.")

        secret_hint = " [keep existing]" if current_secret else ""
        client_secret = _prompt_with_default(f"CertiNext client secret{secret_hint}: ", current_secret, secret=True)
        if not client_secret:
            sys.exit("Client secret is required.")
        if client_secret == current_secret:
            print("Keeping existing client secret.")

        keyring.set_password(service, "CERTINEXT_CLIENT_ID", client_id)
        keyring.set_password(service, "CERTINEXT_CLIENT_SECRET", client_secret)

        print()
        print("Stored:")
        print(f"  CERTINEXT_CLIENT_ID     = {client_id}")
        print(f"  CERTINEXT_CLIENT_SECRET = {'*' * len(client_secret)}")
        print()
        if args.profile:
            print(f"Run scripts with '--profile {args.profile}' or set CERTINEXT_PROFILE={args.profile}.")
        else:
            print("Credentials will be used automatically by any script that reads the certinext keyring service.")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
