"""Shared CLI utilities for certinext command-line scripts.

Provides argument registration, sandbox URL overrides, and session construction
so each CLI entry point stays focused on its own logic rather than credential
plumbing.
"""

import argparse
import getpass
import os
from typing import Any

import certinext
from certinext._keyring import keyring_get, keyring_service


def _resolve(
    arg_value: str | None,
    env_var: str,
    prompt: str,
    secret: bool = False,
    kr_service: str | None = None,
    kr_key: str | None = None,
) -> str:
    """Resolve a credential from CLI arg, keyring, environment variable, or interactive prompt.

    Checks in priority order: explicit argument → keyring → environment variable → prompt.
    Secrets are read with getpass so they are not echoed to the terminal.

    Args:
        arg_value: Value from a CLI argument, or None if not provided.
        env_var: Environment variable name to fall back to.
        prompt: Text shown when prompting interactively.
        secret: If True, use getpass so input is not echoed.
        kr_service: Keyring service name to check before the env var.
        kr_key: Keyring key (username) to look up under kr_service.

    Returns:
        The resolved credential string.
    """
    if arg_value:
        return arg_value
    if kr_service and kr_key:
        kr_value = keyring_get(kr_service, kr_key)
        if kr_value:
            return kr_value
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value
    if secret:
        return getpass.getpass(f"{prompt}: ")
    return input(f"{prompt}: ")


def add_connection_args(target: Any, *, scope: bool = False) -> None:
    """Add standard connection arguments to a parser or argument group.

    Registers ``--profile``, ``--sandbox``, ``--base-url``, ``--token-url``,
    ``--account-number`` / ``--client-id``, and ``--client-secret``. Optionally
    also registers ``--scope`` when ``scope=True``.

    Args:
        target: An :class:`argparse.ArgumentParser` or argument group that
            accepts ``add_argument`` calls.
        scope: If ``True``, also add ``--scope`` for OAuth2 scope strings.
    """
    target.add_argument(
        "--profile", metavar="NAME", default=None,
        help="Credential profile for keyring lookup (env: CERTINEXT_PROFILE; default: use the default profile)",
    )
    target.add_argument(
        "--sandbox", action="store_true", default=False,
        help="Connect to the CertiNext sandbox API; implies --profile sandbox unless --profile is set",
    )
    target.add_argument(
        "--base-url", default=certinext.BASE_URL, metavar="URL",
        help=f"CertiNext base URL (default: {certinext.BASE_URL})",
    )
    target.add_argument(
        "--token-url", default=certinext.TOKEN_URL, metavar="URL",
        help=f"OAuth2 token endpoint URL (default: {certinext.TOKEN_URL})",
    )
    target.add_argument(
        "--account-number", "--client-id", dest="account_number", default=None, metavar="ACCT",
        help="CertiNext account number / OAuth2 client_id (env: CERTINEXT_CLIENT_ID)",
    )
    target.add_argument(
        "--client-secret", default=None, metavar="SECRET",
        help="OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)",
    )
    if scope:
        target.add_argument("--scope", default="", metavar="SCOPE", help="OAuth2 scope (optional)")


def apply_sandbox(args: argparse.Namespace) -> None:
    """Override base_url and token_url for the sandbox when ``--sandbox`` is set.

    Also sets ``args.profile`` to ``'sandbox'`` if no profile was explicitly
    provided, so keyring lookups automatically find sandbox credentials.

    Args:
        args: Parsed CLI arguments (modified in place).
    """
    if args.sandbox:
        args.base_url = certinext.SANDBOX_BASE_URL
        args.token_url = certinext.SANDBOX_TOKEN_URL
        if args.profile is None:
            args.profile = "sandbox"


def build_session(args: argparse.Namespace) -> certinext.CertiNextSession:
    """Resolve credentials and return a configured :class:`~certinext.CertiNextSession`.

    Reads credentials in priority order: explicit CLI argument → keyring →
    environment variable → interactive prompt.

    Args:
        args: Parsed CLI arguments. Must have ``profile``, ``base_url``,
            ``token_url``, ``account_number``, and ``client_secret`` attributes.
            ``scope`` is optional (defaults to ``""`` when absent).

    Returns:
        An authenticated :class:`~certinext.CertiNextSession`.
    """
    profile = getattr(args, "profile", None) or os.environ.get("CERTINEXT_PROFILE")
    svc = keyring_service("certinext", profile)
    client_id = _resolve(
        args.account_number, "CERTINEXT_CLIENT_ID", "CertiNext account number",
        kr_service=svc, kr_key="CERTINEXT_CLIENT_ID",
    )
    client_secret = _resolve(
        args.client_secret, "CERTINEXT_CLIENT_SECRET", "CertiNext client secret", secret=True,
        kr_service=svc, kr_key="CERTINEXT_CLIENT_SECRET",
    )
    return certinext.session(
        base_url=args.base_url,
        token_url=args.token_url,
        client_id=client_id,
        client_secret=client_secret,
        scope=getattr(args, "scope", ""),
        sandbox=getattr(args, "sandbox", False),
    )
