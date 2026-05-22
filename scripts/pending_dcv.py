#!/usr/bin/env python3
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

"""List all domains that require Domain Control Validation (DCV).

Connects to the CertiNext API and prints every active domain whose DCV status
is not yet VERIFIED. Credentials are resolved in priority order: command-line
argument → environment variable → interactive prompt.

Usage:
    python scripts/pending_dcv.py
    python scripts/pending_dcv.py --pattern ".*\\.maine\\.edu"
    python scripts/pending_dcv.py --json
"""

import argparse
import getpass
import json
import os

from tabulate import tabulate

import certinext
from certinext._keyring import keyring_get, keyring_service
from certinext.domains import Domain


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


def _show_domains(domains: list[Domain], use_json: bool) -> None:
    """Print domains as a table or as raw JSON, depending on use_json."""
    if use_json:
        print(json.dumps([d.as_dict() for d in domains], indent=2))
    else:
        if not domains:
            print("(no domains pending DCV)")
            return
        print(tabulate([d.to_row() for d in domains], headers="keys", tablefmt="simple"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="List all active domains that have not completed DCV verification",
    )
    # Credentials: each can be supplied as a CLI arg, env var, or interactive prompt.
    parser.add_argument(
        "--profile", metavar="NAME", default=None,
        help="Credential profile for keyring lookup (env: CERTINEXT_PROFILE; default: use the default profile)",
    )
    parser.add_argument(
        "--account-number", "--client-id", dest="account_number", metavar="ACCT",
        help="CertiNext account number (env: CERTINEXT_CLIENT_ID)",
    )
    parser.add_argument(
        "--client-secret", metavar="SECRET",
        help="OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)",
    )
    # API connection — defaults cover the standard US endpoint.
    parser.add_argument(
        "--base-url", default="https://us-api.certinext.io", metavar="URL",
        help="CertiNext base URL (default: https://us-api.certinext.io)",
    )
    parser.add_argument(
        "--token-url", default="https://us-api.certinext.io/oauth/token", metavar="URL",
        help="OAuth2 token endpoint URL",
    )
    # Optional client-side regex filter applied after the API response.
    parser.add_argument(
        "--pattern", metavar="REGEX",
        help="Filter domains by regex pattern (re.fullmatch, case-insensitive)",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )
    args = parser.parse_args()

    profile = args.profile or os.environ.get("CERTINEXT_PROFILE")
    svc = keyring_service("certinext", profile)

    client_id = _resolve(
        args.account_number, "CERTINEXT_CLIENT_ID", "CertiNext account number",
        kr_service=svc, kr_key="CERTINEXT_CLIENT_ID",
    )
    client_secret = _resolve(
        args.client_secret, "CERTINEXT_CLIENT_SECRET", "CertiNext client secret", secret=True,
        kr_service=svc, kr_key="CERTINEXT_CLIENT_SECRET",
    )

    sess = certinext.session(
        base_url=args.base_url,
        token_url=args.token_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    # list_pending_dcv() uses server-side filters (ACTIVE + non-VERIFIED DCV status)
    # to minimise data transferred, then applies the optional client-side pattern.
    domains = sess.domain.list_pending_dcv(pattern=args.pattern)
    _show_domains(domains, args.json)


if __name__ == "__main__":
    main()
