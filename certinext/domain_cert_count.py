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

"""Show all registered domains and how many certificates each one has.

Fetches the full domain list and the orders report, then joins them by domain
name to produce a per-domain certificate count. Use ``--status`` to restrict
counts to only issued or only expired certificates.

Usage:
    certinext-domain-cert-count
    certinext-domain-cert-count --status issued
    certinext-domain-cert-count --status expired
    certinext-domain-cert-count --json
"""

import argparse
import getpass
import json
import os
from collections import Counter

from tabulate import tabulate

import certinext
from certinext._keyring import keyring_get, keyring_service
from certinext.domains import Domain
from certinext.orders import OrderRecord


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


def _build_rows(
    domains: list[Domain],
    orders: list[OrderRecord],
) -> list[dict[str, str]]:
    """Join domains and orders into a sorted list of display rows.

    All registered domains appear in the output. Domains whose name appears as
    the ``common_name`` on one or more orders show the matching count; others
    show ``0``.

    Orders whose ``common_name`` does not match any registered domain are
    appended at the end, flagged with ``(not registered)``.

    Args:
        domains: Registered domain objects from the Domains API.
        orders: Order records from the Orders Report API.

    Returns:
        List of dicts with keys ``domain``, ``certificates``.
    """
    counts: Counter[str] = Counter(
        o.common_name.lower() for o in orders if o.common_name
    )
    registered: set[str] = {(d.name or "").lower() for d in domains}

    rows: list[dict[str, str]] = []
    for d in sorted(domains, key=lambda x: x.name or ""):
        key = (d.name or "").lower()
        rows.append({"domain": d.name or "", "certificates": str(counts.get(key, 0))})

    # Orphaned: orders with a CN that isn't in the domain registry.
    for cn, count in sorted(counts.items()):
        if cn not in registered:
            rows.append({"domain": f"{cn} (not registered)", "certificates": str(count)})

    return rows


def main() -> None:
    """Entry point for certinext-domain-cert-count."""
    parser = argparse.ArgumentParser(
        description="Show all registered domains and their certificate counts",
    )
    parser.add_argument(
        "--profile", metavar="NAME", default=None,
        help="Credential profile for keyring lookup (env: CERTINEXT_PROFILE)",
    )
    parser.add_argument(
        "--account-number", "--client-id", dest="account_number", metavar="ACCT",
        help="CertiNext account number (env: CERTINEXT_CLIENT_ID)",
    )
    parser.add_argument(
        "--client-secret", metavar="SECRET",
        help="OAuth2 client secret (env: CERTINEXT_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--base-url", default="https://us-api.certinext.io", metavar="URL",
        help="CertiNext base URL (default: https://us-api.certinext.io)",
    )
    parser.add_argument(
        "--token-url", default="https://us-api.certinext.io/oauth/token", metavar="URL",
        help="OAuth2 token endpoint URL",
    )
    parser.add_argument(
        "--status", metavar="STATUS", default=None,
        choices=["issued", "expired"],
        help="Filter certificates by status: 'issued' (active) or 'expired'",
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

    domains = sess.domain.get_list()
    orders = sess.orders.get_list(status=args.status)
    rows = _build_rows(domains, orders)

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("(no results)")
            return
        status_label = f" ({args.status})" if args.status else ""
        print(f"Certificate counts per domain{status_label}:\n")
        print(tabulate(rows, headers="keys", tablefmt="simple"))


if __name__ == "__main__":
    main()
