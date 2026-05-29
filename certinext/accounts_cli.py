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

"""Show account info, groups, and organizations for a CertiNext account.

Displays the current account details, billing groups, and pre-vetted
organizations in tabular format. Use ``--json`` for machine-readable output.

Usage:
    certinext-accounts
    certinext-accounts --sandbox
    certinext-accounts --json
"""

import argparse
import json
import sys

from tabulate import tabulate

from certinext._cli import add_connection_args, apply_sandbox, build_session


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-accounts.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Show account info, groups, and organizations",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )
    conn = parser.add_argument_group("connection")
    add_connection_args(conn)
    return parser


def main() -> None:
    """Entry point for certinext-accounts."""
    try:
        parser = build_parser()
        args = parser.parse_args()
        apply_sandbox(args)
        sess = build_session(args)

        me = sess.accounts.me()
        groups = sess.accounts.list_groups()
        orgs = sess.accounts.list_organizations()

        if args.json:
            output = {
                "account": me.as_dict(),
                "groups": [g.as_dict() for g in groups],
                "organizations": [o.as_dict() for o in orgs],
            }
            print(json.dumps(output, indent=2))
            return

        print("Account:")
        print(f"  Number : {me.account_number or '(unknown)'}")
        print(f"  Name   : {me.account_name or '(unknown)'}")
        print(f"  Type   : {me.account_type or '(unknown)'}")

        print()
        if groups:
            print("Groups:\n")
            print(tabulate(
                [{"group_number": g.group_number or "", "group_name": g.group_name or ""} for g in groups],
                headers="keys",
                tablefmt="simple",
            ))
        else:
            print("Groups: (none)")

        print()
        if orgs:
            print("Organizations:\n")
            org_rows = [
                {
                    "number": o.organization_number or "",
                    "name": o.organization_name or "",
                    "locality": o.locality or "",
                    "country": o.country_code or "",
                    "status": o.status_id or "",
                }
                for o in orgs
            ]
            print(tabulate(org_rows, headers="keys", tablefmt="simple"))
        else:
            print("Organizations: (none)")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
