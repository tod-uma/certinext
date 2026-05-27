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

"""List SSL/TLS certificate orders from the CertiNext orders report.

Fetches all orders with automatic pagination and displays them in tabular
format. Use ``--status`` to filter by certificate lifecycle status.

Usage:
    certinext-list-certificates
    certinext-list-certificates --status issued
    certinext-list-certificates --status expired
    certinext-list-certificates --status pending-dcv
    certinext-list-certificates --sandbox
    certinext-list-certificates --json
"""

import argparse
import json
import sys

from tabulate import tabulate

from certinext._cli import add_connection_args, apply_sandbox, build_session


def main() -> None:
    """Entry point for certinext-list-certificates."""
    try:
        parser = argparse.ArgumentParser(
            description="List SSL/TLS certificate orders",
        )
        add_connection_args(parser)
        parser.add_argument(
            "--status", metavar="STATUS", default=None,
            help=(
                "Filter by certificate status "
                "(e.g. issued, expired, pending-dcv, pending-csr, revoked, cancelled)"
            ),
        )
        parser.add_argument(
            "--json", action="store_true", default=False,
            help="Output raw JSON instead of tabular format",
        )
        args = parser.parse_args()
        apply_sandbox(args)
        sess = build_session(args)

        orders = sess.orders.get_list(status=args.status)

        if args.json:
            print(json.dumps([o.as_dict() for o in orders], indent=2))
            return

        if not orders:
            label = f" with status '{args.status}'" if args.status else ""
            print(f"(no certificates{label})")
            return

        status_label = f" ({args.status})" if args.status else ""
        print(f"Certificates{status_label}:\n")
        print(tabulate([o.to_row() for o in orders], headers="keys", tablefmt="simple"))
        print(f"\n{len(orders)} certificate(s)")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
