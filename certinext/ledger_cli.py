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

"""Show the CertiNext account ledger (transaction history).

Fetches all ledger records with automatic pagination and displays them in
tabular format. Use ``--last N`` to limit output to the most recent N
transactions, or ``--json`` for machine-readable output.

Usage:
    certinext-ledger
    certinext-ledger --sandbox
    certinext-ledger --last 20
    certinext-ledger --json
"""

import argparse
import json
import sys

from tabulate import tabulate

from certinext._cli import add_connection_args, apply_sandbox, build_session


def main() -> None:
    """Entry point for certinext-ledger."""
    try:
        parser = argparse.ArgumentParser(
            description="Show CertiNext account ledger (transaction history)",
        )
        add_connection_args(parser)
        parser.add_argument(
            "--last", metavar="N", type=int, default=None,
            help="Show only the N most recent transactions",
        )
        parser.add_argument(
            "--json", action="store_true", default=False,
            help="Output raw JSON instead of tabular format",
        )
        args = parser.parse_args()
        apply_sandbox(args)
        sess = build_session(args)

        records = sess.ledger.get_list()

        if args.last is not None:
            records = records[-args.last:]

        if args.json:
            print(json.dumps([r.as_dict() for r in records], indent=2))
            return

        if not records:
            print("(no ledger records)")
            return

        rows = [r.to_row() for r in records]
        print(tabulate(rows, headers="keys", tablefmt="simple"))
        print(f"\n{len(records)} transaction(s)")
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
