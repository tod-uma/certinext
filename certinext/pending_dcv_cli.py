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
argument → OS keychain → environment variable → interactive prompt.

Usage:
    certinext-pending-dcv                                    # (installed command)
    certinext-pending-dcv --pattern ".*\\.maine\\.edu"
    certinext-pending-dcv --json
"""

import argparse
import json
import sys

from tabulate import tabulate

from certinext._cli import add_connection_args, apply_sandbox, build_session
from certinext.domains import Domain


def _show_domains(domains: list[Domain], use_json: bool) -> None:
    """Print domains as a table or as raw JSON, depending on use_json."""
    if use_json:
        print(json.dumps([d.as_dict() for d in domains], indent=2))
    else:
        if not domains:
            print("(no domains pending DCV)")
            return
        print(tabulate([d.to_row() for d in domains], headers="keys", tablefmt="simple"))


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-pending-dcv.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="List all active domains that have not completed DCV verification",
    )
    parser.add_argument(
        "--pattern", metavar="REGEX",
        help="Filter domains by regex pattern (re.fullmatch, case-insensitive)",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )
    conn = parser.add_argument_group("connection")
    add_connection_args(conn)
    return parser


def main() -> None:
    """Entry point for certinext-pending-dcv."""
    try:
        parser = build_parser()
        args = parser.parse_args()
        apply_sandbox(args)
        sess = build_session(args)

        # get_pending_dcv() uses server-side filters (ACTIVE + non-VERIFIED DCV status)
        # to minimise data transferred, then applies the optional client-side pattern.
        domains = sess.domain.get_pending_dcv(pattern=args.pattern)
        _show_domains(domains, args.json)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
