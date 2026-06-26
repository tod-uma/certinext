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

"""Show DCV status and expiry for all parent (top-level) CertiNext domains.

Lists every domain in the account that cannot rely on DCV propagating from a
parent — either because it has no registered ancestor in the account, or
because it has its own NS records (a DNS zone boundary) that block DCV
inheritance.  These are the domains that must be validated directly.

By default a DNS NS lookup is performed for each domain to detect zone
boundaries (requires dnspython: pip install certinext[dns]).  Use
``--no-ns-check`` to skip DNS lookups and list only account-level parents.

Usage::

    certinext-parent-dcv-status
    certinext-parent-dcv-status --no-ns-check
    certinext-parent-dcv-status --status expiring
    certinext-parent-dcv-status --status expiring --expiring-days 60
    certinext-parent-dcv-status --status expired
    certinext-parent-dcv-status --pattern r".*\\.maine\\.edu"
    certinext-parent-dcv-status --json
    certinext-parent-dcv-status --sandbox
"""

import argparse
import json
import sys
from datetime import datetime, timezone

import structlog
from tabulate import tabulate

from certinext._cli import _setup_logging, add_connection_args, apply_sandbox, build_session
from certinext.domains import Domain

log = structlog.get_logger()

_STATUS_CHOICES = ("all", "verified", "expiring", "pending", "expired")


def _days_until(dt: datetime) -> int:
    """Return calendar days from now until dt (negative if already past).

    Args:
        dt: A timezone-aware datetime to compare against the current UTC time.

    Returns:
        Integer days remaining; negative when dt is in the past.
    """
    return (dt - datetime.now(timezone.utc)).days


def _status_category(domain: Domain, expiring_days: int) -> str:
    """Return the status category string for a domain used for ``--status`` filtering.

    Categories:

    - ``"verified"``  — DCV is ``VERIFIED`` and not expiring within *expiring_days*.
    - ``"expiring"``  — DCV is ``VERIFIED`` but expires within *expiring_days*.
    - ``"expired"``   — DCV status is ``EXPIRED``.
    - ``"pending"``   — DCV status is ``PENDING``, ``REJECTED``, or unknown.

    Args:
        domain: The domain to categorise.
        expiring_days: Threshold in days for the ``"expiring"`` category.

    Returns:
        One of ``"verified"``, ``"expiring"``, ``"expired"``, or ``"pending"``.
    """
    status = domain.dcv_status or ""
    if status == "VERIFIED":
        return "expiring" if domain.dcv_expires_soon(expiring_days) else "verified"
    if status == "EXPIRED":
        return "expired"
    return "pending"


def _build_row(domain: Domain, expiring_days: int) -> dict[str, str]:
    """Build a tabular display row for one parent domain.

    Args:
        domain: The domain to display.
        expiring_days: Threshold used to add the ``⚠`` warning to ``expires_in``.

    Returns:
        Dict with ``domain``, ``dcv_status``, ``expires``, and ``expires_in`` keys.
    """
    exp = domain.dcv_expires
    if exp is None:
        expires_str = "-"
        expires_in_str = "-"
    else:
        expires_str = exp.strftime("%Y-%m-%d")
        days = _days_until(exp)
        if days < 0:
            expires_in_str = "EXPIRED"
        elif days <= expiring_days:
            expires_in_str = f"{days}d !"
        else:
            expires_in_str = f"{days}d"

    return {
        "domain": domain.name or "(unknown)",
        "dcv_status": domain.dcv_status or "-",
        "expires": expires_str,
        "expires_in": expires_in_str,
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-parent-dcv-status.

    Returns:
        A configured :class:`argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Show DCV status and expiry for domains that require direct DCV validation. "
            "Includes account-level parents (no registered ancestor) and, by default, "
            "zone-boundary subdomains whose NS records block DCV inheritance from a parent."
        ),
    )
    parser.add_argument(
        "--pattern", metavar="REGEX",
        help="Filter domains by regex before identifying parents (re.fullmatch, case-insensitive)",
    )
    parser.add_argument(
        "--status",
        choices=_STATUS_CHOICES,
        default="all",
        metavar="STATUS",
        help=(
            "Filter output by DCV status category: "
            "all (default), verified, expiring, pending, expired"
        ),
    )
    parser.add_argument(
        "--expiring-days", type=int, default=30, metavar="DAYS",
        help=(
            "Number of days ahead to flag a domain as expiring soon "
            "(used by --status expiring and the ! indicator; default: 30)"
        ),
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )
    parser.add_argument(
        "--no-ns-check", action="store_true", default=False,
        help=(
            "Skip DNS NS lookups when identifying domains that need direct DCV. "
            "By default NS records are checked so zone-boundary subdomains "
            "(those with their own NS records) are included even when a parent "
            "domain is registered. Requires dnspython (pip install certinext[dns])."
        ),
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count", default=0,
        help=(
            "Increase verbosity: -v shows progress, "
            "-vvv enables debug logging, "
            "-vvvv also enables third-party debug logging (urllib3)"
        ),
    )
    conn = parser.add_argument_group("connection")
    add_connection_args(conn)
    return parser


def main() -> None:
    """Entry point for certinext-parent-dcv-status."""
    try:
        parser = build_parser()
        args = parser.parse_args()
        _setup_logging(args.verbose)
        apply_sandbox(args)
        sess = build_session(args)

        log.info("Fetching domain list")
        domains = sess.domain.get_list(pattern=args.pattern)
        log.info("Fetched domains", count=len(domains))

        all_names = {d.name for d in domains if d.name}

        # Find every domain that needs direct DCV: no registered ancestor, OR
        # a registered ancestor exists but NS records block DCV inheritance.
        # check_ns=True (default) catches zone-boundary subdomains; --no-ns-check
        # limits the list to account-level parents only.
        check_ns = not args.no_ns_check
        if check_ns:
            log.info("Checking DNS NS records to detect zone boundaries...")
        parents = sorted(
            (d for d in domains if d.dcv_covering_parent(all_names, check_ns=check_ns) is None),
            key=lambda d: d.name or "",
        )
        log.info(
            "Found domains requiring direct DCV",
            count=len(parents),
            scope="including zone-boundary subdomains" if check_ns else "account-level parents only",
        )

        # Only VERIFIED domains have a validTill expiry date — skip the detail
        # fetch for PENDING/EXPIRED/REJECTED domains to avoid unnecessary API calls.
        verified = [d for d in parents if d.dcv_status == "VERIFIED"]
        log.info("Fetching details for expiry dates", count=len(verified))
        use_dots = args.verbose < 3 and sys.stderr.isatty() and len(verified) > 0
        if use_dots:
            print("  ", end="", file=sys.stderr, flush=True)
        for i, d in enumerate(verified, 1):
            log.debug("Fetching domain details", index=i, total=len(verified), domain=d.name)
            d.refresh()
            if use_dots:
                print(".", end="", file=sys.stderr, flush=True)
        if use_dots:
            print(file=sys.stderr)
        log.info("Details fetched")

        if args.status != "all":
            parents = [
                d for d in parents
                if _status_category(d, args.expiring_days) == args.status
            ]

        if args.json:
            output = [
                {
                    "domain": d.name,
                    "dcv_status": d.dcv_status,
                    "dcv_expires": d.dcv_expires.isoformat() if d.dcv_expires else None,
                    "expiring_soon": d.dcv_expires_soon(args.expiring_days),
                }
                for d in parents
            ]
            print(json.dumps(output, indent=2))
        else:
            label = f" ({args.status})" if args.status != "all" else ""
            if not parents:
                print(f"(no parent domains{label})")
                return
            print(f"Parent domains{label}:\n")
            print(tabulate(
                [_build_row(d, args.expiring_days) for d in parents],
                headers="keys",
                tablefmt="simple",
            ))
            print(
                f"\n{len(parents)} domain(s)"
                f"  [! = expiring within {args.expiring_days} days]"
            )
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
