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
    certinext-domain-cert-count --condense
    certinext-domain-cert-count --json
"""

import argparse
import json
import sys
from collections import Counter

from tabulate import tabulate

from certinext._cli import add_connection_args, apply_sandbox, build_session
from certinext.domains import Domain
from certinext.orders import OrderRecord


def _match_domain(cn: str, registered: set[str]) -> str | None:
    """Return the most specific registered domain that a certificate CN belongs to.

    Caller is responsible for lowercasing ``cn`` before calling this function.
    Tries an exact match first, then finds all registered domains that are
    proper suffixes of ``cn`` (i.e. ``cn`` ends with ``.<domain>``), returning
    the longest (most specific) match.

    Args:
        cn: Lowercase certificate common name to look up.
        registered: Set of lowercase registered domain names.

    Returns:
        The matching registered domain name (lowercase), or ``None`` if no
        registered domain is an exact match or suffix of ``cn``.
    """
    if cn in registered:
        return cn
    matches = [d for d in registered if cn.endswith(f".{d}")]
    return max(matches, key=len) if matches else None


def _apex_domain(domain: str, registered: set[str]) -> str:
    """Return the topmost registered ancestor of a domain.

    Walks up the registered-domain tree until it finds an entry that has no
    registered parent (i.e. no other registered domain is a suffix of it).
    Used by ``--condense`` to roll all subdomain counts into their apex.

    Caller is responsible for ensuring ``domain`` is already in ``registered``
    and is lowercase.

    Args:
        domain: Lowercase domain name to resolve upward.
        registered: Set of lowercase registered domain names.

    Returns:
        The topmost registered ancestor (which may be ``domain`` itself if it
        has no registered parent).
    """
    current = domain
    while True:
        parents = [d for d in registered if current.endswith(f".{d}")]
        if not parents:
            return current
        current = max(parents, key=len)


def _build_rows(
    domains: list[Domain],
    orders: list[OrderRecord],
    condense: bool = False,
) -> list[dict[str, str]]:
    """Join domains and orders into a sorted list of display rows.

    Each certificate CN is matched to the most specific (longest) registered
    domain that is a suffix of the CN. A cert for ``host.noc.maine.edu``
    counts toward ``noc.maine.edu`` when that domain is registered, rather
    than the less-specific ``maine.edu``.

    When ``condense=True``, only apex (top-level) registered domains are
    shown — domains that have no registered parent. Counts are the sum of
    all certs that match any domain in that apex's subtree.

    Orders whose CN does not fall under any registered domain are appended at
    the end, flagged with ``(not registered)``.

    Args:
        domains: Registered domain objects from the Domains API.
        orders: Order records from the Orders Report API.
        condense: If ``True``, collapse subdomains into their apex and hide
            subdomain rows.

    Returns:
        List of dicts with keys ``domain``, ``certificates``.
    """
    registered: set[str] = {(d.name or "").lower() for d in domains}

    domain_counts: Counter[str] = Counter()
    orphan_counts: Counter[str] = Counter()
    for o in orders:
        if not o.common_name:
            continue
        cn = o.common_name.lower()
        matched = _match_domain(cn, registered)
        if matched is None:
            orphan_counts[cn] += 1
        elif condense:
            domain_counts[_apex_domain(matched, registered)] += 1
        else:
            domain_counts[matched] += 1

    rows: list[dict[str, str]] = []
    if condense:
        apex_keys = sorted(d for d in registered if not any(d.endswith(f".{p}") for p in registered))
        name_map = {(d.name or "").lower(): d.name or "" for d in domains}
        for key in apex_keys:
            rows.append({"domain": name_map.get(key, key), "certificates": str(domain_counts.get(key, 0))})
    else:
        for d in sorted(domains, key=lambda x: x.name or ""):
            key = (d.name or "").lower()
            rows.append({"domain": d.name or "", "certificates": str(domain_counts.get(key, 0))})

    for cn, count in sorted(orphan_counts.items()):
        rows.append({"domain": f"{cn} (not registered)", "certificates": str(count)})

    return rows


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for certinext-domain-cert-count.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Show all registered domains and their certificate counts",
    )
    parser.add_argument(
        "--status", metavar="STATUS", default=None,
        choices=["issued", "expired"],
        help="Filter certificates by status: 'issued' (active) or 'expired'",
    )
    parser.add_argument(
        "--condense", action="store_true", default=False,
        help="Show only top-level domains; subdomain counts roll up into their apex",
    )
    parser.add_argument(
        "--json", action="store_true", default=False,
        help="Output raw JSON instead of tabular format",
    )
    conn = parser.add_argument_group("connection")
    add_connection_args(conn)
    return parser


def main() -> None:
    """Entry point for certinext-domain-cert-count."""
    try:
        parser = build_parser()
        args = parser.parse_args()
        apply_sandbox(args)
        sess = build_session(args)

        domains = sess.domain.get_list()
        orders = sess.orders.get_list(status=args.status)
        rows = _build_rows(domains, orders, condense=args.condense)

        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            if not rows:
                print("(no results)")
                return
            status_label = f" ({args.status})" if args.status else ""
            print(f"Certificate counts per domain{status_label}:\n")
            print(tabulate(rows, headers="keys", tablefmt="simple"))
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
