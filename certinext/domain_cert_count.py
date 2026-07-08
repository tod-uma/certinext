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

"""Per-domain certificate counting: join registered domains with order records.

Operations layer for ``certinext domain-cert-count`` — the CLI command in
:mod:`certinext.cli` only parses options and renders the rows built here, so
other frontends can reuse the join logic directly.
"""

from collections import Counter

from certinext.domains import Domain
from certinext.orders import OrderRecord


def match_domain(cn: str, registered: set[str]) -> str | None:
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


def apex_domain(domain: str, registered: set[str]) -> str:
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


def build_rows(
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
        matched = match_domain(cn, registered)
        if matched is None:
            orphan_counts[cn] += 1
        elif condense:
            domain_counts[apex_domain(matched, registered)] += 1
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
