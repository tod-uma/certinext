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

"""Probe which CertiNext API paths a credential can read (GET only).

Answers "what can this credential see, and how much of it?" for the v2 and
v3 read paths that reporting and ingest depend on. For each path it records
the HTTP status, the elapsed time, the envelope's reported total, the number
of rows on the page, the envelope's top-level keys and the first row's keys.

**It prints key names and counts, never values**, so its output is safe to
paste into an issue or a transcript. Payload shapes for fixtures come from
``scripts/capture_corpus.py``, which sanitizes what it writes.

Why it exists: v3 list endpoints are scoped to the token's user, so a new
credential (e.g. a dedicated read-only user) can see less than the old one
while still answering 200. Re-running this with the new credential's keyring
profile and comparing the totals is the check.

Usage::

    uv run python scripts/probe_access.py                      # production, default profile
    uv run python scripts/probe_access.py --sandbox
    uv run python scripts/probe_access.py --profile readonly   # another credential, production
    uv run python scripts/probe_access.py --paging             # also walk paginated lists
    uv run python scripts/probe_access.py --order-details 2    # v3 orders/{id} shape per order state
    uv run python scripts/probe_access.py --json > probe.json  # machine-readable

``--order-details N`` walks the whole v3 order list, groups the rows by
(``orderStatus``, ``certificateStatus``, ``originator``), and reads N
details per group. It answers "does ``orders/{id}`` ever carry a field the
list lacks, such as history?" (on 2026-11-23 it did not, in any of the 20
production groups, although the spec's description says so). **Those three
status fields are the one exception to "never values"**: they are vendor
enums, printed in the probe labels so each shape can be tied to an order
state.

Every request is a GET. Credentials resolve like ``capture_corpus.py``:
the OS keyring profile, then ``CERTINEXT_*`` / ``CERTINEXT_SANDBOX_*``
environment variables.
"""

import argparse
import importlib.util
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx


def _load_capture_corpus() -> ModuleType:
    """Load the sibling ``capture_corpus.py`` script as a module.

    Reuses its credential resolution and raw GET helper so the two scripts
    can never disagree about which credential or base URL they use.

    Returns:
        The loaded module.
    """
    path = Path(__file__).resolve().parent / "capture_corpus.py"
    spec = importlib.util.spec_from_file_location("capture_corpus", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_cc = _load_capture_corpus()

from certinext.exceptions import CertiNextAPIError  # noqa: E402  (path set up by capture_corpus)

#: Envelope keys that carry a total count, in the order they are tried.
_TOTAL_KEYS = ("totalResults", "totalElements", "totalRecords", "totalCount", "total", "count")

#: Keys that may hold an id usable for a detail read, in preference order.
_ORDER_ID_KEYS = ("orderNumber", "orderId", "id")
_GROUP_ID_KEYS = ("groupId", "groupNumber", "id")
_ROLE_ID_KEYS = ("roleId", "id", "customRoleId")

V2 = "/api/certinext/v2"
V3 = "/api/v3/certinext"


@dataclass
class Result:
    """The outcome of one probe.

    Attributes:
        label: Human-readable probe name.
        path: Request path, with any id replaced by ``{id}``.
        params: Query parameters sent (values are probe constants, not data).
        status: HTTP status code, or ``None`` on a transport error.
        ms: Elapsed milliseconds.
        total: The envelope's reported total, when it has one.
        rows: Rows on the returned page, when the body holds a list.
        envelope_keys: Sorted top-level keys of a dict body.
        row_keys: Sorted keys of the first row.
        note: Free-form remark (error text, which id key was used, paging).
    """

    label: str
    path: str
    params: dict[str, Any] | None = None
    status: int | None = None
    ms: int = 0
    total: int | None = None
    rows: int | None = None
    envelope_keys: list[str] = field(default_factory=list)
    row_keys: list[str] = field(default_factory=list)
    note: str = ""


def find_rows(body: Any) -> list[Any] | None:
    """Return the row list in a response body, looking one wrapper deep.

    Handles a bare array, ``{"data": [...]}`` and ``{"data": {"content":
    [...]}}``-style envelopes.

    Args:
        body: The parsed JSON body.

    Returns:
        The first list found, or ``None`` when the body holds no list.
    """
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, list):
                return value
        for value in body.values():
            if isinstance(value, dict):
                for inner in value.values():
                    if isinstance(inner, list):
                        return inner
    return None


def find_total(body: Any) -> int | None:
    """Return the envelope's total-count field, looking one wrapper deep.

    Args:
        body: The parsed JSON body.

    Returns:
        The total as an int, or ``None`` when no total key is present.
    """
    if not isinstance(body, dict):
        return None
    scopes = [body] + [v for v in body.values() if isinstance(v, dict)]
    for scope in scopes:
        for key in _TOTAL_KEYS:
            value = scope.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
    return None


def first_id(rows: list[Any] | None, keys: tuple[str, ...]) -> tuple[str, Any] | None:
    """Pick an id from the first row that has one of ``keys``.

    Args:
        rows: Rows from a list body.
        keys: Candidate id keys, in preference order.

    Returns:
        ``(key, value)`` for the first match, or ``None``.
    """
    for row in rows or []:
        if isinstance(row, dict):
            for key in keys:
                if row.get(key) not in (None, ""):
                    return key, row[key]
    return None


class Prober:
    """Run GET probes against one environment and collect :class:`Result` rows.

    Args:
        client: An authenticated low-level client from ``capture_corpus``.
    """

    def __init__(self, client: Any) -> None:
        """Store the client and start an empty result list."""
        self.client = client
        self.results: list[Result] = []

    def get(
        self, label: str, path: str, params: dict[str, Any] | None = None, *, shown_path: str | None = None
    ) -> Any:
        """GET one path, record a :class:`Result`, and return the body.

        Non-2xx statuses and transport errors are recorded, not raised.

        Args:
            label: Probe name for the report.
            path: Request path.
            params: Query parameters.
            shown_path: Path to report instead of ``path`` (hides real ids).

        Returns:
            The parsed body, or ``None`` when the request failed.
        """
        result = Result(label=label, path=shown_path or path, params=params)
        start = time.monotonic()
        body: Any = None
        try:
            resp = _cc.raw_get(self.client, path, params)
            result.status = resp.status_code
            try:
                body = resp.json()
            except ValueError:
                result.note = f"non-JSON body ({len(resp.content)} bytes)"
        except CertiNextAPIError as exc:
            result.status = exc.status_code
            result.note = _short(str(exc))
        except httpx.HTTPError as exc:
            result.note = f"{type(exc).__name__}: {_short(str(exc))}"
        result.ms = int((time.monotonic() - start) * 1000)
        if body is not None:
            rows = find_rows(body)
            result.total = find_total(body)
            result.rows = len(rows) if rows is not None else None
            if isinstance(body, dict):
                result.envelope_keys = sorted(body)
            if rows and isinstance(rows[0], dict):
                result.row_keys = [shape(k, v) for k, v in sorted(rows[0].items())]
            elif isinstance(body, dict) and rows is None:
                result.row_keys = [shape(k, v) for k, v in sorted(body.items()) if isinstance(v, dict)]
        self.results.append(result)
        return body

    def detail(self, label: str, template: str, rows: list[Any] | None, keys: tuple[str, ...]) -> Any:
        """Probe a detail path once per candidate id key found in the first row.

        The vendor's list rows often carry several id-like keys and the docs
        don't say which one the detail path takes, so each is tried and
        recorded.

        Args:
            label: Probe name for the report.
            template: Path containing ``{id}``.
            rows: Rows from the list probe.
            keys: Candidate id keys.

        Returns:
            The body of the first 2xx detail read, or ``None``.
        """
        row = next((r for r in rows or [] if isinstance(r, dict)), None)
        present = [k for k in keys if row and row.get(k) not in (None, "")]
        if not present:
            self.results.append(Result(label=label, path=template, note=f"skipped: no row with {'/'.join(keys)}"))
            return None
        found: Any = None
        for key in present:
            assert row is not None
            body = self.get(f"{label} by {key}", template.format(id=row[key]), shown_path=template)
            if body is not None and found is None:
                found = body
        return found

    def walk(self, label: str, path: str, base: dict[str, Any], page_key: str, size_key: str, size: int) -> None:
        """Page through a list until a short or repeated page, and record the totals.

        Stops on a short page (the v3 orders envelope has no total), on a
        page identical to the previous one (the vendor repeats the last page
        on some endpoints), on an error, or after 200 pages.

        Args:
            label: Probe name for the report.
            path: List path.
            base: Fixed query parameters.
            page_key: Name of the page-number parameter.
            size_key: Name of the page-size parameter.
            size: Page size to request.
        """
        result = Result(label=label, path=path, params={**base, size_key: size})
        start = time.monotonic()
        seen = 0
        previous: Any = None
        pages = 0
        stop = "page cap (200)"
        for page in range(1, 201):
            try:
                resp = _cc.raw_get(self.client, path, {**base, page_key: page, size_key: size})
            except (CertiNextAPIError, httpx.HTTPError) as exc:
                stop = f"error on page {page}: {_short(str(exc))}"
                result.status = getattr(exc, "status_code", None)
                break
            result.status = resp.status_code
            rows = find_rows(resp.json()) or []
            if rows and rows == previous:
                stop = f"page {page} repeated page {page - 1}"
                break
            pages += 1
            seen += len(rows)
            previous = rows
            if len(rows) < size:
                stop = f"short page {page} ({len(rows)} rows)"
                break
        result.ms = int((time.monotonic() - start) * 1000)
        result.rows = seen
        result.note = f"{pages} pages; stopped: {stop}"
        self.results.append(result)

    def order_details(self, per_group: int) -> None:
        """Read v3 ``orders/{id}`` for ``per_group`` orders of every order state.

        Walks every page of the v3 order list, groups rows by
        (``orderStatus``, ``certificateStatus``, ``originator``), and probes
        the detail path by ``orderId`` for the first ``per_group`` orders of
        each group, largest group first. Each detail result records every
        top-level key's shape (not only the nested ones :meth:`get` keeps),
        and its note gives the group's size and any key the list row lacks.

        Args:
            per_group: Detail reads per group; values below 1 do nothing.
        """
        if per_group < 1:
            return
        rows: list[dict[str, Any]] = []
        for page in range(1, 201):
            try:
                resp = _cc.raw_get(self.client, f"{V3}/orders", {"pageNumber": page, "pageSize": 100})
            except (CertiNextAPIError, httpx.HTTPError) as exc:
                self.results.append(Result(label="v3 order details", path=f"{V3}/orders",
                                           note=f"list failed on page {page}: {_short(str(exc))}"))
                return
            batch = [r for r in find_rows(resp.json()) or [] if isinstance(r, dict)]
            rows.extend(batch)
            if len(batch) < 100:
                break
        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for row in rows:
            key = (str(row.get("orderStatus")), str(row.get("certificateStatus")), str(row.get("originator")))
            groups.setdefault(key, []).append(row)
        template = f"{V3}/orders/{{id}}"
        for (order_status, cert_status, originator), members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            for row in [r for r in members if r.get("orderId")][:per_group]:
                label = f"v3 order detail [{order_status} / {cert_status} / {originator}]"
                body = self.get(label, template.format(id=row["orderId"]), shown_path=template)
                result = self.results[-1]
                if isinstance(body, dict):
                    result.row_keys = [shape(k, v) for k, v in sorted(body.items())]
                    extra = sorted(set(body) - set(row))
                    result.note = f"group of {len(members)}; not in list row: {', '.join(extra) or 'none'}"
                else:
                    result.note = f"group of {len(members)}; {result.note}".rstrip("; ")


def shape(key: str, value: Any, depth: int = 0) -> str:
    """Describe a JSON value's structure by key names only, never values.

    ``group{groupId,groupName}`` for an object, ``tags[]`` for a list of
    scalars, ``flags[{a,b}]`` for a list of objects; nesting stops two
    levels down.

    Args:
        key: The key the value sits under.
        value: The JSON value.
        depth: Current nesting depth.

    Returns:
        The shape string.
    """
    if isinstance(value, dict) and depth < 2:
        return f"{key}{{{','.join(shape(k, v, depth + 1) for k, v in sorted(value.items()))}}}"
    if isinstance(value, list):
        item = next((i for i in value if i is not None), None)
        if isinstance(item, dict) and depth < 2:
            return f"{key}[{{{','.join(shape(k, v, depth + 1) for k, v in sorted(item.items()))}}}]"
        return f"{key}[]"
    return key


def _short(text: str, limit: int = 120) -> str:
    """Collapse whitespace and truncate an error message for the table."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def run(prober: Prober, *, audit_days: int, paging: bool, order_details: int = 0) -> None:
    """Run the full probe set.

    Args:
        prober: The prober to record into.
        audit_days: Width of the audit-log window, in days, ending now.
        paging: Also walk paginated lists to count every row.
        order_details: Detail reads per v3 order state; 0 skips them.
    """
    p = prober
    # v2 baseline: the paths the library already wraps.
    p.get("v2 auth/me", f"{V2}/auth/me")
    p.get("v2 reports/orders", f"{V2}/reports/orders", {"page": 1, "size": 100})
    p.get("v2 domains", f"{V2}/domains", {"limit": 100, "offset": 0})
    p.get("v2 organizations", f"{V2}/organizations")
    groups_v2 = p.get("v2 groups", f"{V2}/groups")
    p.get("v2 reports/ledger", f"{V2}/reports/ledger", {"page": 1, "size": 100})

    # v3 orders.
    orders = p.get("v3 orders", f"{V3}/orders", {"pageNumber": 1, "pageSize": 100})
    p.detail("v3 orders/{id}", f"{V3}/orders/{{id}}", find_rows(orders), _ORDER_ID_KEYS)

    # v3 audit logs: server default window, then an explicit one.
    p.get("v3 audit-logs (default)", f"{V3}/audit-logs", {"pageNumber": 1, "pageSize": 100})
    now = datetime.now(timezone.utc)
    window = {
        "pageNumber": 1,
        "pageSize": 100,
        "fromDate": (now - timedelta(days=audit_days)).strftime("%Y-%m-%d"),
        "toDate": now.strftime("%Y-%m-%d"),
    }
    p.get(f"v3 audit-logs ({audit_days}d)", f"{V3}/audit-logs", window)
    # Control: a ten-year window should match the unfiltered total. If it
    # returns 0 instead, the server is rejecting the date format silently.
    wide = {**window, "fromDate": (now - timedelta(days=3650)).strftime("%Y-%m-%d")}
    p.get("v3 audit-logs (3650d control)", f"{V3}/audit-logs", wide)
    p.get("v3 audit-logs/modules", f"{V3}/audit-logs/modules")

    # v3 users, roles, groups, API credentials.
    users = p.get("v3 users", f"{V3}/users", {"pageNumber": 1, "recordLimit": 100})
    p.get("v3 users/detailed", f"{V3}/users/detailed")
    roles = p.get("v3 users/roles", f"{V3}/users/roles", {"pageNumber": 1, "recordLimit": 100})
    p.detail("v3 users/roles/{id}/permissions", f"{V3}/users/roles/{{id}}/permissions", find_rows(roles), _ROLE_ID_KEYS)
    p.get("v3 users/groups/members (no params)", f"{V3}/users/groups/members")
    user_rows = [r for r in find_rows(users) or [] if isinstance(r, dict)]
    candidates: list[tuple[str, str, Any]] = []
    v3_group = first_id([r["group"] for r in user_rows if isinstance(r.get("group"), dict)], _GROUP_ID_KEYS)
    if v3_group:
        candidates.append(("groupId", f"v3 user group.{v3_group[0]}", v3_group[1]))
    v2_group = first_id(find_rows(groups_v2), _GROUP_ID_KEYS)
    if v2_group:
        candidates.append(("groupId", f"v2 group {v2_group[0]}", v2_group[1]))
    v3_user = first_id(user_rows, ("userId", "id"))
    if v3_user:
        candidates.append(("userIds", f"v3 user {v3_user[0]}", v3_user[1]))
    for param, source, value in candidates:
        p.get(
            f"v3 users/groups/members ({param} from {source})", f"{V3}/users/groups/members", {param: value},
            shown_path=f"{V3}/users/groups/members",
        )
        p.results[-1].params = {param: "{id}"}
    p.get("v3 apis", f"{V3}/apis", {"pageNumber": 1, "pageSize": 100})
    p.get("v3 reports/certificates", f"{V3}/reports/certificates")
    p.get("v3 discovery/certificates", f"{V3}/discovery/certificates", {"pageNumber": 1, "pageSize": 100})

    if paging:
        p.walk("v3 orders (all pages)", f"{V3}/orders", {}, "pageNumber", "pageSize", 100)
        p.walk("v3 users (all pages)", f"{V3}/users", {}, "pageNumber", "recordLimit", 20)
        p.walk("v3 apis (all pages)", f"{V3}/apis", {}, "pageNumber", "pageSize", 20)
        p.walk(f"v3 audit-logs ({audit_days}d, all pages)", f"{V3}/audit-logs",
               {k: v for k, v in window.items() if k not in ("pageNumber", "pageSize")},
               "pageNumber", "pageSize", 100)

    prober.order_details(order_details)


def render(results: list[Result], env: str, profile: str | None) -> str:
    """Render results as a Markdown report.

    Args:
        results: Probe results.
        env: ``prod`` or ``sandbox``.
        profile: Keyring profile used, or ``None`` for the default.

    Returns:
        The report text.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# CertiNext access probe: {env}, profile {profile or 'default'}, {stamp}",
        "",
        "| Probe | Status | ms | Total | Rows | Note |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        cells = [r.label, str(r.status or "-"), str(r.ms), _cell(r.total), _cell(r.rows), r.note.replace("|", "/")]
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "## Shapes (key names only)", ""]
    for r in results:
        if r.envelope_keys or r.row_keys:
            lines.append(f"- **{r.label}**: envelope `{', '.join(r.envelope_keys) or '(list)'}`"
                         + (f"; row `{', '.join(r.row_keys)}`" if r.row_keys else ""))
    return "\n".join(lines) + "\n"


def _cell(value: int | None) -> str:
    """Format an optional count for the table."""
    return "-" if value is None else f"{value:,}"


def main() -> None:
    """Entry point: parse args, probe one environment, print the report."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--sandbox", action="store_true", help="probe the sandbox instead of production")
    parser.add_argument("--profile", default=None, help="keyring profile holding the credential to probe with")
    parser.add_argument("--audit-days", type=int, default=7, help="audit-log window in days (default: %(default)s)")
    parser.add_argument("--paging", action="store_true", help="also walk paginated lists to count every row")
    parser.add_argument(
        "--order-details", type=int, default=0, metavar="N",
        help="read N v3 orders/{id} details per order state (default: %(default)s, off)",
    )
    parser.add_argument("--json", action="store_true", help="print results as JSON instead of Markdown")
    args = parser.parse_args()

    env = "sandbox" if args.sandbox else "prod"
    client = _cc.build_client(args.sandbox, args.profile)
    print(f"Probing {env} (GET only)…", file=sys.stderr)
    prober = Prober(client)
    run(prober, audit_days=args.audit_days, paging=args.paging, order_details=args.order_details)
    if args.json:
        print(json.dumps([asdict(r) for r in prober.results], indent=2))
    else:
        print(render(prober.results, env, args.profile))


if __name__ == "__main__":
    main()
