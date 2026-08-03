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

"""``certinext parent-dcv-status`` — DCV status/expiry for parent (top-level) domains.

Lists every domain in the account that cannot rely on DCV propagating from a
parent — either because it has no registered ancestor in the account, or
because it has its own NS records (a DNS zone boundary) that block DCV
inheritance. These are the domains that must be validated directly.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import structlog
import typer
from rich.progress import Progress

from certinext.cli._app import app
from certinext.cli._shared import (
    AccountNumberOption,
    BaseUrlOption,
    ClientSecretOption,
    JsonOption,
    LogFormatOption,
    ProfileOption,
    SandboxOption,
    TokenUrlOption,
    VerboseOption,
    connect,
    data_console,
    err_console,
    progress_disabled,
    rows_table,
)
from certinext.cli_support import LogFormat, setup_logging
from certinext.domains import Domain

log = structlog.get_logger()


class _StatusFilter(str, Enum):
    """The DCV status categories ``--status`` accepts (0.3.x argparse choices)."""

    all = "all"
    verified = "verified"
    expiring = "expiring"
    pending = "pending"
    expired = "expired"


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
        expiring_days: Threshold used to add the ``!`` warning to ``expires_in``.

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


@app.command()
def parent_dcv_status(
    pattern: Optional[str] = typer.Option(
        None, "--pattern", metavar="REGEX",
        help="Filter domains by regex before identifying parents (re.fullmatch, case-insensitive)",
    ),
    status: _StatusFilter = typer.Option(
        _StatusFilter.all, "--status", metavar="STATUS",
        help=(
            "Filter output by DCV status category: "
            "all (default), verified, expiring, pending, expired"
        ),
    ),
    expiring_days: int = typer.Option(
        30, "--expiring-days", metavar="DAYS",
        help=(
            "Number of days ahead to flag a domain as expiring soon "
            "(used by --status expiring and the ! indicator; default: 30)"
        ),
    ),
    output_json: JsonOption = False,
    no_ns_check: bool = typer.Option(
        False, "--no-ns-check",
        help=(
            "Skip DNS NS lookups when identifying domains that need direct DCV. "
            "By default NS records are checked so zone-boundary subdomains "
            "(those with their own NS records) are included even when a parent "
            "domain is registered. Requires dnspython (pip install certinext[dns])."
        ),
    ),
    verbose: VerboseOption = 0,
    log_format: LogFormatOption = LogFormat.LOGFMT,
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
) -> None:
    """Show DCV status and expiry for domains that require direct DCV validation.

    Includes account-level parents (no registered ancestor) and, by default,
    zone-boundary subdomains whose NS records block DCV inheritance from a parent.
    """
    setup_logging(verbose, log_format=log_format)
    sess = connect(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret,
    )

    log.info("Fetching domain list")
    domains = sess.domain.get_list(pattern=pattern)
    log.info("Fetched domains", count=len(domains))

    # Find every domain that needs direct DCV: no registered ancestor, OR
    # a registered ancestor exists but NS records block DCV inheritance.
    # check_ns=True (default) catches zone-boundary subdomains; --no-ns-check
    # limits the list to account-level parents only.
    check_ns = not no_ns_check
    if check_ns:
        log.info("Checking DNS NS records to detect zone boundaries...")
        with Progress(console=err_console, disable=progress_disabled(verbose)) as progress:
            task = progress.add_task("Checking DNS NS records", total=len(domains))

            def _needs_direct_dcv(d: Domain) -> bool:
                progress.advance(task)
                return d.dcv_covering_parent(domains, check_ns=True) is None

            parents = sorted(
                (d for d in domains if _needs_direct_dcv(d)),
                key=lambda d: d.name or "",
            )
    else:
        parents = sorted(
            (d for d in domains if d.dcv_covering_parent(domains, check_ns=False) is None),
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
    with Progress(console=err_console, disable=progress_disabled(verbose)) as progress:
        task = progress.add_task("Fetching domain details", total=len(verified))
        for d in verified:
            log.debug("Fetching domain details", domain=d.name)
            d.refresh()
            progress.advance(task)
    log.info("Details fetched")

    if status is not _StatusFilter.all:
        parents = [
            d for d in parents
            if _status_category(d, expiring_days) == status.value
        ]

    if output_json:
        output = [
            {
                "domain": d.name,
                "dcv_status": d.dcv_status,
                "dcv_expires": d.dcv_expires.isoformat() if d.dcv_expires else None,
                "expiring_soon": d.dcv_expires_soon(expiring_days),
            }
            for d in parents
        ]
        print(json.dumps(output, indent=2))
        return

    label = f" ({status.value})" if status is not _StatusFilter.all else ""
    if not parents:
        print(f"(no parent domains{label})")
        return
    print(f"Parent domains{label}:\n")
    data_console().print(rows_table([_build_row(d, expiring_days) for d in parents]))
    print(
        f"\n{len(parents)} domain(s)"
        f"  [! = expiring within {expiring_days} days]"
    )
