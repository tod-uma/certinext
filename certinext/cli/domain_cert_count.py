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

"""``certinext domain-cert-count`` — thin wrapper over :mod:`certinext.domain_cert_count`."""

import json
from enum import Enum
from typing import Optional

import typer

from certinext.cli._app import app
from certinext.cli._shared import data_console, rows_table, session
from certinext.domain_cert_count import build_rows


class _CertStatus(str, Enum):
    """The order statuses ``--status`` accepts (0.3.x argparse choices)."""

    issued = "issued"
    expired = "expired"


@app.command()
def domain_cert_count(
    ctx: typer.Context,
    status: Optional[_CertStatus] = typer.Option(
        None, "--status", metavar="STATUS",
        help="Filter certificates by status: 'issued' (active) or 'expired'",
    ),
    condense: bool = typer.Option(
        False, "--condense",
        help="Show only top-level domains; subdomain counts roll up into their apex",
    ),
) -> None:
    """Show all registered domains and their certificate counts."""
    sess = session(ctx)

    domains = sess.domain.get_list()
    orders = sess.orders.get_list(status=status.value if status else None)
    rows = build_rows(domains, orders, condense=condense)

    if ctx.obj.output_json:
        print(json.dumps(rows, indent=2))
        return

    if not rows:
        print("(no results)")
        return

    status_label = f" ({status.value})" if status else ""
    print(f"Certificate counts per domain{status_label}:\n")
    data_console().print(rows_table(rows))
