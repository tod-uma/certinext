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

"""``certinext list-certificates`` — list SSL/TLS certificate orders."""

import json
from typing import Optional

import structlog
import typer

from certinext.cli._app import app
from certinext.cli._shared import data_console, rows_table, session
from certinext.exceptions import CertiNextAPIError
from certinext.session import CertiNextSession

log = structlog.get_logger()


def _ca_map(sess: CertiNextSession) -> dict[str, str]:
    """Return product code → CA from one catalog read, or ``{}`` if it fails.

    The CA column is a convenience; a catalog outage must not hide the
    certificate list itself.

    Args:
        sess: An authenticated session.

    Returns:
        The :meth:`~certinext.catalog.CatalogAccessor.ca_by_product_code`
        map, or an empty dict after logging a warning.
    """
    try:
        return sess.catalog.ca_by_product_code()
    except CertiNextAPIError as exc:
        log.warning("catalog read failed; CA column left blank", status_code=exc.status_code)
        return {}


@app.command()
def list_certificates(
    ctx: typer.Context,
    status: Optional[str] = typer.Option(
        None, "--status", metavar="STATUS",
        help=(
            "Filter by certificate status "
            "(e.g. issued, expired, pending-dcv, pending-csr, revoked, cancelled)"
        ),
    ),
) -> None:
    """List SSL/TLS certificate orders from the CertiNext orders report.

    The ``ca`` column (and JSON key) names the issuing CA, joined from each
    order's product code through the catalog: the issuer name can't tell,
    because emSign issues from InCommon-branded intermediates.
    """
    sess = session(ctx)

    orders = sess.orders.get_list(status=status)
    cas = _ca_map(sess) if orders else {}

    def _ca(product_code: str | None) -> str:
        return cas.get(product_code or "", "")

    if ctx.obj.output_json:
        print(json.dumps([{**o.as_dict(), "ca": _ca(o.product_code)} for o in orders], indent=2))
        return

    if not orders:
        label = f" with status '{status}'" if status else ""
        print(f"(no certificates{label})")
        return

    status_label = f" ({status})" if status else ""
    print(f"Certificates{status_label}:\n")
    data_console().print(rows_table([{**o.to_row(), "ca": _ca(o.product_code)} for o in orders]))
    print(f"\n{len(orders)} certificate(s)")
