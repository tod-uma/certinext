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

"""``certinext ca-validation`` — show an organization's SSL.com (non-emSign CA) validation.

Read-only by default. ``--sync`` asks CertiNext to re-read the status from
the CA, which changes only CertiNext's cached copy. Submitting an
organization for vetting stays library-only
(:meth:`~certinext.accounts.AccountAccessor.submit_ca_validation`).

The output never includes the ``readiness`` block's contact name, phone or
email: JSON is built from the model's fields, not the raw payload.
"""

import json
from typing import Any

import typer

from certinext.cli._app import app
from certinext.cli._shared import data_console, pairs_table, rows_table, session
from certinext.models.accounts import OrgCaValidation


def _summary(val: OrgCaValidation) -> dict[str, Any]:
    """Return the PII-free, JSON-safe view of a CA validation.

    Args:
        val: The validation to summarise.

    Returns:
        The model fields plus the readiness flags and missing-item lists.
    """
    data = val.model_dump(mode="json")
    data.update(
        ready=val.ready,
        ev_ready=val.ev_ready,
        missing=val.missing,
        ev_missing=val.ev_missing,
        soft_missing=val.soft_missing,
    )
    return data


@app.command("ca-validation")
def ca_validation(
    ctx: typer.Context,
    organization_id: str = typer.Argument(..., metavar="ORG", help="Organization number"),
    ca: str = typer.Option("SSLCOM", "--ca", metavar="CA", help="Non-emSign CA to show"),
    sync: bool = typer.Option(
        False, "--sync",
        help="Re-read the status from the CA first (updates CertiNext's cached copy only)",
    ),
) -> None:
    """Show an organization's SSL.com validation status.

    Lists the overall status, each level (OV, EV) with its expiry, and any
    items still missing before the organization can be submitted.
    """
    accounts = session(ctx).accounts
    val = (
        accounts.sync_ca_validation(organization_id, ca=ca)
        if sync
        else accounts.get_ca_validation(organization_id, ca=ca)
    )
    data = _summary(val)
    if ctx.obj.output_json:
        print(json.dumps(data, indent=2))
        return

    def _yn(value: bool | None) -> str:
        return "" if value is None else ("yes" if value else "no")

    console = data_console()
    console.print(pairs_table({
        "organization": val.organization_number,
        "ca": val.ca,
        "status": val.status,
        "enabled": _yn(val.enabled),
        "agreement_accepted": _yn(val.subscriber_agreement_accepted),
        "ready (OV)": _yn(val.ready),
        "ready (EV)": _yn(val.ev_ready),
        "validated_at": data["validated_at"],
        "last_synced_at": data["last_synced_at"],
        "last_error": val.last_error,
    }))
    if val.levels:
        print("\nLevels:\n")
        console.print(rows_table([
            {
                "level": lvl.level or "",
                "status": lvl.status or "",
                "usable": _yn(lvl.usable),
                "valid_till": lvl.valid_till.isoformat() if lvl.valid_till else "",
            }
            for lvl in val.levels
        ]))
    for label, items in (
        ("Missing (blocks submit)", val.missing),
        ("Missing for EV", val.ev_missing),
        ("Recommended", val.soft_missing),
    ):
        if items:
            print(f"\n{label}: {', '.join(items)}")
