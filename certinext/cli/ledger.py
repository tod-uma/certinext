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

"""``certinext ledger`` — show the account ledger (transaction history)."""

import json
from typing import Optional

import typer

from certinext.cli._app import app
from certinext.cli._shared import data_console, rows_table, session


@app.command()
def ledger(
    ctx: typer.Context,
    last: Optional[int] = typer.Option(
        None, "--last", metavar="N",
        help="Show only the N most recent transactions",
    ),
) -> None:
    """Show the CertiNext account ledger (transaction history)."""
    sess = session(ctx)

    records = sess.ledger.get_list()

    if last is not None:
        records = records[-last:]

    if ctx.obj.output_json:
        print(json.dumps([r.as_dict() for r in records], indent=2))
        return

    if not records:
        print("(no ledger records)")
        return

    data_console().print(rows_table([r.to_row() for r in records]))
    print(f"\n{len(records)} transaction(s)")
