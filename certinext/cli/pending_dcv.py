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

"""``certinext pending-dcv`` — list domains that require DCV validation."""

import json
from typing import Optional

import typer

from certinext.cli._app import app
from certinext.cli._shared import data_console, rows_table, session


@app.command()
def pending_dcv(
    ctx: typer.Context,
    pattern: Optional[str] = typer.Option(
        None, "--pattern", metavar="REGEX",
        help="Filter domains by regex pattern (re.fullmatch, case-insensitive)",
    ),
) -> None:
    """List all active domains that have not completed DCV verification."""
    sess = session(ctx)

    # get_pending_dcv() filters domainStatus=ACTIVE server-side (R02) and
    # applies needs_dcv (dcvStatus != VERIFIED) + the optional pattern
    # client-side. dcvStatus stays client-side until issue #6 settles the
    # enum: EXPIRED still 400s server-side (vendor #135290).
    domains = sess.domain.get_pending_dcv(pattern=pattern)

    if ctx.obj.output_json:
        print(json.dumps([d.as_dict() for d in domains], indent=2))
        return

    if not domains:
        print("(no domains pending DCV)")
        return

    data_console().print(rows_table([d.to_row() for d in domains]))
