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
from certinext.cli._shared import (
    AccountNumberOption,
    BaseUrlOption,
    ClientSecretOption,
    JsonOption,
    ProfileOption,
    SandboxOption,
    TokenUrlOption,
    VerboseOption,
    connect,
    data_console,
    rows_table,
)
from certinext.cli_support import setup_logging


@app.command()
def ledger(
    last: Optional[int] = typer.Option(
        None, "--last", metavar="N",
        help="Show only the N most recent transactions",
    ),
    output_json: JsonOption = False,
    verbose: VerboseOption = 0,
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
) -> None:
    """Show the CertiNext account ledger (transaction history)."""
    setup_logging(verbose)
    sess = connect(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret,
    )

    records = sess.ledger.get_list()

    if last is not None:
        records = records[-last:]

    if output_json:
        print(json.dumps([r.as_dict() for r in records], indent=2))
        return

    if not records:
        print("(no ledger records)")
        return

    data_console().print(rows_table([r.to_row() for r in records]))
    print(f"\n{len(records)} transaction(s)")
