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

"""``certinext accounts`` — show account info, groups, and organizations."""

import json

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
    rows_table,
)
from certinext.cli_support import LogFormat, setup_logging


@app.command()
def accounts(
    output_json: JsonOption = False,
    verbose: VerboseOption = 0,
    log_format: LogFormatOption = LogFormat.LOGFMT,
    profile: ProfileOption = None,
    sandbox: SandboxOption = False,
    base_url: BaseUrlOption = None,
    token_url: TokenUrlOption = None,
    account_number: AccountNumberOption = None,
    client_secret: ClientSecretOption = None,
) -> None:
    """Show account info, groups, and organizations."""
    setup_logging(verbose, log_format=log_format)
    sess = connect(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret,
    )

    me = sess.accounts.me()
    groups = sess.accounts.list_groups()
    orgs = sess.accounts.list_organizations()

    if output_json:
        output = {
            "account": me.as_dict(),
            "groups": [g.as_dict() for g in groups],
            "organizations": [o.as_dict() for o in orgs],
        }
        print(json.dumps(output, indent=2))
        return

    console = data_console()
    print("Account:")
    print(f"  Number : {me.account_number or '(unknown)'}")
    print(f"  Name   : {me.account_name or '(unknown)'}")
    print(f"  Type   : {me.account_type or '(unknown)'}")

    print()
    if groups:
        print("Groups:\n")
        console.print(rows_table(
            [{"group_number": g.group_number or "", "group_name": g.group_name or ""} for g in groups]
        ))
    else:
        print("Groups: (none)")

    print()
    if orgs:
        print("Organizations:\n")
        org_rows = [
            {
                "number": o.organization_number or "",
                "name": o.organization_name or "",
                "locality": o.locality or "",
                "country": o.country_code or "",
                "status": o.status_id or "",
            }
            for o in orgs
        ]
        console.print(rows_table(org_rows))
    else:
        print("Organizations: (none)")
