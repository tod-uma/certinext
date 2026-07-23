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

import typer

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
def list_certificates(
    status: Optional[str] = typer.Option(
        None, "--status", metavar="STATUS",
        help=(
            "Filter by certificate status "
            "(e.g. issued, expired, pending-dcv, pending-csr, revoked, cancelled)"
        ),
    ),
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
    """List SSL/TLS certificate orders from the CertiNext orders report."""
    setup_logging(verbose, log_format=log_format)
    sess = connect(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret,
    )

    orders = sess.orders.get_list(status=status)

    if output_json:
        print(json.dumps([o.as_dict() for o in orders], indent=2))
        return

    if not orders:
        label = f" with status '{status}'" if status else ""
        print(f"(no certificates{label})")
        return

    status_label = f" ({status})" if status else ""
    print(f"Certificates{status_label}:\n")
    data_console().print(rows_table([o.to_row() for o in orders]))
    print(f"\n{len(orders)} certificate(s)")
