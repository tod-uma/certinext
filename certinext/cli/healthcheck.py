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

"""``certinext healthcheck`` — thin CLI wrapper over :mod:`certinext.healthcheck`.

The probe registry, classification, and exit-code policy live in the library
module; this command only parses options and renders. The exit-code contract
(non-zero on DENIED/NOT_FOUND/SERVER_BUG/NETWORK, plus EMPTY under
``--strict``) is monitoring-relevant and must not change.
"""

import json

import structlog
import typer

from certinext import healthcheck as hc
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
)
from certinext.cli_support import setup_logging

log = structlog.get_logger()


@app.command()
def healthcheck(
    quick: bool = typer.Option(
        False, "--quick",
        help="Run Tier-1 probes only (skip derived-input Tier-2 probes)",
    ),
    strict: bool = typer.Option(
        False, "--strict",
        help="Also exit non-zero when a baseline list is unexpectedly empty (EMPTY)",
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
    """Probe every read-only CertiNext endpoint the library exposes and report
    what works for the given credentials. Read-only and safe against production.
    """
    setup_logging(verbose)
    sess = connect(
        profile=profile, sandbox=sandbox, base_url=base_url, token_url=token_url,
        account_number=account_number, client_secret=client_secret,
    )

    log.info("Running CertiNext health check", scope="tier-1" if quick else "all")
    results = hc.run(sess, quick=quick)

    if output_json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        data_console().print(hc.results_table(results))
        print()
        print(hc.render_summary(results))

    raise SystemExit(hc.exit_code(results, strict=strict))
