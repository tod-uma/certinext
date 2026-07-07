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

"""Snapshot tests for the ``certinext`` app's ``--help`` trees (phase 4, step 6).

The snapshots document the *new* typer help contract — they intentionally
differ from the 0.3.x argparse help text. Their job is to catch accidental
drift: a renamed flag, a dropped subcommand, or reworded help showing up in a
diff nobody meant to make. Deliberate changes are fine; regenerate with::

    uv run pytest tests/test_cli_help_snapshots.py --update-goldens
"""

import pytest

from certinext.cli import main as cli_main

# Every node of the command tree: golden name -> argv prefix before --help.
_HELP_CASES: dict[str, list[str]] = {
    "root": [],
    "accounts": ["accounts"],
    "domain-cert-count": ["domain-cert-count"],
    "healthcheck": ["healthcheck"],
    "issue-cert": ["issue-cert"],
    "ledger": ["ledger"],
    "list-certificates": ["list-certificates"],
    "parent-dcv-status": ["parent-dcv-status"],
    "pending-dcv": ["pending-dcv"],
    "setup": ["setup"],
    "setup-defaults": ["setup", "defaults"],
    "setup-keyring": ["setup", "keyring"],
    "domains": ["domains"],
    "domains-list": ["domains", "list"],
    "domains-get": ["domains", "get"],
    "domains-create": ["domains", "create"],
    "domains-deactivate": ["domains", "deactivate"],
    "domains-get-dcv": ["domains", "get-dcv"],
    "domains-verify-dcv": ["domains", "verify-dcv"],
    "domains-change-dcv-method": ["domains", "change-dcv-method"],
    "domains-last-dcv-attempt": ["domains", "last-dcv-attempt"],
    "domains-dcv-attempt-history": ["domains", "dcv-attempt-history"],
}


@pytest.fixture(autouse=True)
def _pinned_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin console width and styling so help renders identically everywhere.

    Rich sizes its console from COLUMNS/terminal state and typer additionally
    reads TERMINAL_WIDTH into a module constant at import time; both are
    pinned so the snapshot doesn't depend on who ran the tests where.

    Args:
        monkeypatch: The pytest monkeypatch fixture.
    """
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.setenv("LINES", "50")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TERMINAL_WIDTH", raising=False)
    try:
        from typer import rich_utils
    except ImportError:
        pass
    else:
        monkeypatch.setattr(rich_utils, "MAX_WIDTH", 100, raising=False)


@pytest.mark.parametrize("name", _HELP_CASES)
def test_help_snapshot(
    name: str, capsys: pytest.CaptureFixture[str], golden
) -> None:
    """``--help`` for every command exits 0 and matches its recorded snapshot."""
    argv = _HELP_CASES[name]
    assert cli_main([*argv, "--help"]) == 0
    golden(f"help/{name}.txt", capsys.readouterr().out)
