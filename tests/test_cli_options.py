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

"""Tests for the public :mod:`certinext.cli_options` surface.

Downstream scripts (e.g. ums-certinext-scripts) build their typer commands
from these aliases so their connection flags never drift from the bundled
CLI's. These tests pin that contract: the aliases exist, produce the expected
flag spellings, the internal CLI re-exports the *same* objects, and
:func:`~certinext.cli_options.connect` chains the two cli_support helpers.
"""

from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from certinext import cli_options
from certinext.cli import _shared

runner = CliRunner()


def _probe_app() -> typer.Typer:
    """Build a minimal typer app declaring every public option alias.

    Returns:
        A single-command app whose ``--help`` exercises all aliases.
    """
    app = typer.Typer()

    @app.command()
    def probe(
        profile: cli_options.ProfileOption = None,
        sandbox: cli_options.SandboxOption = False,
        base_url: cli_options.BaseUrlOption = None,
        token_url: cli_options.TokenUrlOption = None,
        account_number: cli_options.AccountNumberOption = None,
        client_secret: cli_options.ClientSecretOption = None,
        scope: cli_options.ScopeOption = "",
        json_output: cli_options.JsonOption = False,
        verbose: cli_options.VerboseOption = 0,
    ) -> None:
        """Probe command exercising the shared option aliases."""

    return app


def test_aliases_render_expected_flags() -> None:
    """Every alias contributes its canonical flag spelling to ``--help``."""
    result = runner.invoke(_probe_app(), ["--help"])
    assert result.exit_code == 0
    for flag in (
        "--profile",
        "--sandbox",
        "--base-url",
        "--token-url",
        "--account-number",
        "--client-id",
        "--client-secret",
        "--scope",
        "--json",
        "--verbose",
        "-v",
    ):
        assert flag in result.output, f"missing flag {flag} in --help output"


def test_internal_cli_reexports_same_objects() -> None:
    """The bundled CLI's ``_shared`` module re-exports the public aliases unchanged.

    Guards against the internal CLI and the public surface drifting apart —
    the whole point of promoting the aliases.
    """
    for name in (
        "ProfileOption",
        "SandboxOption",
        "BaseUrlOption",
        "TokenUrlOption",
        "AccountNumberOption",
        "ClientSecretOption",
        "ScopeOption",
        "JsonOption",
        "VerboseOption",
        "connect",
    ):
        assert getattr(_shared, name) is getattr(cli_options, name), f"_shared.{name} is not cli_options.{name}"


def test_connect_chains_resolve_and_build(monkeypatch: pytest.MonkeyPatch) -> None:
    """``connect()`` forwards its arguments through resolve_connection into build_session."""
    seen: dict[str, Any] = {}
    conn_sentinel = object()
    session_sentinel = object()

    def fake_resolve(**kwargs: Any) -> object:
        seen["resolve"] = kwargs
        return conn_sentinel

    def fake_build(conn: object, **kwargs: Any) -> object:
        seen["conn"] = conn
        seen["build"] = kwargs
        return session_sentinel

    monkeypatch.setattr(cli_options, "resolve_connection", fake_resolve)
    monkeypatch.setattr(cli_options, "build_session", fake_build)

    result = cli_options.connect(
        profile="p", sandbox=True, base_url="https://b", token_url="https://t",
        account_number="acct", client_secret="sec", scope="s", prompt=False,
    )

    assert result is session_sentinel
    assert seen["resolve"] == {
        "profile": "p", "sandbox": True, "base_url": "https://b", "token_url": "https://t",
    }
    assert seen["conn"] is conn_sentinel
    assert seen["build"] == {
        "account_number": "acct", "client_secret": "sec", "scope": "s", "prompt": False,
    }
