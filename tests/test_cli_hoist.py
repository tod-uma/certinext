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

"""Tests for the ``--profile``/``--sandbox``/``--json``/``-v`` argv hoisting.

Per ADR 0009, these options live on the root ``app`` callback, so Click only
accepts them before the first subcommand token by default. ``certinext.cli
main()`` rewrites argv before Click sees it so the options work anywhere; see
:func:`certinext.cli._hoist_shared_options`.
"""

import pytest

import certinext.cli
from certinext.cli import main as cli_main


class _FakeDomain:
    """Stand-in for :class:`certinext.domains.Domain` with a printable str form."""

    def __str__(self) -> str:
        return "fake-domain"


class _FakeDomainAccessor:
    """Stand-in for the session's ``domain`` accessor; ``get`` ignores its id."""

    def get(self, _domain_id: str) -> _FakeDomain:
        return _FakeDomain()


class _FakeSession:
    """Minimal session double so ``domains get`` runs without a real API."""

    domain = _FakeDomainAccessor()


@pytest.mark.parametrize(("args", "expected"), [
    pytest.param(
        ["domains", "get", "maine.edu", "--sandbox"],
        ["--sandbox", "domains", "get", "maine.edu"],
        id="sandbox-after-leaf-subcommand",
    ),
    pytest.param(
        ["--sandbox", "domains", "get", "maine.edu"],
        ["--sandbox", "domains", "get", "maine.edu"],
        id="already-hoisted-unchanged",
    ),
    pytest.param(
        ["domains", "list", "--offset", "5", "--json", "-vvv"],
        ["--json", "-vvv", "domains", "list", "--offset", "5"],
        id="json-and-combined-verbosity-hoisted",
    ),
    pytest.param(
        ["domains", "list", "--profile=dev"],
        ["--profile=dev", "domains", "list"],
        id="equals-form-hoisted",
    ),
    pytest.param(
        ["domains", "deactivate", "id123", "--yes", "--sandbox"],
        ["--sandbox", "domains", "deactivate", "id123", "--yes"],
        id="leaf-only-yes-flag-left-in-place",
    ),
    pytest.param(
        ["setup", "keyring", "--profile", "x"],
        ["--profile", "x", "setup", "keyring"],
        id="nested-group-hoisted-past-both-levels",
    ),
    pytest.param(
        ["accounts", "--json"],
        ["--json", "accounts"],
        id="leaf-command-option-hoisted",
    ),
    pytest.param(["--help"], ["--help"], id="help-flag-left-in-place"),
    pytest.param([], [], id="empty-args-left-in-place"),
])
def test_hoist_shared_options(args: list[str], expected: list[str]) -> None:
    """Shared root-level options are moved to the very front of argv."""
    assert certinext.cli._hoist_shared_options(list(args)) == expected


def test_sandbox_after_subcommand_reaches_session(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """--sandbox typed after 'get' still resolves to the root GlobalOptions."""
    seen: dict[str, object] = {}

    def fake_session(ctx: object, **_kwargs: object) -> _FakeSession:
        seen["sandbox"] = ctx.obj.sandbox  # type: ignore[attr-defined]
        return _FakeSession()

    monkeypatch.setattr(certinext.cli.domains, "session", fake_session)
    code = cli_main(["domains", "get", "maine.edu", "--sandbox"])
    assert code == 0
    assert seen["sandbox"] is True
    assert capsys.readouterr().out.strip() == "fake-domain"
