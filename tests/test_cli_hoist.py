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

"""Tests for the ``domains --profile``/``--sandbox``/``--json``/``-v`` hoisting.

These options sit on ``domains_app``'s group callback, so Click only accepts
them between ``domains`` and the leaf subcommand by default. ``certinext.cli
main()`` rewrites argv before Click sees it so the options work anywhere;
see :func:`certinext.cli._hoist_group_options`.
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
        ["domains", "--sandbox", "get", "maine.edu"],
        id="sandbox-after-leaf-subcommand",
    ),
    pytest.param(
        ["domains", "--sandbox", "get", "maine.edu"],
        ["domains", "--sandbox", "get", "maine.edu"],
        id="already-in-group-position-unchanged",
    ),
    pytest.param(
        ["domains", "list", "--offset", "5", "--json", "-vvv"],
        ["domains", "--json", "-vvv", "list", "--offset", "5"],
        id="json-and-combined-verbosity-hoisted",
    ),
    pytest.param(
        ["domains", "list", "--profile=dev"],
        ["domains", "--profile=dev", "list"],
        id="equals-form-hoisted",
    ),
    pytest.param(
        ["domains", "deactivate", "id123", "--yes", "--sandbox"],
        ["domains", "--sandbox", "deactivate", "id123", "--yes"],
        id="leaf-only-yes-flag-left-in-place",
    ),
    pytest.param(
        ["setup", "keyring", "--profile", "x"],
        ["setup", "keyring", "--profile", "x"],
        id="setup-group-left-untouched",
    ),
    pytest.param(
        ["bogus", "get", "x", "--profile", "y"], ["bogus", "get", "x", "--profile", "y"],
        id="unknown-group-left-untouched",
    ),
    pytest.param(["--help"], ["--help"], id="no-group-name-left-untouched"),
])
def test_hoist_group_options(args: list[str], expected: list[str]) -> None:
    """Group-level options are moved to sit right after the entity group name."""
    assert certinext.cli._hoist_group_options(list(args)) == expected


def test_sandbox_after_subcommand_reaches_connect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """--sandbox typed after 'get' still resolves to connect()'s sandbox kwarg."""
    seen: dict[str, object] = {}

    def fake_connect(**kwargs: object) -> _FakeSession:
        seen.update(kwargs)
        return _FakeSession()

    monkeypatch.setattr(certinext.cli.domains, "connect", fake_connect)
    code = cli_main(["domains", "get", "maine.edu", "--sandbox"])
    assert code == 0
    assert seen["sandbox"] is True
    assert capsys.readouterr().out.strip() == "fake-domain"
