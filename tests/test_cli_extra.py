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

"""The library works without the ``cli`` extra (ADR 0026).

Each check runs in a fresh interpreter with typer, rich, tomlkit and click
blocked in ``sys.modules``, which is what a ``pip install certinext`` without
extras looks like to the import system.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

_BLOCK = 'import sys\nfor _m in ("typer", "rich", "tomlkit", "click"):\n    sys.modules[_m] = None\n'
_CLI_DEPS = {"typer", "rich", "tomlkit"}

#: Modules a library-only consumer (e.g. a Splunk modular input) may import.
_LIBRARY_MODULES = [
    "certinext",
    "certinext.settings",
    "certinext.retry",
    "certinext.certificate_lookup",
    "certinext.replacement",
    "certinext.healthcheck",
    "certinext.cli_support",
    "certinext._config",
]


def _run(code: str) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a fresh interpreter with the CLI dependencies blocked.

    Args:
        code: Python source to run after the block.

    Returns:
        The completed process, with text stdout/stderr.
    """
    return subprocess.run(
        [sys.executable, "-c", _BLOCK + textwrap.dedent(code)],
        capture_output=True, text=True, timeout=120, check=False,
    )


@pytest.mark.parametrize("module", _LIBRARY_MODULES)
def test_library_module_imports_without_cli_extra(module: str) -> None:
    """Library modules never import typer, rich or tomlkit at import time."""
    proc = _run(f"import {module}")
    assert proc.returncode == 0, proc.stderr


def test_session_and_settings_work_without_cli_extra() -> None:
    """Building a session and resolving settings needs only core dependencies."""
    proc = _run(
        """
        import certinext
        from certinext.settings import CertiNextSettings
        sess = certinext.session(client_id="id", client_secret="s", retry=certinext.RetryPolicy())
        assert sess.retry is not None
        CertiNextSettings(client_id="id", client_secret="s")
        print("ok")
        """
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_cli_without_extra_names_the_fix() -> None:
    """Importing the CLI without the extra says which extra to install."""
    proc = _run("import certinext.cli")
    assert proc.returncode != 0
    assert "certinext[cli]" in proc.stderr


def test_cli_dependencies_are_only_in_extras() -> None:
    """typer, rich and tomlkit are not core dependencies, and the cli extra has all three."""
    meta = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    def names(specs: list[str]) -> set[str]:
        """Reduce requirement strings to bare distribution names."""
        return {spec.split(";")[0].split("[")[0].split(">")[0].split("=")[0].split("<")[0].strip() for spec in specs}

    assert not names(meta["dependencies"]) & _CLI_DEPS
    assert names(meta["optional-dependencies"]["cli"]) == _CLI_DEPS
    assert _CLI_DEPS <= names(meta["optional-dependencies"]["dev"])
