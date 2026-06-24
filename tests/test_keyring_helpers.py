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

"""Tests for keyring backend detection and the no-backend help message."""

import sys
from unittest.mock import MagicMock

import keyring
import keyring.backends.fail
import pytest
from keyring.errors import NoKeyringError

from certinext._cli import _resolve
from certinext._keyring import in_wsl, keyring_available, no_keyring_help
from certinext.setup_keyring_cli import main as setup_keyring_main


def _fake_uname(release: str) -> MagicMock:
    """Return a stand-in for platform.uname() with the given kernel release."""
    return MagicMock(release=release)


def test_in_wsl_via_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """WSL_DISTRO_NAME being set is sufficient to detect WSL."""
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert in_wsl() is True


def test_in_wsl_via_kernel_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 'microsoft' kernel release string is detected as WSL."""
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(
        "certinext._keyring.platform.uname",
        lambda: _fake_uname("5.15.167.4-microsoft-standard-WSL2"),
    )
    assert in_wsl() is True


def test_in_wsl_false_elsewhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither signal present means not WSL."""
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(
        "certinext._keyring.platform.uname",
        lambda: _fake_uname("6.8.0-49-generic"),
    )
    assert in_wsl() is False


def test_keyring_available_false_with_fail_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fail backend (no OS keychain reachable) reports unavailable."""
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    assert keyring_available() is False


def test_keyring_available_true_with_real_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any backend other than the fail backend reports available."""
    monkeypatch.setattr(keyring, "get_keyring", lambda: MagicMock())
    assert keyring_available() is True


def test_no_keyring_help_wsl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under WSL the help suggests keyring-pybridge and the env-var fallback."""
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    text = no_keyring_help()
    assert "keyring-pybridge" in text
    assert "PYTHON_KEYRING_BACKEND" in text
    assert "CERTINEXT_CLIENT_ID" in text
    assert "gnome-keyring or KWallet" in text


def test_no_keyring_help_non_wsl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside WSL the help suggests a Secret Service daemon, not pybridge."""
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(
        "certinext._keyring.platform.uname",
        lambda: _fake_uname("6.8.0-49-generic"),
    )
    text = no_keyring_help()
    assert "keyring-pybridge" not in text
    assert "gnome-keyring" in text
    assert "CERTINEXT_CLIENT_SECRET" in text


def test_setup_keyring_cli_no_backend(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """The setup CLI exits 1 with guidance instead of a traceback when no backend exists."""
    monkeypatch.setattr(sys, "argv", ["certinext-setup-keyring"])
    monkeypatch.setattr(
        keyring, "get_password",
        MagicMock(side_effect=NoKeyringError("No recommended backend was available.")),
    )
    with pytest.raises(SystemExit) as excinfo:
        setup_keyring_main()
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "no usable OS keyring backend" in err
    assert "CERTINEXT_CLIENT_ID" in err


def test_setup_keyring_warns_on_sandbox_with_profile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--sandbox + --profile warns that --sandbox is ignored and stores under the profile."""
    monkeypatch.setattr(sys, "argv", ["certinext-setup-keyring", "--profile", "prod", "--sandbox"])
    monkeypatch.setattr(keyring, "get_password", lambda *a, **k: None)
    stored: list[tuple[str, str, str]] = []
    monkeypatch.setattr(keyring, "set_password", lambda s, k, v: stored.append((s, k, v)))
    monkeypatch.setattr("builtins.input", lambda *a, **k: "acct123")
    # client secret, then an empty prevetting token (skip).
    monkeypatch.setattr(
        "certinext.setup_keyring_cli.getpass.getpass",
        MagicMock(side_effect=["secret-xyz", ""]),
    )

    setup_keyring_main()

    err = capsys.readouterr().err
    assert "--sandbox is ignored" in err
    assert "prod" in err
    assert ("certinext-prod", "CERTINEXT_CLIENT_ID", "acct123") in stored


def test_resolve_non_tty_without_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """_resolve's non-TTY error includes the keyring help when no backend exists."""
    monkeypatch.delenv("CERTINEXT_CLIENT_ID", raising=False)
    monkeypatch.setattr("certinext._cli.keyring_available", lambda: False)
    monkeypatch.setattr("certinext._cli.sys.stdin.isatty", lambda: False)
    with pytest.raises(RuntimeError, match="no usable\\s+OS keyring backend"):
        _resolve(None, "CERTINEXT_CLIENT_ID", "CertiNext account number")


def test_resolve_non_tty_with_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """_resolve's non-TTY error keeps the short keyring suggestion when a backend exists."""
    monkeypatch.delenv("CERTINEXT_CLIENT_ID", raising=False)
    monkeypatch.setattr("certinext._cli.keyring_available", lambda: True)
    monkeypatch.setattr("certinext._cli.sys.stdin.isatty", lambda: False)
    with pytest.raises(RuntimeError, match="store the credential in the keyring"):
        _resolve(None, "CERTINEXT_CLIENT_ID", "CertiNext account number")
