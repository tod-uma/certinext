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

"""Tests for how `certinext issue-cert` reports a failed order create."""

import sys
from unittest.mock import MagicMock

import pytest

from certinext.cli.issue_cert import _create_order
from certinext.cli_support import setup_logging
from certinext.exceptions import CertiNextAPIError


def _fail_create(
    body: dict[str, str], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> str:
    """Run _create_order against a DV create that fails with ``body`` and return stderr.

    Args:
        body: RFC 7807 response body for the 422.
        capsys: pytest capture fixture.
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        Everything logged to stderr.
    """
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    setup_logging(0)
    sess = MagicMock()
    sess.ssl.create_dv.side_effect = CertiNextAPIError(422, body)
    values = MagicMock(cert_type="dv")
    with pytest.raises(SystemExit):
        _create_order(sess, values, domain="host.example.edu", sans=None,
                      auto_secure_www=False, prevetting_token=None)
    return capsys.readouterr().err


def test_ems_1099_logs_new_key_hint(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reused-CSR rejection tells the user to generate a fresh CSR."""
    err = _fail_create(
        {"detail": "[EMS-1099] You are attempting to submit a CSR of an existing certificate order"},
        capsys, monkeypatch,
    )
    assert "Error creating order" in err
    assert "hint=" in err
    assert "generate a fresh CSR" in err
    assert "new private key is not required but is recommended" in err


def test_other_errors_log_no_hint(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codes without known advice log the error alone."""
    err = _fail_create({"detail": "[EMS-921] CSR malformed"}, capsys, monkeypatch)
    assert "Error creating order" in err
    assert "hint" not in err
