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

"""CLI: ``domains last-dcv-attempt`` and ``domains dcv-attempt-history``.

The session is a MagicMock patched into the command module, so these tests
check which library methods the CLI uses and how it renders the result.
"""

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest
import structlog

from certinext.cli import main as cli_main
from certinext.models.dcv_attempts import DcvAttempt, DcvAttemptSummary


@pytest.fixture(autouse=True)
def _uncached_structlog(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the CLI's structlog configuration from leaking into other tests.

    See the fixture of the same purpose in ``test_cli_sslcom_flags.py``.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Yields:
        Nothing; resets before and after the test.
    """
    real_configure = structlog.configure

    def configure_uncached(*args: Any, **kwargs: Any) -> None:
        """Pass through to ``structlog.configure`` with caching disabled."""
        kwargs["cache_logger_on_first_use"] = False
        real_configure(*args, **kwargs)

    monkeypatch.setattr(structlog, "configure", configure_uncached)
    structlog.reset_defaults()
    yield
    structlog.reset_defaults()


@pytest.fixture
def sess(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch a MagicMock session into the domains command module.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        The MagicMock session.
    """
    mock = MagicMock()
    monkeypatch.setattr("certinext.cli.domains.session", lambda ctx, **kw: mock)
    return mock


_EMSIGN_ROW = {"attemptId": "729645", "attemptedAt": "2026-10-26T19:12:49Z", "overallStatus": "VERIFIED"}
_SSLCOM_ROW = {"attemptId": "sslcom-latest", "overallStatus": "VERIFIED"}


def test_last_dcv_attempt_uses_latest_and_adds_attempt_id(
    sess: MagicMock, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command uses latest_dcv_attempt() and prints attemptId even when the wire lacks it."""
    payload = {"status": "VERIFIED", "domainId": "id-1"}
    attempt = DcvAttempt.model_validate(payload)
    attempt.attempt_id = "729645"
    domain = sess.domain.get.return_value
    domain.latest_dcv_attempt.return_value = attempt
    assert cli_main(["domains", "--json", "last-dcv-attempt", "dom-1"]) == 0
    domain.latest_dcv_attempt.assert_called_once_with()
    domain.last_dcv_attempt.assert_not_called()
    assert json.loads(capsys.readouterr().out) == {"attemptId": "729645", "status": "VERIFIED", "domainId": "id-1"}


def test_last_dcv_attempt_none_exits_1(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """A domain with no attempts is reported on stderr with exit code 1."""
    sess.domain.get.return_value.latest_dcv_attempt.return_value = None
    assert cli_main(["domains", "last-dcv-attempt", "dom-1"]) == 1
    captured = capsys.readouterr()
    assert "No DCV attempts" in captured.err
    assert captured.out == ""


def test_history_json_is_raw_rows_from_every_page(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """--json prints every row exactly as received, via dcv_attempts()."""
    domain = sess.domain.get.return_value
    domain.dcv_attempts.return_value = [
        DcvAttemptSummary.model_validate(_EMSIGN_ROW),
        DcvAttemptSummary.model_validate(_SSLCOM_ROW),
    ]
    assert cli_main(["domains", "--json", "dcv-attempt-history", "dom-1"]) == 0
    domain.dcv_attempt_history.assert_not_called()
    assert json.loads(capsys.readouterr().out) == [_EMSIGN_ROW, _SSLCOM_ROW]


def test_history_table_has_uniform_columns(sess: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
    """The table shows the same columns for rows with different wire keys."""
    sess.domain.get.return_value.dcv_attempts.return_value = [
        DcvAttemptSummary.model_validate(_SSLCOM_ROW),
        DcvAttemptSummary.model_validate(_EMSIGN_ROW),
    ]
    assert cli_main(["domains", "dcv-attempt-history", "dom-1"]) == 0
    out = capsys.readouterr().out
    header = out.splitlines()[0].split()
    assert header == ["attemptId", "attemptedAt", "overallStatus", "failureClass", "method"]
    assert "2026-10-26T19:12:49+00:00" in out
