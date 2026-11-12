"""A CertiNext outage ends a CLI run with one log line, not a traceback.

Replays the 2026-11-12 incident: the token endpoint timed out, then returned
an nginx 502 page, and ``replacement-report`` died with a ``RuntimeError``
traceback from ``auth._fetch_token``.
"""

from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock

import httpx
import pytest

from certinext.cli import _vendor_failure
from certinext.cli import main as cli_main
from certinext.exceptions import CertiNextAPIError, CertiNextAuthError
from certinext.session import CertiNextSession


def _gateway_page() -> MagicMock:
    """Return a mock 502 token response carrying nginx's HTML error page."""
    resp = MagicMock()
    resp.is_success = False
    resp.status_code = 502
    resp.reason_phrase = "Bad Gateway"
    resp.url = "https://us-api.certinext.io/oauth/token"
    resp.text = "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n</html>\r\n"
    return resp


@pytest.fixture
def run_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> Callable[[Any], tuple[int, str, str]]:
    """Run ``certinext replacement-report`` with a real session whose token POST is faked.

    Returns:
        A ``run(token_post) -> (exit_code, stdout, stderr)`` callable, where
        ``token_post`` is the ``side_effect`` for ``httpx.post``.
    """
    monkeypatch.setenv("CERTINEXT_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setattr("certinext.cli.replacement_report.cache_dir", lambda: tmp_path / "cache")
    monkeypatch.setattr("certinext.auth.time.sleep", lambda _s: None)

    def run(token_post: Any) -> tuple[int, str, str]:
        """Invoke the command once.

        Args:
            token_post: ``side_effect`` for the token endpoint's ``httpx.post``.

        Returns:
            ``(exit_code, stdout, stderr)``.
        """
        sess = CertiNextSession(client_id="test", client_secret="secret")
        monkeypatch.setattr("certinext.cli.replacement_report.session", lambda ctx, **kw: sess)
        monkeypatch.setattr("certinext.auth.httpx.post", MagicMock(side_effect=token_post))
        code = cli_main(["replacement-report", "--no-cache"])
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


def test_token_gateway_error_is_one_line(run_report: Callable[[Any], tuple[int, str, str]]) -> None:
    """A 502 from the token endpoint (after retries) exits 1 with a one-line error, no HTML."""
    code, out, err = run_report(lambda *a, **kw: _gateway_page())
    assert code == 1
    assert "CertiNext is unavailable; try again later" in err
    assert "token request: 502 Bad Gateway" in err
    assert "Traceback" not in err and "<html>" not in err
    assert "Token request failed; retrying" in err  # the retries were logged
    assert out == ""


def test_token_timeout_is_one_line(run_report: Callable[[Any], tuple[int, str, str]]) -> None:
    """The incident's first symptom: an unreachable token endpoint also ends cleanly.

    The group-name lookup degrades on the transport error (as before); the
    catalog read then hits the token hold-off and fails at once.
    """
    code, _, err = run_report(httpx.ReadTimeout("The read operation timed out"))
    assert code == 1
    assert "Could not resolve group names" in err
    assert "Could not reach CertiNext; try again later" in err
    assert "Traceback" not in err


@pytest.mark.parametrize(
    ("exc", "event"),
    [
        (CertiNextAuthError("m", 503, "Service Unavailable"), "CertiNext is unavailable; try again later"),
        (CertiNextAuthError("m", 401, "Unauthorized"), "CertiNext refused the credentials; check the profile"),
        (CertiNextAuthError("m", 200, "OK"), "CertiNext token request failed"),
        (httpx.ConnectError("refused"), "Could not reach CertiNext; try again later"),
        (CertiNextAPIError(503, "down"), "CertiNext is unavailable; try again later"),
        (CertiNextAPIError(500, "boom"), "CertiNext is failing; try again later"),
    ],
)
def test_vendor_failure_events(exc: Exception, event: str) -> None:
    """Each vendor-side failure maps to an event that says what to do."""
    result = _vendor_failure(exc)
    assert result is not None and result[0] == event


def test_client_errors_keep_their_traceback() -> None:
    """A 4xx API error is a bug or contract change, not an outage: main() re-raises it."""
    assert _vendor_failure(CertiNextAPIError(422, "bad")) is None
