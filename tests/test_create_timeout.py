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

"""Configurable timeouts and opt-in recovery of a timed-out certificate order.

On 2026-11-06 the sandbox took over 60s to answer ``POST /ssl-certificates``
while still creating and issuing the order, so the client raised a bare
``httpx.ReadTimeout`` for a certificate that existed. These tests pin the
fix: a longer create-only timeout, a specific error carrying what is needed
to find the order, and recovery that never runs unless the caller asks.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

import certinext
from certinext.cli.issue_cert import _handle_create_timeout
from certinext.client import CertiNextClient
from certinext.exceptions import CertiNextCreateTimeoutError, CertiNextOrderRecoveryError
from certinext.models.orders import OrderRecord
from certinext.ssl_certificates import SslAccessor
from tests.test_ssl_certificates import _ORDER_DATA, _make_client, _ok_response

_SENT = datetime(2026, 11, 6, 18, 54, 15, tzinfo=timezone.utc)
_CN = "certinext-ci-1.example.edu"
_FAKE_ORDER = MagicMock(name="recovered-order")


def _record(number: str, ordered: datetime, cn: str = _CN) -> OrderRecord:
    """Build an orders-report row.

    Args:
        number: Order number.
        ordered: Order timestamp (UTC).
        cn: Common name.

    Returns:
        The OrderRecord.
    """
    return OrderRecord.model_validate(
        {"orderNumber": number, "commonName": cn, "orderDate": ordered.strftime("%Y-%m-%d %H:%M:%S")}
    )


def _timeout_error() -> CertiNextCreateTimeoutError:
    """Return a create-timeout error for _CN sent at _SENT."""
    return CertiNextCreateTimeoutError(_CN, _SENT, "ov")


class TestTimeoutConfiguration:
    """Timeouts are configurable and the create call gets its own, longer one."""

    def test_defaults(self) -> None:
        client = CertiNextClient("https://x.invalid", "https://x.invalid/t", "id", "secret")
        assert client.timeout.read == 60.0
        assert client.create_timeout.read == 180.0

    def test_float_and_timeout_objects_accepted(self) -> None:
        client = CertiNextClient(
            "https://x.invalid", "https://x.invalid/t", "id", "secret",
            timeout=30, create_timeout=httpx.Timeout(5.0, read=300.0),
        )
        assert client.timeout.read == 30.0
        assert client.timeout.connect == 30.0
        assert client.create_timeout.read == 300.0

    def test_session_factory_passes_timeouts_through(self) -> None:
        sess = certinext.session(client_id="id", client_secret="secret", sandbox=True, create_timeout=240)
        assert sess._client.create_timeout.read == 240.0
        assert sess._client.timeout.read == 60.0

    def test_create_sends_create_timeout(self) -> None:
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response(_ORDER_DATA)
        SslAccessor(client).create_dv("example.com")
        assert mock_session.post.call_args.kwargs["timeout"] is client.create_timeout

    def test_other_posts_keep_client_default(self) -> None:
        """A plain post() passes no timeout kwarg, so httpx uses the client default."""
        client, mock_session = _make_client()
        mock_session.post.return_value = _ok_response({})
        client.post("/api/x", json={})
        assert "timeout" not in mock_session.post.call_args.kwargs


class TestCreateTimeoutError:
    """A read timeout on create becomes CertiNextCreateTimeoutError; others propagate."""

    def test_read_timeout_is_wrapped(self) -> None:
        client, mock_session = _make_client()
        mock_session.post.side_effect = httpx.ReadTimeout("timed out")
        with pytest.raises(CertiNextCreateTimeoutError) as info:
            SslAccessor(client).create_ov(_CN, "12345")
        err = info.value
        assert err.common_name == _CN
        assert err.product_variant == "ov"
        assert err.sent_at.tzinfo is not None
        assert "may still have been created" in str(err)
        # Existing handlers for the transport error still catch it.
        assert isinstance(err, httpx.ReadTimeout)
        assert isinstance(err, httpx.HTTPError)

    def test_connect_timeout_propagates_unchanged(self) -> None:
        """No connection means no order, so it is not reported as possibly created."""
        client, mock_session = _make_client()
        mock_session.post.side_effect = httpx.ConnectTimeout("no route")
        with pytest.raises(httpx.ConnectTimeout) as info:
            SslAccessor(client).create_dv("example.com")
        assert not isinstance(info.value, CertiNextCreateTimeoutError)


class TestFindCreatedOrders:
    """find_created_orders() lists candidates without adopting anything."""

    def test_filters_by_time_with_skew(self, mock_client: MagicMock) -> None:
        rows = [
            _record("OLD", _SENT - timedelta(days=3)),
            _record("SKEW", _SENT - timedelta(seconds=30)),
            _record("NEW", _SENT + timedelta(seconds=45)),
        ]
        with patch("certinext.ssl_certificates.OrderAccessor.find_by_domain", return_value=rows) as find:
            got = SslAccessor(mock_client).find_created_orders(_CN, _SENT)
        find.assert_called_once_with(_CN, status=None)
        assert [r.order_number for r in got] == ["SKEW", "NEW"]

    def test_ignores_rows_without_date_or_number(self, mock_client: MagicMock) -> None:
        rows = [OrderRecord.model_validate({"orderNumber": "X", "commonName": _CN}), _record("", _SENT)]
        with patch("certinext.ssl_certificates.OrderAccessor.find_by_domain", return_value=rows):
            assert SslAccessor(mock_client).find_created_orders(_CN, _SENT) == []


class TestRecoverTimedOutCreate:
    """recover_timed_out_create() adopts exactly one match and never guesses."""

    def _accessor(self, mock_client: MagicMock, batches: list[list[OrderRecord]]) -> tuple[SslAccessor, Any]:
        accessor = SslAccessor(mock_client)
        finder = patch.object(accessor, "find_created_orders", side_effect=batches)
        return accessor, finder

    def test_single_match_is_fetched_and_returned(self, mock_client: MagicMock) -> None:
        accessor, finder = self._accessor(mock_client, [[_record("7527842798", _SENT)]])
        with finder, patch.object(accessor, "get", return_value=_FAKE_ORDER) as get:
            assert accessor.recover_timed_out_create(_timeout_error()) is _FAKE_ORDER
        get.assert_called_once_with("7527842798")

    def test_order_appearing_late_is_found(self, mock_client: MagicMock) -> None:
        accessor, finder = self._accessor(mock_client, [[], [], [_record("N1", _SENT)]])
        with finder, patch.object(accessor, "get", return_value=_FAKE_ORDER), \
                patch("certinext.ssl_certificates.time.sleep") as sleep:
            assert accessor.recover_timed_out_create(_timeout_error(), interval=10) is _FAKE_ORDER
        assert sleep.call_count == 2

    def test_several_matches_raise_with_candidates(self, mock_client: MagicMock) -> None:
        accessor, finder = self._accessor(mock_client, [[_record("A", _SENT), _record("B", _SENT)]])
        with finder, patch.object(accessor, "get") as get, pytest.raises(CertiNextOrderRecoveryError) as info:
            accessor.recover_timed_out_create(_timeout_error())
        assert info.value.candidates == ["A", "B"]
        get.assert_not_called()

    def test_none_found_by_deadline_raises_empty(self, mock_client: MagicMock) -> None:
        accessor, finder = self._accessor(mock_client, [[], [], []])
        clock = iter([0.0, 5.0, 25.0, 31.0])
        with finder, patch("certinext.ssl_certificates.time.sleep"), \
                patch("certinext.ssl_certificates.time.monotonic", side_effect=lambda: next(clock)), \
                pytest.raises(CertiNextOrderRecoveryError) as info:
            accessor.recover_timed_out_create(_timeout_error(), wait=30, interval=10)
        assert info.value.candidates == []


class TestCliHandleCreateTimeout:
    """issue-cert lists candidates by default and adopts only with --recover-on-timeout.

    The module logger is replaced: the CLI configures structlog with
    ``cache_logger_on_first_use``, so touching ``issue_cert.log`` here would pin
    it to the current processor list and break later ``capture_logs()``
    assertions in other modules (test_issue_cert_domain, once
    test_issue_cert_create_errors has re-run ``setup_logging``). ``new=`` is
    explicit on purpose: without it, ``patch`` probes the original for
    ``__func__`` to choose an AsyncMock, and that attribute access on
    structlog's lazy proxy is itself a first use.
    """

    @pytest.fixture(autouse=True)
    def _quiet_log(self) -> Any:
        """Replace issue_cert's module logger without touching the real one."""
        mock_log = MagicMock()
        with patch("certinext.cli.issue_cert.log", new=mock_log):
            yield mock_log

    def test_default_lists_candidates_and_exits(self) -> None:
        sess = MagicMock()
        sess.ssl.find_created_orders.return_value = [_record("N1", _SENT)]
        with pytest.raises(SystemExit) as info:
            _handle_create_timeout(sess, _timeout_error(), recover=False)
        assert info.value.code == 1
        sess.ssl.recover_timed_out_create.assert_not_called()

    def test_recover_flag_returns_the_order(self) -> None:
        sess = MagicMock()
        sess.ssl.recover_timed_out_create.return_value = _FAKE_ORDER
        assert _handle_create_timeout(sess, _timeout_error(), recover=True) is _FAKE_ORDER

    def test_recover_flag_ambiguous_exits(self) -> None:
        sess = MagicMock()
        sess.ssl.recover_timed_out_create.side_effect = CertiNextOrderRecoveryError(_CN, ["A", "B"])
        with pytest.raises(SystemExit) as info:
            _handle_create_timeout(sess, _timeout_error(), recover=True)
        assert info.value.code == 1
