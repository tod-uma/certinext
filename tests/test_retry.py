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

"""Tests for the opt-in read retry policy (certinext.retry, ADR 0025).

The client runs against an ``httpx.MockTransport``, so status codes and the
``Retry-After`` header go through the real request and error-mapping code.
"""

from unittest.mock import MagicMock

import httpx
import pytest

import certinext
from certinext import CertiNextAPIError, CertiNextRateLimitError, RetryPolicy
from certinext.client import CertiNextClient
from certinext.retry import retry_after_seconds

_BASE = "https://api.example.test"


class _Script:
    """Serve scripted responses in order and count the requests."""

    def __init__(self, *responses: httpx.Response) -> None:
        """
        Args:
            responses: Responses to return, one per request; the last repeats.
        """
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        """Return the next scripted response.

        Args:
            request: The outgoing request.

        Returns:
            The next response (the last one once the script runs out).
        """
        self.requests.append(request)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


def _status(code: int, retry_after: str | None = None) -> httpx.Response:
    """Build an error response, optionally with Retry-After.

    Args:
        code: HTTP status.
        retry_after: Raw header value, or None for no header.

    Returns:
        The response.
    """
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return httpx.Response(code, headers=headers, json={"title": "nope"})


_OK = httpx.Response(200, json={"ok": True})


def _client(script: _Script, policy: RetryPolicy | None) -> CertiNextClient:
    """Build a client whose HTTP goes to ``script``.

    Args:
        script: The scripted transport handler.
        policy: The retry policy, or None.

    Returns:
        The client, with token fetching mocked out.
    """
    client = CertiNextClient(_BASE, f"{_BASE}/oauth/token", "id", "secret", retry=policy)
    client._auth = MagicMock()
    client._auth.get_token.return_value = "token"
    client._session = httpx.Client(transport=httpx.MockTransport(script))
    return client


def _policy(waits: list[float], **kwargs: object) -> RetryPolicy:
    """Build a policy that records its waits instead of sleeping.

    Args:
        waits: List the waits are appended to.
        **kwargs: Other :class:`RetryPolicy` fields.

    Returns:
        The policy.
    """
    return RetryPolicy(sleep=waits.append, **kwargs)  # type: ignore[arg-type]


def test_no_policy_raises_first_failure() -> None:
    """Without a policy the client behaves as before: one request, then raise."""
    script = _Script(_status(503), _OK)
    with pytest.raises(CertiNextAPIError) as info:
        _client(script, None).get("/x")
    assert info.value.status_code == 503
    assert len(script.requests) == 1


@pytest.mark.parametrize("code", [429, 502, 503, 504])
def test_retryable_status_recovers(code: int) -> None:
    """Each default status is retried and the later success is returned."""
    waits: list[float] = []
    script = _Script(_status(code), _OK)
    assert _client(script, _policy(waits)).get("/x") == {"ok": True}
    assert len(script.requests) == 2
    assert waits == [5.0]


def test_retry_after_is_honoured_for_429_and_5xx() -> None:
    """The server's Retry-After sets the wait, whatever the retryable status."""
    waits: list[float] = []
    script = _Script(_status(429, "7"), _status(503, "2"), _OK)
    assert _client(script, _policy(waits)).get("/x") == {"ok": True}
    assert waits == [7.0, 2.0]


def test_backoff_doubles_without_retry_after() -> None:
    """With no Retry-After the base delay doubles per retry, capped at max_delay."""
    waits: list[float] = []
    script = _Script(_status(502))
    with pytest.raises(CertiNextAPIError):
        _client(script, _policy(waits, attempts=4, delay=1.0, max_delay=3.0)).get("/x")
    assert waits == [1.0, 2.0, 3.0]


def test_no_sleep_after_the_last_attempt() -> None:
    """The final failure raises at once; the old lookup helper slept once more first."""
    waits: list[float] = []
    script = _Script(_status(429, "1"))
    with pytest.raises(CertiNextRateLimitError) as info:
        _client(script, _policy(waits)).get("/x")
    assert len(script.requests) == 3
    assert waits == [1.0, 1.0]
    assert info.value.retry_after == 1.0


def test_retry_after_beyond_max_delay_is_not_retried() -> None:
    """Retrying sooner than the server asked would only earn another 429."""
    waits: list[float] = []
    script = _Script(_status(429, "600"), _OK)
    with pytest.raises(CertiNextRateLimitError):
        _client(script, _policy(waits, max_delay=60.0)).get("/x")
    assert waits == []
    assert len(script.requests) == 1


@pytest.mark.parametrize("code", [400, 404, 409, 500])
def test_other_statuses_are_not_retried(code: int) -> None:
    """Statuses outside the policy raise on the first attempt."""
    waits: list[float] = []
    script = _Script(_status(code), _OK)
    with pytest.raises(CertiNextAPIError):
        _client(script, _policy(waits)).get("/x")
    assert waits == [] and len(script.requests) == 1


def test_custom_statuses() -> None:
    """A caller can widen the retried statuses."""
    waits: list[float] = []
    script = _Script(_status(500), _OK)
    assert _client(script, _policy(waits, statuses=frozenset({500}))).get("/x") == {"ok": True}


def test_get_bytes_is_retried() -> None:
    """Binary downloads use the same policy."""
    waits: list[float] = []
    script = _Script(_status(503), httpx.Response(200, content=b"PEM"))
    assert _client(script, _policy(waits)).get_bytes("/x", "application/x-pem-file") == b"PEM"
    assert waits == [5.0]


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_writes_are_never_retried(method: str) -> None:
    """Writes are not idempotent (certificate creation), so they never retry."""
    waits: list[float] = []
    script = _Script(_status(503), _OK)
    client = _client(script, _policy(waits))
    with pytest.raises(CertiNextAPIError):
        getattr(client, method)("/x")
    assert waits == [] and len(script.requests) == 1


def test_attempts_one_disables_retry() -> None:
    """``attempts=1`` means a single try."""
    waits: list[float] = []
    script = _Script(_status(429, "1"), _OK)
    with pytest.raises(CertiNextRateLimitError):
        _client(script, _policy(waits, attempts=1)).get("/x")
    assert waits == []


@pytest.mark.parametrize("kwargs", [{"attempts": 0}, {"delay": -1.0}, {"max_delay": -1.0}])
def test_policy_validation(kwargs: dict[str, float]) -> None:
    """Nonsense numbers are refused at construction."""
    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("header", "expected"),
    [("3", 3.0), ("0.5", 0.5), ("0", 0.0), ("-1", None), ("soon", None), ("Wed, 21 Oct 2026 07:28:00 GMT", None)],
)
def test_retry_after_parsing(header: str, expected: float | None) -> None:
    """Only non-negative delta-seconds count; dates and junk are absent."""
    assert retry_after_seconds(httpx.Response(429, headers={"Retry-After": header})) == expected


def test_retry_after_absent() -> None:
    """No header, or no response at all, means no value."""
    assert retry_after_seconds(httpx.Response(429)) is None
    assert retry_after_seconds(None) is None


def test_session_factory_and_property() -> None:
    """``certinext.session(retry=...)`` reaches the client; the property reads and replaces it."""
    policy = RetryPolicy()
    sess = certinext.session(client_id="id", client_secret="s", retry=policy)
    assert sess.retry is policy and sess._client.retry is policy
    sess.retry = None
    assert sess._client.retry is None


def test_retrying_scopes_and_restores() -> None:
    """``retrying`` applies a policy for the block and restores the old one, even on error."""
    outer = RetryPolicy(attempts=2)
    inner = RetryPolicy(attempts=5)
    sess = certinext.session(client_id="id", client_secret="s", retry=outer)
    with sess.retrying(inner) as same:
        assert same is sess and sess.retry is inner
    assert sess.retry is outer
    with pytest.raises(RuntimeError), sess.retrying(None):
        assert sess.retry is None
        raise RuntimeError
    assert sess.retry is outer


def test_models_share_the_session_policy() -> None:
    """A model returned earlier reads through the same client, so it sees a later policy."""
    sess = certinext.session(client_id="id", client_secret="s")
    order = certinext.SslOrder.from_payload(sess._client, {"orderId": "1"})
    sess.retry = RetryPolicy()
    assert order._client is not None
    assert order._client.retry is sess.retry
