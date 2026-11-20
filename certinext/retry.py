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

"""Opt-in retry policy for idempotent API reads (ADR 0025).

A :class:`RetryPolicy` on a session makes :meth:`CertiNextClient.get` and
:meth:`CertiNextClient.get_bytes` retry a rate limit (429) or a gateway
failure (502/503/504). Writes are never retried: certificate creation is not
idempotent (ADR 0020). Without a policy, which is the default, the client
raises on the first failure as it always has.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from certinext.exceptions import CertiNextAPIError, CertiNextRateLimitError

#: Statuses retried by default: a rate limit, and a gateway that is down or
#: overloaded. Both mean the request was not processed.
DEFAULT_RETRY_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})


def retry_after_seconds(response: httpx.Response | None) -> float | None:
    """Parse a response's ``Retry-After`` header as seconds.

    Only the delta-seconds form is understood, which is what CertiNext
    sends; an HTTP-date or junk value counts as absent.

    Args:
        response: The HTTP response, or None.

    Returns:
        The non-negative delay in seconds, or None when absent or unparseable.
    """
    if response is None:
        return None
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


@dataclass(frozen=True)
class RetryPolicy:
    """How a session retries failed reads.

    Pass one to :func:`certinext.session` (``retry=RetryPolicy()``), set
    :attr:`CertiNextSession.retry`, or scope one to a block with
    :meth:`CertiNextSession.retrying`.

    The wait before each retry is the response's ``Retry-After`` when it has
    one, otherwise ``delay`` doubled per retry (5s, then 10s by default). A
    ``Retry-After`` above ``max_delay`` is not retried at all: retrying
    sooner than the server asked would only earn another 429, and waiting
    that long is the caller's decision. There is no wait after the last
    attempt; the error is raised straight away.

    Attributes:
        attempts: Total tries, including the first. 1 disables retrying.
        statuses: HTTP statuses that are retried.
        delay: Base wait in seconds when the response gives no
            ``Retry-After``.
        max_delay: Longest wait accepted, in seconds; also caps the doubled
            ``delay``.
        sleep: Called with each wait in seconds. Replace it to coordinate
            several workers (``replacement-report`` pauses them all) or to
            avoid real sleeps in tests.
    """

    attempts: int = 3
    statuses: frozenset[int] = DEFAULT_RETRY_STATUSES
    delay: float = 5.0
    max_delay: float = 120.0
    sleep: Callable[[float], None] = field(default=time.sleep, compare=False)

    def __post_init__(self) -> None:
        """Validate the numbers.

        Raises:
            ValueError: If ``attempts`` is below 1 or a delay is negative.
        """
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")
        if self.delay < 0 or self.max_delay < 0:
            raise ValueError("delays must not be negative")

    def wait_before_retry(self, exc: CertiNextAPIError, attempt: int) -> float | None:
        """Decide whether to retry after ``exc`` and how long to wait first.

        Args:
            exc: The error the attempt raised.
            attempt: The attempt that failed, counting from 1.

        Returns:
            Seconds to wait before the next attempt, or None to give up and
            re-raise ``exc``.
        """
        if exc.status_code not in self.statuses or attempt >= self.attempts:
            return None
        if isinstance(exc, CertiNextRateLimitError) and exc.retry_after is not None:
            asked: float | None = exc.retry_after
        else:
            asked = retry_after_seconds(exc.response)
        if asked is not None:
            return asked if asked <= self.max_delay else None
        return min(self.delay * 2.0 ** (attempt - 1), self.max_delay)
