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

"""CertiNext exception classes."""

import re
from typing import Any

from requests.exceptions import HTTPError


class CertiNextAPIError(HTTPError):
    """An HTTP error response from the CertiNext API.

    Subclasses :class:`requests.HTTPError` so existing code that catches
    ``HTTPError`` continues to work. Adds :attr:`status_code` and
    :attr:`body` so callers can inspect what the API actually returned.

    The API returns RFC 7807 ``application/problem+json`` bodies. When the
    response is parsed JSON, ``__str__`` extracts the ``detail`` field for a
    human-readable message, and :attr:`ems_code` and :attr:`field_errors`
    expose the structured diagnostic fields.

    Attributes:
        status_code: The HTTP status code (e.g. 422).
        body: Parsed JSON response body as a dict, or raw text if the
            response was not valid JSON.
    """

    def __init__(
        self,
        status_code: int,
        body: dict[str, Any] | str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """
        Args:
            status_code: The HTTP status code returned by the API.
            body: Parsed JSON response body, or raw response text.
            *args: Forwarded to :class:`requests.HTTPError`.
            **kwargs: Forwarded to :class:`requests.HTTPError` (e.g. ``response=``).
        """
        self.status_code = status_code
        self.body = body
        super().__init__(*args, **kwargs)

    def __str__(self) -> str:
        """Return a string with the status code and the most useful error message available.

        Checks RFC 7807 fields (``detail``, ``title``) first, then Spring Boot
        fields (``error``, ``message``). Appends ``path`` when present so
        404/405 responses identify the missing endpoint.
        """
        if isinstance(self.body, dict):
            message = (
                self.body.get("detail")
                or self.body.get("title")
                or self.body.get("message")
                or self.body.get("error")
                or str(self.body)
            )
            path = self.body.get("path")
            if path:
                message = f"{message} ({path})"
            return f"HTTP {self.status_code}: {message}"
        return f"HTTP {self.status_code}: {self.body}"

    @property
    def ems_code(self) -> str | None:
        """Return the EMS error code from the response body, or None.

        Searches the RFC 7807 ``detail`` field first, then the ``type`` URL.
        Matches codes of the form ``EMS-NNN`` or ``EMS-WORD-NNN``.
        """
        if not isinstance(self.body, dict):
            return None
        for field in ("detail", "type"):
            value = self.body.get(field)
            if isinstance(value, str):
                m = re.search(r'\b(EMS-[A-Z0-9]+(?:-[A-Z0-9]+)*)', value)
                if m:
                    return m.group(1)
        return None

    @property
    def field_errors(self) -> list[dict[str, str]]:
        """Return field-level validation errors from the RFC 7807 ``errors`` array.

        Returns an empty list when the body is not JSON or contains no ``errors`` key.
        """
        if not isinstance(self.body, dict):
            return []
        errors = self.body.get("errors", [])
        return errors if isinstance(errors, list) else []


class CertiNextNotFoundError(CertiNextAPIError):
    """Raised when the API returns 404 Not Found.

    The requested resource (domain, order, certificate, etc.) does not exist
    or the caller's account does not have access to it.
    """


class CertiNextRateLimitError(CertiNextAPIError):
    """Raised when the API returns 429 Too Many Requests.

    The API includes a ``Retry-After`` response header when rate-limiting.

    Attributes:
        retry_after: Seconds to wait before retrying, taken from the
            ``Retry-After`` response header. ``None`` if the header was absent
            or could not be parsed as a number.
    """

    def __init__(
        self,
        status_code: int,
        body: dict[str, Any] | str,
        *args: Any,
        retry_after: float | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Args:
            status_code: HTTP status code (429).
            body: Parsed JSON or raw response text.
            retry_after: Value of the ``Retry-After`` response header in seconds.
            *args: Forwarded to :class:`CertiNextAPIError`.
            **kwargs: Forwarded to :class:`CertiNextAPIError`.
        """
        self.retry_after = retry_after
        super().__init__(status_code, body, *args, **kwargs)


class CertiNextTimeoutError(TimeoutError):
    """Raised when polling for order issuance exceeds the configured wait limit.

    Subclasses the built-in :exc:`TimeoutError` so callers can catch it
    with either ``CertiNextTimeoutError`` or the standard ``TimeoutError``.

    Attributes:
        order_id: The order that did not issue in time. Pass this value to
            ``--order-id`` (or :meth:`~certinext.ssl_certificates.SslAccessor.get`)
            to resume polling.
        wait: The wait limit in seconds that was exceeded.
    """

    def __init__(self, order_id: str | None, wait: int) -> None:
        """
        Args:
            order_id: The order ID that timed out.
            wait: The wait limit in seconds that was exceeded.
        """
        self.order_id = order_id
        self.wait = wait
        super().__init__(
            f"Order {order_id!r} did not reach 'issued' status within {wait}s"
        )


class CertiNextConflictError(CertiNextAPIError):
    """Raised when the API returns 409 Conflict.

    Occurs for duplicate resource creation, most commonly when registering a
    domain that already exists (EMS-DOMAIN-002 or EMS-DOMAIN-101).

    Attributes:
        existing_domain_id: The ID of the pre-existing domain, if the API
            included ``existingDomainId`` in the response body (EMS-DOMAIN-101).
            ``None`` when not present.
    """

    @property
    def existing_domain_id(self) -> str | None:
        """Return the pre-existing domain's ID from the response body, if present."""
        if isinstance(self.body, dict):
            return self.body.get("existingDomainId")
        return None
