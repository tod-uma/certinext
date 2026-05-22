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

from typing import Any

from requests.exceptions import HTTPError


class CertiNextAPIError(HTTPError):
    """An HTTP error response from the CertiNext API.

    Subclasses :class:`requests.HTTPError` so existing code that catches
    ``HTTPError`` continues to work. Adds :attr:`status_code` and
    :attr:`body` so callers can inspect what the API actually returned.

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
        """Return a string showing the status code and response body."""
        return f"HTTP {self.status_code}: {self.body}"
