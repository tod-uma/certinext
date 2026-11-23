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

"""Read-only accessor for the v3 CLM API-credentials list (``/api/v3/certinext/apis``)."""

from ._v3 import V3_BASE, iter_v3_rows
from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.api_credentials import ApiCredential

__all__ = ["ApiCredential", "ApiCredentialAccessor"]

_PATH = f"{V3_BASE}/apis"


class ApiCredentialAccessor:
    """Accessor for the account's API credentials (metadata, never secrets).

    Mounted on a session as ``session.api_credentials``.

    Example::

        for cred in sess.api_credentials.get_list():
            print(cred.description, cred.api_type, cred.status)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """Initialise the accessor.

        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def get_list(self, page_size: int = 100) -> list[ApiCredential]:
        """Return every API credential, fetching all pages.

        Not capped at 20, as an earlier note claimed: 21 came back in one
        page with ``pageSize=100`` (prod, 2026-11-23).

        Args:
            page_size: Rows per page (default 100).

        Returns:
            All credentials.

        Raises:
            CertiNextAPIError: On a non-2xx API response.
        """
        rows = iter_v3_rows(self._client, _PATH, "credentials", page_size=page_size)
        return [ApiCredential.model_validate(r) for r in rows]
