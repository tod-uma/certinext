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

"""CertiNext API client library.

Typical usage::

    import certinext

    sess = certinext.session(
        client_id="YOUR_ACCOUNT_NUMBER",
        client_secret="YOUR_CLIENT_SECRET",
    )

    for domain in sess.domain.list():
        print(domain)
"""

from .client import CertiNextClient
from .domains import VALID_DCV_METHODS, Domain, DomainAccessor
from .exceptions import CertiNextAPIError
from .session import CertiNextSession


def session(
    base_url: str = "https://us-api.certinext.io",
    token_url: str = "https://us-api.certinext.io/oauth/token",
    client_id: str = "",
    client_secret: str = "",
    scope: str = "",
) -> CertiNextSession:
    """Create and return a new `CertiNextSession`.

    This is the recommended entry point for the library. The session obtains
    and caches an OAuth 2.0 bearer token automatically.

    Args:
        base_url: CertiNext API base URL. Defaults to the US production endpoint.
        token_url: OAuth 2.0 token endpoint URL.
        client_id: Your CertiNext account number (used as the OAuth client ID).
        client_secret: OAuth client secret generated in the CertiNext portal
            under Integrations → APIs → OAuth mode.
        scope: Optional OAuth scope string. Leave empty if not required.

    Returns:
        A configured `CertiNextSession` ready to make API calls.
    """
    return CertiNextSession(base_url, token_url, client_id, client_secret, scope)


__all__ = [
    "session",
    "CertiNextAPIError",
    "CertiNextClient",
    "CertiNextSession",
    "Domain",
    "DomainAccessor",
    "VALID_DCV_METHODS",
]
