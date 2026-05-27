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

    for domain in sess.domain.get_list():
        print(domain)

Known API limitations (vendor bugs, pending fix):
    - The ``search`` parameter to :meth:`~certinext.domains.DomainAccessor.get_list`
      remains broken (re-tested 2026-05-27): FQDN searches (any value containing
      ``"."``) return all domains; substring searches return 0. Use ``pattern`` for
      client-side filtering.
    - Passing both ``domain_status`` and ``dcv_status`` to
      :meth:`~certinext.domains.DomainAccessor.get_list` returns a 400 error.
      :meth:`~certinext.domains.DomainAccessor.get_pending_dcv` works around this
      by fetching all domains and filtering client-side.

Errors:
    All API errors raise a subclass of :class:`CertiNextAPIError` (itself a
    subclass of :class:`requests.HTTPError`). Typed subclasses are raised for
    specific status codes: :class:`CertiNextNotFoundError` (404),
    :class:`CertiNextConflictError` (409), and :class:`CertiNextRateLimitError`
    (429). All carry ``.status_code`` (int) and ``.body`` (dict or str). When
    the body is RFC 7807 JSON, ``.ems_code`` extracts the ``EMS-xxx`` code and
    ``.field_errors`` surfaces the ``errors`` array.
"""

from .accounts import AccountAccessor, AccountInfo, Group, Organization
from .catalog import CatalogAccessor, CustomField, Product, ProductCategory
from .client import CertiNextClient
from .domains import VALID_DCV_METHODS, DcvInfo, DcvMethod, DcvStatus, Domain, DomainAccessor, DomainStatus
from .exceptions import (
    CertiNextAPIError,
    CertiNextConflictError,
    CertiNextNotFoundError,
    CertiNextRateLimitError,
)
from .ledger import LedgerAccessor, LedgerRecord
from .orders import CertificateStatus, OrderAccessor, OrderRecord
from .session import CertiNextSession
from .ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    ReissueMode,
    SslAccessor,
    SslOrder,
    SslOrderStatus,
)

BASE_URL: str = "https://us-api.certinext.io"
"""Base URL for the CertiNext US production environment."""

TOKEN_URL: str = "https://us-api.certinext.io/oauth/token"
"""OAuth 2.0 token endpoint for the CertiNext US production environment."""

SANDBOX_BASE_URL: str = "https://sandbox-us-api.certinext.io"
"""Base URL for the CertiNext US sandbox environment."""

SANDBOX_TOKEN_URL: str = "https://sandbox-us-api.certinext.io/oauth/token"
"""OAuth 2.0 token endpoint for the CertiNext US sandbox environment."""


def session(
    base_url: str = BASE_URL,
    token_url: str = TOKEN_URL,
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
    "BASE_URL",
    "TOKEN_URL",
    "SANDBOX_BASE_URL",
    "SANDBOX_TOKEN_URL",
    # Exceptions
    "CertiNextAPIError",
    "CertiNextConflictError",
    "CertiNextNotFoundError",
    "CertiNextRateLimitError",
    # Core
    "CertiNextClient",
    "CertiNextSession",
    # Accounts
    "AccountAccessor",
    "AccountInfo",
    "Group",
    "Organization",
    # Catalog
    "CatalogAccessor",
    "CustomField",
    "Product",
    "ProductCategory",
    # Domains
    "Domain",
    "DomainAccessor",
    "DcvInfo",
    "DcvMethod",
    "DcvStatus",
    "DomainStatus",
    "VALID_DCV_METHODS",
    # Ledger
    "LedgerAccessor",
    "LedgerRecord",
    # Orders
    "CertificateStatus",
    "OrderAccessor",
    "OrderRecord",
    # SSL/TLS Certificates
    "CertificateDownload",
    "DcvChallenge",
    "ReissueMode",
    "SslAccessor",
    "SslOrder",
    "SslOrderStatus",
]
