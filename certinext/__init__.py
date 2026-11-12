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
      is partially fixed (re-tested 2026-06-05): exact FQDN matches now work, but
      substring searches (values without ``"."``) return 0 results. Use ``pattern``
      for client-side filtering.
    - Passing both ``domain_status`` and ``dcv_status`` to
      :meth:`~certinext.domains.DomainAccessor.get_list` returns a 400 error.
      :meth:`~certinext.domains.DomainAccessor.get_pending_dcv` works around this
      by fetching all domains and filtering client-side.

Errors:
    All API errors raise a subclass of :class:`CertiNextAPIError` (a plain
    :class:`Exception` — deliberately independent of the HTTP transport
    library; transport-level failures raise :class:`httpx.HTTPError`
    instead). Typed subclasses are raised for
    specific status codes: :class:`CertiNextNotFoundError` (404),
    :class:`CertiNextConflictError` (409), and :class:`CertiNextRateLimitError`
    (429). All carry ``.status_code`` (int) and ``.body`` (dict or str). When
    the body is RFC 7807 JSON, ``.ems_code`` extracts the ``EMS-xxx`` code and
    ``.field_errors`` surfaces the ``errors`` array.

    A failed OAuth token request raises :class:`CertiNextAuthError` (a
    :class:`RuntimeError`, not an API error) with ``.status_code`` and
    ``.transient`` (502/503/504). The token request alone is retried twice
    on a transport error or a transient status; API calls are not retried.
"""

from .accounts import AccountAccessor, AccountInfo, CaLevelValidation, Group, Organization, OrgCaValidation
from .catalog import CatalogAccessor, CustomField, Product, ProductCategory
from .client import CertiNextClient, TimeoutSpec
from .csr import CsrInfo
from .domains import (
    VALID_DCV_METHODS,
    CaStatus,
    CertificateAuthority,
    DcvInfo,
    DcvMethod,
    DcvOption,
    DcvStatus,
    Domain,
    DomainAccessor,
    DomainStatus,
    filter_needs_dcv,
)
from .exceptions import (
    CertiNextAPIError,
    CertiNextAuthError,
    CertiNextConflictError,
    CertiNextCreateTimeoutError,
    CertiNextNotFoundError,
    CertiNextOrderRecoveryError,
    CertiNextRateLimitError,
    CertiNextTimeoutError,
)
from .ledger import LedgerAccessor, LedgerRecord
from .orders import CertificateStatus, OrderAccessor, OrderRecord
from .session import CertiNextSession
from .ssl_certificates import (
    CertificateDownload,
    DcvChallenge,
    OrderWorkflow,
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

KNOWN_API_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("Production - US", BASE_URL),
    ("Production - India", "https://api.certinext.io"),
    ("QA", "https://qa-api.certinext.io"),
    ("Demo", "https://demo-api.certinext.io"),
)
"""Known CERTInext REST API endpoints as ``(label, base_url)`` pairs, taken from
the certinext-v2 OpenAPI ``servers`` list
(``https://<host>/v3/api-docs/certinext-v2``). ``certinext-setup-defaults``
presents these as a menu. The token endpoint for each is
``<base_url>/oauth/token``; the US sandbox is selected via the ``sandbox`` flag
rather than listed here. ``https://api.certinext.io`` is the India (global)
production region."""


def session(
    base_url: str = "",
    token_url: str = "",
    client_id: str = "",
    client_secret: str = "",
    scope: str = "",
    sandbox: bool = False,
    timeout: TimeoutSpec | None = None,
    create_timeout: TimeoutSpec | None = None,
) -> CertiNextSession:
    """Create and return a new `CertiNextSession`.

    This is the recommended entry point for the library. The session obtains
    and caches an OAuth 2.0 bearer token automatically.

    When ``sandbox=True`` the sandbox endpoints are used by default — you do
    not need to pass explicit ``base_url`` / ``token_url`` values.  Explicit
    URL arguments always take precedence over the ``sandbox`` flag.

    Args:
        base_url: CertiNext API base URL. Defaults to the US production
            endpoint, or the US sandbox endpoint when ``sandbox=True``.
        token_url: OAuth 2.0 token endpoint URL. Defaults to the production
            (or sandbox) token endpoint to match ``base_url``.
        client_id: Your CertiNext account number (used as the OAuth client ID).
        client_secret: OAuth client secret generated in the CertiNext portal
            under Integrations → APIs → OAuth mode.
        scope: Optional OAuth scope string. Leave empty if not required.
        sandbox: When ``True``, connect to the sandbox environment and default
            ``base_url`` / ``token_url`` to the sandbox endpoints.
        timeout: Default request timeout — an :class:`httpx.Timeout` or
            seconds. Default: 10s connect, 60s read.
        create_timeout: Timeout for certificate creation only. Default: 10s
            connect, 180s read, because the vendor can take over a minute to
            answer while still creating the order.

    Returns:
        A configured `CertiNextSession` ready to make API calls.
    """
    resolved_base = base_url or (SANDBOX_BASE_URL if sandbox else BASE_URL)
    resolved_token = token_url or (SANDBOX_TOKEN_URL if sandbox else TOKEN_URL)
    return CertiNextSession(
        resolved_base, resolved_token, client_id, client_secret, scope, sandbox,
        timeout=timeout, create_timeout=create_timeout,
    )


__all__ = [
    "session",
    "BASE_URL",
    "TOKEN_URL",
    "SANDBOX_BASE_URL",
    "SANDBOX_TOKEN_URL",
    "KNOWN_API_ENDPOINTS",
    # CSR parsing
    "CsrInfo",
    # Exceptions
    "CertiNextAPIError",
    "CertiNextAuthError",
    "CertiNextConflictError",
    "CertiNextNotFoundError",
    "CertiNextRateLimitError",
    "CertiNextTimeoutError",
    "CertiNextCreateTimeoutError",
    "CertiNextOrderRecoveryError",
    # Core
    "CertiNextClient",
    "TimeoutSpec",
    "CertiNextSession",
    # Accounts
    "AccountAccessor",
    "AccountInfo",
    "CaLevelValidation",
    "Group",
    "Organization",
    "OrgCaValidation",
    # Catalog
    "CatalogAccessor",
    "CustomField",
    "Product",
    "ProductCategory",
    # Domains
    "Domain",
    "DomainAccessor",
    "DcvInfo",
    "DcvOption",
    "filter_needs_dcv",
    "CaStatus",
    "CertificateAuthority",
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
    "OrderWorkflow",
    "ReissueMode",
    "SslAccessor",
    "SslOrder",
    "SslOrderStatus",
]
