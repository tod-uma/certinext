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

"""Pydantic models for the Domains API (domains and DCV results).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
:class:`Domain` carries the HTTP client in a private attribute (set by
:meth:`Domain.from_payload`) so its verb methods keep working.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, cast

import structlog
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PrivateAttr, model_validator

from ..client import CertiNextClient
from ._base import CertiNextModel

log = structlog.get_logger()

_BASE = "/api/certinext/v2/domains"

DomainStatus = Literal["ACTIVE", "INACTIVE", "EXPIRED", "REVOKED"]
"""Valid values returned by :attr:`Domain.status`."""

DcvStatus = Literal["VERIFIED", "PENDING", "REJECTED", "EXPIRED"]
"""Valid values returned by :attr:`Domain.dcv_status`."""

DcvMethod = Literal["DNS-TXT", "HTTP-URL"]
"""Valid DCV method strings accepted by :meth:`Domain.change_dcv_method`."""

VALID_DCV_METHODS: frozenset[str] = frozenset({"DNS-TXT", "HTTP-URL"})


def _has_ns_records(name: str) -> bool:
    """Return True if name has its own NS records, indicating a DNS zone boundary.

    Requires dnspython (``pip install certinext[dns]``). Returns ``False``
    when dnspython is not installed or the query fails, erring on the side of
    assuming the parent covers the domain.

    Args:
        name: Fully-qualified domain name to query for NS records.

    Returns:
        ``True`` if NS records were found, ``False`` otherwise or on error.
    """
    try:
        import dns.resolver
        dns.resolver.resolve(name, "NS")
        return True
    except ImportError:
        log.debug(
            "dnspython not installed - skipping NS check",
            domain=name,
        )
        return False
    except Exception:
        return False


def _lenient_datetime(value: Any) -> datetime | None:
    """Parse a wire timestamp into a timezone-aware datetime, or ``None``.

    Mirrors the 0.3.x property behavior: absent/null/empty values and
    unparseable strings yield ``None`` rather than a ``ValidationError``
    (ADR 0005).

    Args:
        value: The raw wire value (ISO 8601 string expected).

    Returns:
        The parsed datetime, or ``None``.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


_LenientDatetime = Annotated[datetime | None, BeforeValidator(_lenient_datetime)]


class DcvInfo(BaseModel):
    """Parsed DCV configuration returned by :meth:`Domain.get_dcv`.

    Normalises the raw API response so callers don't need to handle multiple
    field name variants or case differences. Build from a wire payload with
    :meth:`from_wire`; direct keyword construction preserves values verbatim.

    Attributes:
        method: DCV method in upper case, e.g. ``DNS-TXT`` or ``HTTP-URL``.
        token:  Challenge value to publish. For DNS-TXT this is the TXT record
                content (``txtToken``); for HTTP-URL it is the file token
                (``fileToken``).
        host:   Sub-domain prefix for the challenge record. The Domains API
                does not return this field; the DNS-TXT challenge is implicitly
                placed at ``_emudhra-challenge.<domain>``.
    """

    model_config = ConfigDict(populate_by_name=True)

    method: str = Field(description="DCV method in upper case, e.g. ``DNS-TXT`` or ``HTTP-URL``.")
    token: str = Field(description="Challenge value to publish.")
    host: str = Field(description="Sub-domain prefix for the challenge record.")

    @classmethod
    def from_wire(cls, raw: dict[str, Any]) -> "DcvInfo":
        """Build a DcvInfo from a raw DCV endpoint payload.

        Resolves the 0.3.x fallback chains exactly (a falsy value in an
        earlier candidate falls through to the next — semantics
        ``AliasChoices`` cannot express): ``dcvMethod``/``method`` (upper-cased),
        ``txtToken``/``fileToken``/``token``/``dnsContents``, and
        ``dnsHost``/``host``. Missing chains resolve to ``""``.

        Args:
            raw: The raw API response dict from the DCV endpoint.

        Returns:
            The normalised DcvInfo.
        """
        method = (raw.get("dcvMethod") or raw.get("method") or "").upper()
        token = raw.get("txtToken") or raw.get("fileToken") or raw.get("token") or raw.get("dnsContents") or ""
        host = raw.get("dnsHost") or raw.get("host") or ""
        return cls(method=method, token=token, host=host)


class DcvVerifyResult(CertiNextModel):
    """Summary of a DCV verification trigger returned by :meth:`Domain.verify`.

    Wraps the raw multi-perspective diagnostic response and exposes only the
    fields that matter for logging and decision-making. The raw response data
    is available via :attr:`raw` when deeper inspection is needed.

    Attributes:
        overall_status: Top-level outcome — typically ``"VERIFIED"`` or
            ``"PENDING"``.
        agreed: ``True`` when all queried perspectives reached consensus.
        perspectives_queried: Number of geographic perspectives that checked
            the challenge record.
    """

    overall_status: str = Field(
        default="unknown",
        description='Top-level outcome - typically ``"VERIFIED"`` or ``"PENDING"``.',
    )
    agreed: bool = Field(
        default=False,
        description="``True`` when all queried perspectives reached consensus.",
    )
    perspectives_queried: int = Field(
        default=0,
        description="Number of geographic perspectives that checked the challenge record.",
    )

    @model_validator(mode="before")
    @classmethod
    def _from_wire(cls, data: Any) -> Any:
        """Derive the summary fields from the raw verify payload.

        Passes through untouched when the input already uses the model's own
        field names (programmatic construction).

        Args:
            data: The raw wire payload or a field-name keyed dict.

        Returns:
            A dict with the three summary fields resolved.
        """
        if not isinstance(data, dict):
            return data
        if {"overall_status", "agreed", "perspectives_queried"} & data.keys():
            return data
        consensus: dict[str, Any] = (data.get("diagnostics") or {}).get("consensus") or {}
        return {
            "overall_status": str(data.get("overallStatus") or data.get("status") or "unknown"),
            "agreed": bool(consensus.get("agreed", False)),
            "perspectives_queried": int(consensus.get("totalPerspectivesQueried", 0)),
        }

    @property
    def raw(self) -> dict[str, Any]:
        """The raw API response dict from the verify endpoint."""
        return self._raw if self._raw is not None else {}

    def __str__(self) -> str:
        """Return a short human-readable summary of the verification result."""
        return (
            f"overall_status={self.overall_status} "
            f"agreed={self.agreed} "
            f"perspectives={self.perspectives_queried}"
        )

    def __repr__(self) -> str:
        """Return a developer-friendly representation."""
        return f"DcvVerifyResult({self!s})"


class Domain(CertiNextModel):
    """Represents a single CertiNext domain resource.

    Instances are returned by `DomainAccessor` methods and should not be
    constructed directly. All API response fields are exposed as read-only
    attributes; assigning to ``name`` updates the local object only — call
    the appropriate API method to persist changes to the server.

    Supports ``str()`` for human-readable output and ``repr()`` for a concise
    developer representation, so you can use ``print(domain)`` directly.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        domain = sess.domain.get("maine.edu")
        print(domain)
        domain.verify()
    """

    id: str | None = Field(
        default=None,
        alias="domainId",
        description="Unique domain ID assigned by CertiNext.",
    )
    name: str | None = Field(
        default=None,
        alias="domainName",
        description="Fully-qualified domain name (e.g. ``maine.edu``).",
    )
    organization_id: str | None = Field(
        default=None,
        alias="organizationId",
        description="ID of the organization this domain belongs to.",
    )
    organization_name: str | None = Field(
        default=None,
        alias="organizationName",
        description="Display name of the organization this domain belongs to.",
    )
    status: str | None = Field(
        default=None,
        description="Domain status. One of ``ACTIVE``, ``INACTIVE``, ``EXPIRED``, ``REVOKED``.",
    )
    dcv_status: str | None = Field(
        default=None,
        alias="dcvStatus",
        description="DCV status. One of ``VERIFIED``, ``PENDING``, ``REJECTED``, ``EXPIRED``.",
    )
    created_at: _LenientDatetime = Field(
        default=None,
        alias="createdAt",
        description="Creation timestamp as a timezone-aware UTC datetime, or ``None``.",
    )
    verified_at: _LenientDatetime = Field(
        default=None,
        alias="verifiedAt",
        description="Timestamp when DCV was last completed, or ``None`` when not yet verified.",
    )
    dcv_expires: _LenientDatetime = Field(
        default=None,
        alias="validTill",
        description=(
            "DCV token expiry as a timezone-aware UTC datetime, or ``None``. "
            "Only present after DCV has been completed; ``None`` for domains "
            "in PENDING or REJECTED state."
        ),
    )

    _client: CertiNextClient | None = PrivateAttr(default=None)

    @classmethod
    def from_payload(cls, client: CertiNextClient | None, data: Any) -> "Domain":
        """Build a Domain from a wire payload and attach the HTTP client.

        Args:
            client: The underlying HTTP client used by the verb methods
                (:meth:`refresh`, :meth:`verify`, ...). ``None`` produces a
                detached object usable for field access only.
            data: Raw API response dict for this domain (non-dict values
                validate as an empty payload).

        Returns:
            The validated Domain instance.
        """
        domain = cls.model_validate(data if isinstance(data, dict) else {})
        domain._client = client
        return domain

    def _require_client(self) -> CertiNextClient:
        """Return the attached HTTP client or raise for detached instances.

        Returns:
            The client set by :meth:`from_payload`.

        Raises:
            RuntimeError: When the Domain was constructed without a client.
        """
        if self._client is None:
            raise RuntimeError(
                "This Domain has no attached API client; "
                "obtain instances from a session accessor"
            )
        return self._client

    def _replace_payload(self, data: dict[str, Any]) -> None:
        """Re-validate ``data`` and update all fields and extras in place.

        Used by :meth:`refresh` and :meth:`deactivate`, which the 0.3.x class
        implemented by swapping the raw dict behind its properties.

        Args:
            data: The new raw payload dict.
        """
        fresh = type(self).model_validate(data)
        for field_name in type(self).model_fields:
            setattr(self, field_name, getattr(fresh, field_name))
        object.__setattr__(self, "__pydantic_extra__", fresh.__pydantic_extra__)
        self._raw = data

    # --- dunder methods ---

    def __str__(self) -> str:
        """Return a human-readable multi-line summary of the domain."""
        def row(label: str, value: Any) -> str:
            return f"  {label:<16} {value or ''}"
        lines = [f"Domain: {self.name or '(unknown)'}"]
        lines.append(row("id:", self.id))
        lines.append(row("status:", self.status))
        lines.append(row("dcv_status:", self.dcv_status))
        if self.dcv_expires:
            lines.append(row("dcv_expires:", self.dcv_expires))
        lines.append(row("organization:", self.organization_name))
        if self.created_at:
            lines.append(row("created:", self.created_at))
        return "\n".join(lines)

    def __repr__(self) -> str:
        """Return a concise developer representation of the domain."""
        return f"Domain(name={self.name!r}, status={self.status!r})"

    # --- public helpers ---

    @property
    def needs_dcv(self) -> bool:
        """Return True if this domain is active and not yet DCV-verified."""
        return self.status == "ACTIVE" and self.dcv_status != "VERIFIED"

    def dcv_expires_soon(self, days: int = 30) -> bool:
        """Return True if the DCV token expires within ``days`` days.

        Useful for building proactive renewal workflows — call this before
        :meth:`verify` to avoid letting DCV lapse.  Returns ``False`` when
        :attr:`dcv_expires` is ``None`` (field not present in the API
        response or domain has no active DCV token).

        Args:
            days: Number of days ahead to check. Default is 30.

        Returns:
            ``True`` if the DCV expiry is known and within ``days`` days
            from now (including already-expired tokens).
        """
        exp = self.dcv_expires
        if exp is None:
            return False
        return exp <= datetime.now(timezone.utc) + timedelta(days=days)

    def dcv_covering_parent(
        self,
        all_domain_names: set[str],
        *,
        check_ns: bool = True,
    ) -> str | None:
        """Return the closest registered ancestor that covers this domain's DCV, or None.

        CertiNext propagates DCV verification down the domain tree: once a
        parent is verified, its subdomains inherit that status automatically.
        This method finds the closest ancestor in *all_domain_names* that
        provides that coverage.

        However, propagation stops at DNS zone boundaries.  A subdomain that
        has its own NS records forms a separate DNS zone and **will not**
        inherit DCV from its parent — it must be validated directly.  When
        *check_ns* is ``True`` an NS DNS lookup is performed; if NS records
        are found ``None`` is returned even when a parent exists in
        *all_domain_names*.  Requires ``dnspython``
        (``pip install certinext[dns]``); falls back gracefully when not
        installed.

        .. note::

            Zone-boundary behaviour confirmed by members of the InCommon
            cert-users mailing list (2026-06-01):

            - **Cory Gekoski, University of Maryland** — identified the
              pattern: subdomains with MX records pointing to their own DNS
              servers failed to inherit DCV while those sharing the parent's
              DNS succeeded, suggesting a zone-delegation root cause.
            - **Blake Bourgeois, Louisiana State University** — confirmed the
              definitive indicator: every subdomain that did not inherit DCV
              had its own NS records (a distinct DNS subzone), regardless of
              MX configuration.

        Args:
            all_domain_names: Set of all registered domain names (typically
                the full account list). Used to identify covering ancestors.
            check_ns: When ``True`` (the default), query DNS for NS records
                to detect zone boundaries. Set to ``False`` to skip DNS
                lookups (useful in tests or environments without DNS access).

        Returns:
            The covering ancestor domain name, or ``None`` if no ancestor is
            registered or this domain is a DNS zone boundary.
        """
        if check_ns and _has_ns_records(self.name or ""):
            log.debug(
                "has NS records (DNS zone boundary) - DCV will not propagate from parent",
                domain=self.name,
            )
            return None
        labels = (self.name or "").split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in all_domain_names:
                return parent
        return None

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` of key fields suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "name": _s(self.name),
            "status": _s(self.status),
            "dcv_status": _s(self.dcv_status),
            "dcv_expires": self.dcv_expires.isoformat() if self.dcv_expires else "",
            "organization": _s(self.organization_name),
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "id": _s(self.id),
        }

    # --- API methods ---

    def refresh(self) -> "Domain":
        """Re-fetch this domain from the API and update all fields in place.

        Returns:
            ``self``, allowing method chaining.
        """
        result = self._require_client().get(f"{_BASE}/{self.id}")
        if isinstance(result, dict):
            self._replace_payload(result)
        return self

    def deactivate(self) -> "Domain":
        """Deactivate this domain and update fields from the API response.

        Returns:
            ``self``, allowing method chaining.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._require_client().post(f"{_BASE}/{self.id}/deactivate")
        if isinstance(result, dict):
            self._replace_payload(result)
        return self

    def get_dcv(self) -> DcvInfo:
        """Return the current Domain Control Validation configuration from the API.

        Returns:
            :class:`DcvInfo` with normalised ``method``, ``token``, and ``host``.

        Raises:
            ValueError: If the API reports a DCV method outside
                ``VALID_DCV_METHODS``.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result: dict[str, Any] | list[Any] = self._require_client().get(f"{_BASE}/{self.id}/dcv")
        raw: dict[str, Any] = result if isinstance(result, dict) else {}
        info = DcvInfo.from_wire(raw)
        if info.method and info.method not in VALID_DCV_METHODS:
            raise ValueError(
                f"Unexpected DCV method {info.method!r} from API; "
                f"expected one of {sorted(VALID_DCV_METHODS)}"
            )
        return info

    def verify(self) -> DcvVerifyResult:
        """Trigger DCV verification for this domain.

        Returns:
            A :class:`DcvVerifyResult` summarising the outcome. Call
            :meth:`refresh` and check :attr:`dcv_status` to confirm the
            final status once the CA has processed the result.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        raw: Any = self._require_client().post(f"{_BASE}/{self.id}/dcv/verify")
        return DcvVerifyResult.model_validate(raw if isinstance(raw, dict) else {})

    def change_dcv_method(self, method: DcvMethod) -> dict[str, Any]:
        """Change the DCV method for this domain.

        Args:
            method: The new DCV method. Must be ``"DNS-TXT"`` or ``"HTTP-URL"``.
                    Case-insensitive; normalized to upper case before validation
                    and to lower case before sending to the API.

        Returns:
            Raw API response dict containing the updated DCV configuration.

        Raises:
            ValueError: If ``method`` is not one of the accepted DCV methods.
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        method_upper = method.upper()
        if method_upper not in VALID_DCV_METHODS:
            raise ValueError(
                f"Invalid DCV method {method_upper!r}; must be one of {sorted(VALID_DCV_METHODS)}"
            )
        return self._require_client().patch(
            f"{_BASE}/{self.id}/dcv/method", json={"dcvMethod": method_upper.lower()}
        )

    def reinitiate_dcv(self) -> DcvInfo:
        """Reset the DCV challenge and return a fresh set of credentials.

        Calls :meth:`change_dcv_method` with the domain's current method to
        force the API to issue a new challenge token, even when the method is
        unchanged.  Use this when:

        - The domain is ``VERIFIED`` but the challenge token (``tokenExpiry``)
          has lapsed — :meth:`get_dcv` returns an empty token in this state.
        - You want to proactively revalidate a domain approaching DCV expiry
          (``validTill``) before it becomes ``EXPIRED``.

        The API issues a fresh ``tokenExpiry`` and new token value.  The
        previously published TXT or HTTP challenge artifact becomes **invalid**
        after this call — the old token will not satisfy a subsequent
        :meth:`verify` call.  Publish the returned token and call
        :meth:`verify` to complete revalidation.

        Returns:
            Fresh :class:`DcvInfo` with a new ``token`` and ``host`` for the
            same DCV method.

        Raises:
            ValueError: If the current DCV method cannot be determined or is
                not one of the accepted values (``"DNS-TXT"``, ``"HTTP-URL"``).
            CertiNextAPIError: On a non-2xx API response.
        """
        current = self.get_dcv()
        if not current.method or current.method not in VALID_DCV_METHODS:
            raise ValueError(
                f"Cannot reinitiate DCV for {self.name!r}: "
                f"current method {current.method!r} is not in "
                f"{sorted(VALID_DCV_METHODS)}"
            )
        self.change_dcv_method(cast(DcvMethod, current.method))
        return self.get_dcv()

    def last_dcv_attempt(self) -> dict[str, Any]:
        """Return details of the most recent DCV attempt for this domain.

        Returns:
            Raw API response dict. Contains attempt metadata such as timestamp
            and result; exact keys depend on the API version.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._require_client().get(f"{_BASE}/{self.id}/dcv/attempts/last")
        return result if isinstance(result, dict) else {}

    def dcv_attempt_history(self) -> dict[str, Any] | list[Any]:
        """Return the full DCV attempt history for this domain.

        Returns:
            Raw API response. May be a list of attempt dicts or a wrapper dict
            depending on the API version; iterate defensively.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        return self._require_client().get(f"{_BASE}/{self.id}/dcv/attempts")
