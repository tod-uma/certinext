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

"""Pydantic models for DCV attempt history and attempt details.

The OpenAPI spec types every DCV-attempt response as a bare ``object``, so
these shapes come from the production payload corpus
(``tests/fixtures/corpus/prod/domains-dcv-attempts*.json``) and a read-only
survey of 80 production domains on 2026-11-19. Validation is lenient per
ADR 0005: every field is optional, unknown keys are kept, and the exact wire
payload stays reachable through :meth:`~CertiNextModel.as_dict`.

Two families of attempt exist, one per validating CA:

- **emSign** attempts have numeric-string ids and a rich
  :class:`DcvDiagnostics` block (per-resolver ``perspectives``,
  ``consensus``, ``nextSteps``, ``attemptTimestamp``).
- **SSL.com** keeps only its latest result. It appears as one attempt whose
  id is :data:`SSLCOM_LATEST`, with CA fields in the diagnostics
  (``caStatus``, ``caMessage``, ``mpic``, ``validTill``).
"""

from typing import Annotated, Any

from pydantic import BeforeValidator, Field

from ._base import CertiNextModel, _LenientDatetime, _LenientDatetimeUTC, coerce_flag

#: The attempt id the vendor gives the single, live-read attempt of every
#: SSL.com-validated domain (GitLab #38).
SSLCOM_LATEST = "sslcom-latest"


def _flag_or_none(value: Any) -> bool | None:
    """Coerce a wire flag to ``bool``, keeping absent values as ``None``.

    Args:
        value: The raw wire value.

    Returns:
        ``None`` for ``None``; otherwise :func:`coerce_flag` of the value.
    """
    return None if value is None else coerce_flag(value)


def _int_or_none(value: Any) -> int | None:
    """Parse a wire integer leniently.

    Args:
        value: The raw wire value.

    Returns:
        The integer, or ``None`` when absent or not an integer.
    """
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _list_or_empty(value: Any) -> list[Any]:
    """Return ``value`` when it is a list, else an empty list.

    Args:
        value: The raw wire value.

    Returns:
        The list, or ``[]``.
    """
    return value if isinstance(value, list) else []


def _dict_or_none(value: Any) -> dict[str, Any] | None:
    """Return ``value`` when it is a dict, else ``None``.

    Args:
        value: The raw wire value.

    Returns:
        The dict, or ``None``.
    """
    return value if isinstance(value, dict) else None


_Flag = Annotated[bool | None, BeforeValidator(_flag_or_none)]
_Int = Annotated[int | None, BeforeValidator(_int_or_none)]
_DictList = Annotated[list[dict[str, Any]], BeforeValidator(_list_or_empty)]
_Dict = Annotated[dict[str, Any] | None, BeforeValidator(_dict_or_none)]


class DcvAttemptSummary(CertiNextModel):
    """One row of a domain's DCV attempt history.

    Returned by :meth:`~certinext.models.domains.Domain.dcv_attempts`,
    newest first. Pass :attr:`attempt_id` to
    :meth:`~certinext.models.domains.Domain.get_dcv_attempt` for the
    diagnostics.

    The vendor omits fields freely: an SSL.com row carries only
    ``attemptId`` and ``overallStatus``, and most emSign rows have no
    ``method``.

    Example::

        for row in domain.dcv_attempts():
            print(row.attempted_at, row.overall_status, row.failure_class)
    """

    attempt_id: str | None = Field(
        default=None,
        alias="attemptId",
        description="Attempt id: a numeric string (emSign) or ``sslcom-latest``.",
    )
    attempted_at: _LenientDatetime = Field(
        default=None,
        alias="attemptedAt",
        description="When the attempt ran (UTC). Absent on SSL.com rows.",
    )
    overall_status: str | None = Field(
        default=None,
        alias="overallStatus",
        description='Attempt outcome, e.g. ``"VERIFIED"``.',
    )
    failure_class: str | None = Field(
        default=None,
        alias="failureClass",
        description=(
            'Failure category, e.g. ``"OK"``, ``"UNKNOWN"``, ``"ALL_FAILED"``, '
            '``"PARTIAL_CONSENSUS"``. Absent on SSL.com rows.'
        ),
    )
    method: str | None = Field(
        default=None,
        description=(
            'DCV method in the lower-case wire form, e.g. ``"dns-txt"``, '
            '``"dns-persist"``. Often absent.'
        ),
    )

    @property
    def is_sslcom_latest(self) -> bool:
        """Return True for the single live-read attempt of an SSL.com domain."""
        return self.attempt_id == SSLCOM_LATEST

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"DcvAttemptSummary(attempt_id={self.attempt_id!r}, "
            f"overall_status={self.overall_status!r}, attempted_at={self.attempted_at!r})"
        )


class DcvDiagnostics(CertiNextModel):
    """The ``diagnostics`` block of a DCV attempt.

    Holds the union of both CA families' fields; each attempt fills one
    family and leaves the other ``None``. The nested per-resolver blocks
    (:attr:`perspectives`, :attr:`consensus`, :attr:`next_steps`,
    :attr:`expected`) stay as wire dicts.
    """

    schema_version: _Int = Field(default=None, alias="schemaVersion", description="Diagnostics schema version.")
    overall_status: str | None = Field(default=None, alias="overallStatus", description="Attempt outcome (emSign).")
    failure_class: str | None = Field(default=None, alias="failureClass", description="Failure category (emSign).")
    method: str | None = Field(
        default=None,
        description=(
            'Check performed, in upper-case form, e.g. ``"DNS_TXT"``, '
            '``"CAA_PRECHECK"`` (emSign). Not the same vocabulary as '
            ":attr:`DcvAttemptSummary.method`."
        ),
    )
    attempt_timestamp: _LenientDatetimeUTC = Field(
        default=None,
        alias="attemptTimestamp",
        description=(
            "When the attempt ran (emSign). The wire value has no offset but "
            "is UTC: it matches the history row's ``attemptedAt`` to the "
            "second (production, 2026-11-19)."
        ),
    )
    token_is_stale: _Flag = Field(
        default=None, alias="tokenIsStale", description="Whether the DCV token had expired (emSign)."
    )
    ca_status: str | None = Field(
        default=None, alias="caStatus", description='CA validation status, e.g. ``"VALIDATED"`` (SSL.com).'
    )
    ca_external_status: str | None = Field(
        default=None, alias="caExternalStatus", description='The CA\'s own status string, e.g. ``"active"``.'
    )
    ca_message: str | None = Field(
        default=None, alias="caMessage", description="Why the CA's last check failed (SSL.com, failures only)."
    )
    mpic: str | None = Field(
        default=None,
        description='Multi-perspective corroboration summary, e.g. ``"corroborated 4/5"`` (SSL.com).',
    )
    valid_till: _LenientDatetime = Field(
        default=None, alias="validTill", description="When the CA's validation expires (SSL.com)."
    )
    validated_by: str | None = Field(
        default=None, alias="validatedBy", description='Validating CA, e.g. ``"SSLCOM"``.'
    )
    covers_subdomains: _Flag = Field(
        default=None,
        alias="coversSubdomains",
        description="Whether the validation also covers subdomains (SSL.com).",
    )
    option_id: str | None = Field(
        default=None, alias="optionId", description="DCV option the validation used (SSL.com, sometimes)."
    )
    perspectives: _DictList = Field(
        default_factory=list, description="Per-resolver results, as wire dicts (emSign)."
    )
    next_steps: _DictList = Field(
        default_factory=list,
        alias="nextSteps",
        description="Vendor-recommended next steps (``key``, ``severity``, ``params``) (emSign).",
    )
    consensus: _Dict = Field(default=None, description="Multi-perspective consensus summary (emSign).")
    expected: _Dict = Field(default=None, description="The record or file the check expected (emSign).")


class DcvAttempt(CertiNextModel):
    """Full details of one DCV attempt.

    Returned by :meth:`~certinext.models.domains.Domain.get_dcv_attempt`
    and :meth:`~certinext.models.domains.Domain.latest_dcv_attempt`.

    Example::

        attempt = domain.latest_dcv_attempt()
        if attempt and attempt.diagnostics:
            print(attempt.status, attempt.diagnostics.failure_class or attempt.diagnostics.ca_status)
    """

    attempt_id: str | None = Field(
        default=None,
        alias="attemptId",
        description=(
            "Attempt id. The wire carries it only for SSL.com attempts; "
            ":meth:`~certinext.models.domains.Domain.get_dcv_attempt` fills "
            "it in from the requested id for emSign ones."
        ),
    )
    domain_id: str | None = Field(default=None, alias="domainId", description="Opaque domain id.")
    status: str | None = Field(default=None, description='Attempt outcome, e.g. ``"VERIFIED"``.')
    method: str | None = Field(default=None, description='DCV method, e.g. ``"dns-txt"``. Often absent.')
    diagnostics: Annotated[DcvDiagnostics | None, BeforeValidator(_dict_or_none)] = Field(
        default=None, description="The diagnostics block."
    )

    @property
    def is_sslcom_latest(self) -> bool:
        """Return True for the single live-read attempt of an SSL.com domain."""
        return self.attempt_id == SSLCOM_LATEST

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"DcvAttempt(attempt_id={self.attempt_id!r}, status={self.status!r})"
