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

"""Base model and leniency helpers for CertiNext API response models.

Implements the validation policy of ADR 0005 (lenient response models):

- ``extra="allow"`` — unknown wire keys are retained, never fatal.
- The original wire payload is stashed at validation time so
  :meth:`CertiNextModel.as_dict` can return it exactly (the raw-payload
  escape hatch).
- :func:`lenient_enum` builds validators for enum-like fields that fall
  back to the raw string (with a logged warning) on unknown values.
- :func:`coerce_flag` normalizes boolean flags that arrive as the strings
  ``"1"``/``"0"`` (or other truthy/falsy wire shapes).
- ``_LenientDatetime`` parses ISO 8601 wire timestamps into timezone-aware
  ``datetime`` objects, falling back to ``None`` on anything unparseable
  rather than raising. Use it for any wire field with a single consistent
  ISO 8601 shape; leave a field as a raw ``str`` instead when the vendor is
  known to send more than one date format for it (e.g.
  ``LedgerRecord.transaction_date``, which mixes RFC 2822 and ISO 8601
  depending on the response shape — coercing would silently drop the RFC
  2822 form to ``None``).
- ``_LenientDatetimeUTC`` is the same, but assumes UTC for wire values with
  no offset marker. Use it only where the vendor has confirmed the
  convention out-of-band despite the field itself being ambiguous (e.g.
  ``OrderRecord.order_date``/``.certificate_expiry_date`` — GitLab issue
  #20 / vendor ticket #136598).
- ``_V3DisplayDatetimeUTC`` parses the v3 CLM display format
  ``DD Mon YYYY (HH:MM)`` as UTC (verified for v3 orders and the audit
  log; see :func:`_v3_display_datetime_utc`).

Models for each API area live in sibling modules (``models.catalog``,
``models.accounts``, ...) and are re-exported from the legacy module
locations (``certinext.catalog``, ...) so import paths stay stable.
"""

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, TypeVar

import structlog
from pydantic import BaseModel, BeforeValidator, ConfigDict, PrivateAttr, model_validator
from pydantic.functional_validators import ModelWrapValidatorHandler

log = structlog.get_logger()

_EnumT = TypeVar("_EnumT", bound=Enum)


class CertiNextModel(BaseModel):
    """Base class for all CertiNext API response models.

    Applies the ADR 0005 leniency policy: unknown wire keys are allowed and
    retained, and the exact payload the model was validated from remains
    reachable via :meth:`as_dict`.

    Subclasses declare wire fields with ``validation_alias`` (or
    ``AliasChoices`` chains where the vendor uses multiple key names) and may
    add a ``to_row()`` method returning a flat ``dict[str, str]`` for table
    output where the 0.3.x class had one.
    """

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        coerce_numbers_to_str=True,
    )

    _raw: dict[str, Any] | None = PrivateAttr(default=None)

    @model_validator(mode="wrap")
    @classmethod
    def _stash_raw_payload(
        cls, data: Any, handler: ModelWrapValidatorHandler["CertiNextModel"]
    ) -> "CertiNextModel":
        """Validate ``data`` normally, then stash the original payload dict.

        Args:
            data: The raw value passed to validation (a wire dict when
                parsing API responses; may be anything pydantic accepts).
            handler: Pydantic's inner validation handler.

        Returns:
            The validated model instance, with ``_raw`` set to the original
            dict (by reference, not a copy) when the input was a dict.
        """
        instance = handler(data)
        if isinstance(data, dict):
            instance._raw = data
        return instance

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API payload this model was validated from.

        This is the ADR 0005 escape hatch: the returned dict is the exact
        object received from the wire (aliases and unknown keys included).
        For instances constructed programmatically (by field name, not from
        a payload), falls back to ``model_dump(by_alias=True)``.

        Returns:
            The original wire-shaped dict, or an alias-keyed dump when no
            raw payload exists.
        """
        if self._raw is not None:
            return self._raw
        return self.model_dump(by_alias=True)

    def _replace_payload(self, data: dict[str, Any]) -> None:
        """Re-validate ``data`` and update all fields and extras in place.

        Used by models with ``refresh()``-style verb methods, which the 0.3.x
        classes implemented by swapping the raw dict behind their properties.

        Args:
            data: The new raw payload dict.
        """
        fresh = type(self).model_validate(data)
        for field_name in type(self).model_fields:
            setattr(self, field_name, getattr(fresh, field_name))
        object.__setattr__(self, "__pydantic_extra__", fresh.__pydantic_extra__)
        self._raw = data


def lenient_enum(enum_cls: type[_EnumT]) -> Any:
    """Build a pydantic ``BeforeValidator`` mapping values into ``enum_cls`` leniently.

    Known values become enum members; unknown values are logged at warning
    level and passed through as-is, so the field must be typed
    ``KnownEnum | str`` (ADR 0005: vendor drift degrades into warnings, not
    ``ValidationError``). ``None`` passes through untouched.

    Args:
        enum_cls: The enum class holding the currently known values.

    Returns:
        A ``BeforeValidator`` suitable for use in ``Annotated[...]`` field
        types.
    """
    from pydantic import BeforeValidator

    def _validate(value: Any) -> Any:
        if value is None or isinstance(value, enum_cls):
            return value
        try:
            return enum_cls(value)
        except ValueError:
            log.warning(
                "unknown_enum_value",
                enum=enum_cls.__name__,
                value=value,
            )
            return value

    return BeforeValidator(_validate)


def coerce_flag(value: Any) -> bool:
    """Coerce a vendor boolean flag to ``bool``.

    The API delivers some flags as the strings ``"1"``/``"0"`` (e.g.
    ``isPreVettingOrg``). Mirrors the 0.3.x behavior of ``bool()`` truthiness
    except that the string ``"0"`` is falsy.

    Args:
        value: The raw wire value.

    Returns:
        The coerced boolean.
    """
    if isinstance(value, str):
        return value.strip() not in ("", "0", "false", "False")
    return bool(value)


def _optional_flag(value: Any) -> bool | None:
    """Coerce a vendor flag to ``bool``, keeping an absent value as ``None``.

    Args:
        value: The raw wire value.

    Returns:
        ``None`` for ``None``, otherwise :func:`coerce_flag` of the value.
    """
    return None if value is None else coerce_flag(value)


_OptionalFlag = Annotated[bool | None, BeforeValidator(_optional_flag)]
"""A ``"0"``/``"1"`` (or other truthy/falsy) flag that may be absent."""


def _lenient_datetime(value: Any) -> datetime | None:
    """Parse a wire timestamp into a timezone-aware datetime, or ``None``.

    Absent/null/empty values and unparseable strings yield ``None`` rather
    than a ``ValidationError`` (ADR 0005).

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


def _lenient_datetime_utc(value: Any) -> datetime | None:
    """Parse a wire timestamp, assuming UTC when it carries no offset.

    Vendor confirmed (GitLab issue #20 / vendor ticket #136598) that
    ``/reports/orders``'s ``orderDate``/``certificateExpiryDate`` are UTC
    despite lacking a ``Z``/offset suffix, unlike every other CertiNext v2
    timestamp. Delegates to :func:`_lenient_datetime` first, so if the
    vendor later adds an explicit offset the parsed value's real offset
    still wins over this UTC assumption.

    Args:
        value: The raw wire value (ISO 8601 string expected).

    Returns:
        The parsed datetime (UTC-aware), or ``None``.
    """
    parsed = _lenient_datetime(value)
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


_LenientDatetimeUTC = Annotated[datetime | None, BeforeValidator(_lenient_datetime_utc)]


_MONTHS = {
    name: number
    for number, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1
    )
}
_V3_DISPLAY_DATE = re.compile(r"^\s*(\d{1,2}) ([A-Za-z]{3}) (\d{4})(?: \((\d{1,2}):(\d{2})\))?\s*$")


def _v3_display_datetime(value: Any) -> datetime | None:
    """Parse a v3 CLM display date (``DD Mon YYYY (HH:MM)``) into a naive datetime.

    The v3 paths (``/api/v3/certinext/...``) send display strings, not ISO
    8601, with no offset marker. Models use :data:`_V3DisplayDatetimeUTC`,
    which wraps this parser and attaches UTC.

    The month is matched against a fixed English table rather than
    ``strptime``'s ``%b``, which depends on the process locale. A date
    without the ``(HH:MM)`` part parses as midnight. Absent, empty and
    unparseable values yield ``None`` (ADR 0005); the raw string stays
    reachable through ``as_dict()``.

    Args:
        value: The raw wire value.

    Returns:
        The parsed naive datetime, or ``None``.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    match = _V3_DISPLAY_DATE.match(str(value))
    if match is None:
        return None
    day, month_name, year, hour, minute = match.groups()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    try:
        return datetime(int(year), month, int(day), int(hour or 0), int(minute or 0))
    except ValueError:
        return None


def _v3_display_datetime_utc(value: Any) -> datetime | None:
    """Parse a v3 CLM display date as UTC into a UTC-aware datetime.

    Verified on 2026-11-23, prod and sandbox:

    - v3 orders: ``requestedDate`` and ``expiresOn`` equalled v2
      ``/reports/orders``' ``orderDate`` and ``certificateExpiryDate``
      (vendor-confirmed UTC, #20) to the minute, for 1,533 prod and 151
      sandbox orders across July to November, so across a DST change.
    - Audit log: portal logins made at a noted time appeared with that UTC
      minute as their ``timestamp``.
    - ``users/profile`` has no timezone setting.

    User, role and credential ``createdDate`` values had no reference to
    check against; they are taken as UTC because two independent v3
    endpoints are. ``discovery/certificates`` is the exception: its
    ``expiresOn`` is in some local zone, and it is not modelled.

    Args:
        value: The raw wire value.

    Returns:
        The parsed datetime with ``tzinfo=UTC``, or ``None``.
    """
    parsed = _v3_display_datetime(value)
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


_V3DisplayDatetimeUTC = Annotated[datetime | None, BeforeValidator(_v3_display_datetime_utc)]
"""A v3 display date verified to be UTC, parsed UTC-aware; see :func:`_v3_display_datetime_utc`."""
