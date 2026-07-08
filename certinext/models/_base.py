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

Models for each API area live in sibling modules (``models.catalog``,
``models.accounts``, ...) and are re-exported from the legacy module
locations (``certinext.catalog``, ...) so import paths stay stable.
"""

from datetime import datetime
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
