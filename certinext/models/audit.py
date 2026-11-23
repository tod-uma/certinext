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

"""Pydantic model for the v3 CLM audit log (``/api/v3/certinext/audit-logs``)."""

from typing import Any

from pydantic import Field

from ._base import CertiNextModel, _V3DisplayDatetimeUTC


class AuditLogEntry(CertiNextModel):
    """One audit log record.

    Instances are returned by :class:`~certinext.audit.AuditAccessor`. The
    log records portal and API activity by user; the ``Orders`` module holds
    UI activity only, not order state changes. :attr:`activity` is free text
    that embeds the names of users, groups and API credentials.

    :attr:`timestamp` has minute resolution, so de-duplicate on
    :attr:`audit_log_id`, not on time. It is UTC: portal logins made at a
    noted time on 2026-11-23 appeared stamped with that UTC minute in prod
    and sandbox (see :data:`~certinext.models._base._V3DisplayDatetimeUTC`).
    """

    audit_log_id: str | None = Field(default=None, alias="auditLogId", description="Unique record id; dedupe key.")
    timestamp: _V3DisplayDatetimeUTC = Field(
        default=None, alias="timestamp", description="When it happened (UTC, minute resolution)."
    )
    module: str | None = Field(default=None, alias="module", description="Module name, one of ``list_modules()``.")
    activity: str | None = Field(default=None, alias="activity", description="Free-text description of the action.")
    status: str | None = Field(default=None, alias="status", description='``"Success"`` or ``"Failed"``.')
    user_name: str | None = Field(default=None, alias="userName", description="Name of the acting user.")

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display.

        Returns:
            Every field as a string, with ``""`` for missing values.
        """

        def _s(val: Any) -> str:
            return "" if val is None else str(val)

        return {
            "timestamp": _s(self.timestamp),
            "module": _s(self.module),
            "status": _s(self.status),
            "user_name": _s(self.user_name),
            "activity": _s(self.activity),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"AuditLogEntry(audit_log_id={self.audit_log_id!r}, module={self.module!r}, status={self.status!r})"
