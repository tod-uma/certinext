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

"""Pydantic model for the Ledger Report API (transaction history rows).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
"""

from typing import Any

from pydantic import AliasChoices, Field

from ._base import CertiNextModel


class LedgerRecord(CertiNextModel):
    """Represents a single row from the CertiNext ledger statement report.

    Instances are returned by :class:`LedgerAccessor` methods and should not
    be constructed directly. Common fields are promoted to typed attributes;
    all raw API fields are accessible via :meth:`as_dict`.

    The exact set of fields returned depends on the API version and account
    type. Attributes that are not present in the response are ``None``.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for entry in sess.ledger.get_list():
            print(entry.transaction_date, entry.description, entry.credit)
    """

    transaction_date: str | None = Field(
        default=None,
        validation_alias=AliasChoices("transactionDate", "date"),
        serialization_alias="transactionDate",
        description="Date and time of the transaction as an ISO 8601 string.",
    )
    description: str | None = Field(
        default=None,
        description="Human-readable description of the transaction.",
    )
    order_number: str | None = Field(
        default=None,
        alias="orderNumber",
        description="Order number associated with this transaction, if any.",
    )
    transaction_type: str | None = Field(
        default=None,
        validation_alias=AliasChoices("transactionType", "type"),
        serialization_alias="transactionType",
        description='Type of transaction (e.g. ``"PURCHASE"``, ``"RENEWAL"``, ``"REFUND"``).',
    )
    debit: str | None = Field(
        default=None,
        description="Debit amount as a string, if applicable.",
    )
    credit: str | None = Field(
        default=None,
        description="Credit amount as a string, if applicable.",
    )
    balance: str | None = Field(
        default=None,
        description="Account balance after this transaction.",
    )

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "transaction_date": _s(self.transaction_date),
            "description": _s(self.description),
            "order_number": _s(self.order_number),
            "transaction_type": _s(self.transaction_type),
            "debit": _s(self.debit),
            "credit": _s(self.credit),
            "balance": _s(self.balance),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"LedgerRecord(transaction_date={self.transaction_date!r}, "
            f"description={self.description!r})"
        )
