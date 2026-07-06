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

"""Pydantic model for the Orders Report API (order history rows).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
"""

from typing import Any, Literal

from pydantic import Field, model_validator

from ._base import CertiNextModel

CertificateStatus = Literal[
    "pending-dcv",
    "pending-organization-verification",
    "pending-csr",
    "pending-documents",
    "pending-agreement",
    "pending-approval",
    "issued",
    "revoked",
    "cancelled",
    "rejected",
    "expired",
    "unknown",
]
"""Valid ``certificateStatus`` values returned by :attr:`OrderRecord.certificate_status`.

.. note::
    The orders report API returns human-readable display strings (e.g.
    ``"Pending for Approver"``, ``"Certificate Downloaded"``) rather than these
    enum values. :attr:`OrderRecord.certificate_status` passes them through as-is;
    do not compare against this ``Literal`` type at runtime. Use
    :attr:`OrderRecord.order_status` (``"Order Fulfilled"`` / ``"Order Accepted"``)
    for reliable programmatic checks.
"""


class OrderRecord(CertiNextModel):
    """Represents a single row from the CertiNext orders report.

    Instances are returned by `OrderAccessor` methods and should not be
    constructed directly. All API response fields are exposed as read-only
    attributes.

    The ``common_name`` attribute attempts to locate the certificate's primary
    domain from multiple candidate field names (``commonName``, ``cn``,
    ``domain``, ``domainName``). If the orders report response does not include
    a domain field, ``common_name`` is ``None``.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for order in sess.orders.get_list(status="issued"):
            print(order.common_name, order.certificate_status)
    """

    order_number: str | None = Field(
        default=None,
        alias="orderNumber",
        description="Unique order number assigned by CertiNext.",
    )
    request_number: str | None = Field(
        default=None,
        alias="requestNumber",
        description="Request number associated with this order.",
    )
    product_code: str | None = Field(
        default=None,
        alias="productCode",
        description="Certificate product code (e.g. ``OV_SSL``, ``DV_SSL``).",
    )
    order_status: str | None = Field(
        default=None,
        alias="orderStatus",
        description="High-level order status string.",
    )
    certificate_status: str | None = Field(
        default=None,
        alias="certificateStatus",
        description=(
            "Certificate lifecycle status. See `CertificateStatus` for the "
            "documented values; the live API sends display strings, which pass "
            "through unchanged (ADR 0005)."
        ),
    )
    common_name: str | None = Field(
        default=None,
        alias="commonName",
        description=(
            "Common name (primary domain) of the certificate, resolved from "
            "``commonName``/``cn``/``domain``/``domainName`` in order; ``None`` "
            "when no candidate has a non-empty value."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _resolve_common_name(cls, data: Any) -> Any:
        """Resolve the common-name fallback chain exactly as 0.3.x did.

        A falsy value (e.g. ``""``) in an earlier candidate falls through to
        the next, and an all-falsy chain yields ``None`` — behavior
        ``AliasChoices`` (absent-key-only fallback) cannot express.

        Args:
            data: The raw wire payload.

        Returns:
            A shallow copy with ``commonName`` set to the resolved value
            (the original dict is left unmutated for the raw-payload stash).
        """
        if not isinstance(data, dict):
            return data
        resolved = (
            data.get("commonName")
            or data.get("cn")
            or data.get("domain")
            or data.get("domainName")
            or None
        )
        out = dict(data)
        out["commonName"] = resolved
        return out

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display."""
        def _s(val: Any) -> str:
            return str(val) if val is not None else ""
        return {
            "common_name": _s(self.common_name),
            "certificate_status": _s(self.certificate_status),
            "order_status": _s(self.order_status),
            "order_number": _s(self.order_number),
            "product_code": _s(self.product_code),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"OrderRecord(order_number={self.order_number!r}, "
            f"common_name={self.common_name!r}, "
            f"certificate_status={self.certificate_status!r})"
        )
