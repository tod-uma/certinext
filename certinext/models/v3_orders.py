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

"""Pydantic models for the v3 CLM orders API (``/api/v3/certinext/orders``).

The v3 order set is not the v2 ``/reports/orders`` set (see
:class:`~certinext.models.orders.OrderRecord`): v3 adds unsubmitted portal
drafts and omits most "Order Accepted" ACME orders, and every issued
certificate is in both. v3 rows are richer (requestor, issuer,
subscription fields). Dates are display strings without an offset; they are
UTC (verified against v2 for ``requestedDate`` and ``expiresOn``) and parse
to UTC-aware datetimes; see :data:`~certinext.models._base._V3DisplayDatetimeUTC`.

The order detail (``orders/{orderId}``) carries **no order history**,
despite the vendor spec's description (prod probe, 2026-11-23).
"""

from typing import Annotated, Any

from pydantic import BeforeValidator, Field

from ._base import CertiNextModel, _OptionalFlag, _V3DisplayDatetimeUTC


def _flatten_ordered_by(value: Any) -> Any:
    """Return the user string from ``orderedBy`` in either wire shape.

    The list row sends ``"orderedBy": "<user>"``; the detail sends
    ``"orderedBy": {"user": "<user>"}``.

    Args:
        value: The raw wire value.

    Returns:
        The user string, or the value unchanged when it is not a dict.
    """
    if isinstance(value, dict):
        return value.get("user")
    return value


_OrderedBy = Annotated[str | None, BeforeValidator(_flatten_ordered_by)]


class V3Order(CertiNextModel):
    """One row of the v3 orders list.

    Instances are returned by :class:`~certinext.v3_orders.V3OrderAccessor`.
    Use :attr:`order_id` (not :attr:`order_number`) to fetch the detail:
    ``orders/{orderNumber}`` returns 404.

    Example::

        for order in sess.v3_orders.get_list():
            print(order.order_number, order.certificate_status, order.expires_on)
    """

    order_id: str | None = Field(
        default=None, alias="orderId", description="Opaque v3 order id; the key for ``orders/{id}``."
    )
    order_number: str | None = Field(
        default=None, alias="orderNumber", description="Order number, the same key the v2 report uses."
    )
    external_order_number: str | None = Field(
        default=None, alias="externalOrderNumber", description="The issuing CA's order number, when there is one."
    )
    order_status: str | None = Field(
        default=None,
        alias="orderStatus",
        description='Display string, e.g. ``"Order Fulfilled"``, ``"Order Accepted"``, ``"Auto Save"`` (a draft).',
    )
    certificate_status: str | None = Field(
        default=None,
        alias="certificateStatus",
        description=(
            'Display string (e.g. ``"Certificate Issued"``) or, for some orders, a bare numeric '
            'code such as ``"14"`` or ``"15"``. Kept as a string; no mapping is published.'
        ),
    )
    common_name: str | None = Field(default=None, alias="commonName", description="Certificate common name.")
    identifier: str | None = Field(default=None, alias="identifier", description="Primary identifier (a domain).")
    group: str | None = Field(default=None, alias="group", description="Group name the order belongs to.")
    product: str | None = Field(default=None, alias="product", description="Product display name.")
    originator: str | None = Field(
        default=None, alias="originator", description="Channel that created the order (portal, API, ACME, ...)."
    )
    ordered_by: _OrderedBy = Field(
        default=None, alias="orderedBy", description="User who placed the order (flattened from the detail's object)."
    )
    requestor_name: str | None = Field(default=None, alias="requestorName", description="Requestor's name.")
    requestor_email: str | None = Field(default=None, alias="requestorEmail", description="Requestor's email.")
    organization_name: str | None = Field(default=None, alias="organizationName", description="Organization name.")
    issuer: str | None = Field(default=None, alias="issuer", description="Issuing CA name, once issued.")
    ca_source: str | None = Field(default=None, alias="caSource", description="CA source.")
    state: str | None = Field(default=None, alias="state", description="Order state, when set.")
    requested_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="requestedDate", description="When the order was requested (UTC)."
    )
    expires_on: _V3DisplayDatetimeUTC = Field(
        default=None, alias="expiresOn", description="Certificate expiry (UTC)."
    )
    expires_in: str | None = Field(
        default=None, alias="expiresIn", description="Days until expiry as the server computed it, a string."
    )
    subscription_start_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="subscriptionStartDate", description="Subscription start (UTC)."
    )
    subscription_end_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="subscriptionEndDate", description="Subscription end (UTC)."
    )
    subscription_status: str | None = Field(
        default=None, alias="subscriptionStatus", description="Subscription status."
    )
    subscription_validity: str | None = Field(
        default=None, alias="subscriptionValidity", description='Subscription length, e.g. ``"1 Year"``.'
    )
    bulk_name: str | None = Field(
        default=None, alias="bulkName", description="Bulk-order name; null on every captured row."
    )
    connector: str | None = Field(
        default=None, alias="connector", description="CA connector; null on every captured row."
    )
    certificate_price: str | None = Field(
        default=None, alias="certificatePrice", description="Price; null on every captured row."
    )
    currency: str | None = Field(default=None, alias="currency", description="Currency code for the price.")
    ignored: bool | None = Field(default=None, alias="ignored", description="Whether the order is marked ignored.")
    tags: list[Any] = Field(default_factory=list, alias="tags", description="Tags; empty on every captured row.")
    flags: list[Any] = Field(default_factory=list, alias="flags", description="Flags; empty on every captured row.")

    def to_row(self) -> dict[str, str]:
        """Return a flat ``dict[str, str]`` suitable for tabular display.

        Returns:
            Selected fields as strings, with ``""`` for missing values.
        """

        def _s(val: Any) -> str:
            return "" if val is None else str(val)

        return {
            "order_number": _s(self.order_number),
            "common_name": _s(self.common_name),
            "order_status": _s(self.order_status),
            "certificate_status": _s(self.certificate_status),
            "product": _s(self.product),
            "expires_on": _s(self.expires_on),
        }

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"V3Order(order_id={self.order_id!r}, order_number={self.order_number!r}, "
            f"certificate_status={self.certificate_status!r})"
        )


class V3CertificateInfo(CertiNextModel):
    """The ``certificate`` object of a v3 order detail."""

    serial_number: str | None = Field(default=None, alias="serialNumber", description="Certificate serial number.")
    valid_from: _V3DisplayDatetimeUTC = Field(
        default=None, alias="validFrom", description="Not-before (UTC)."
    )
    expires_on: _V3DisplayDatetimeUTC = Field(
        default=None, alias="expiresOn", description="Not-after (UTC)."
    )
    validity: str | None = Field(default=None, alias="validity", description='Display length, e.g. ``"397 Days"``.')


class V3IssuerCA(CertiNextModel):
    """The ``issuerCA`` object of a v3 order detail."""

    ca_type: str | None = Field(default=None, alias="caType", description="CA type.")
    root_ca: str | None = Field(default=None, alias="rootCA", description="Root CA name.")
    subordinate_ca: str | None = Field(
        default=None, alias="subordinateCA", description="Issuing (subordinate) CA name."
    )


class V3Requestor(CertiNextModel):
    """The ``requestor`` object of a v3 order detail."""

    name: str | None = Field(default=None, alias="name", description="Requestor's name.")
    email: str | None = Field(default=None, alias="email", description="Requestor's email.")
    mobile_number: str | None = Field(default=None, alias="mobileNumber", description="Requestor's phone, when set.")


class V3OrderDetail(V3Order):
    """A v3 order detail (``GET /api/v3/certinext/orders/{orderId}``).

    Shares the list row's fields (most are absent from the detail and stay
    ``None``) and adds the certificate, issuer and requestor objects. There
    is **no history field**: the 2026-11-23 prod probe read two orders from
    each of all 20 (order status, certificate status, originator) groups and
    none carried one. Revoked orders add ``revocationDate``/``revocationReason``
    and cancelled ones ``additionalInformation``.
    """

    certificate: V3CertificateInfo | None = Field(
        default=None, alias="certificate", description="Issued certificate summary, when issued."
    )
    issuer_ca: V3IssuerCA | None = Field(default=None, alias="issuerCA", description="Issuer CA chain names.")
    requestor: V3Requestor | None = Field(default=None, alias="requestor", description="Requestor contact.")
    ordered_date: _V3DisplayDatetimeUTC = Field(
        default=None, alias="orderedDate", description="When the order was placed (UTC)."
    )
    renewal_notifications_enabled: _OptionalFlag = Field(
        default=None, alias="renewalNotificationsEnabled", description='Sent as ``"0"``/``"1"``.'
    )
    revocation_date: _V3DisplayDatetimeUTC = Field(
        default=None,
        alias="revocationDate",
        description="Revocation time on revoked orders (UTC; format assumed, no fixture yet).",
    )
    revocation_reason: str | None = Field(
        default=None, alias="revocationReason", description="Revocation reason on revoked orders."
    )
    additional_information: str | None = Field(
        default=None, alias="additionalInformation", description="Free text on cancelled orders."
    )

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return (
            f"V3OrderDetail(order_id={self.order_id!r}, order_number={self.order_number!r}, "
            f"certificate_status={self.certificate_status!r})"
        )
