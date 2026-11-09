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

"""Pydantic models for the Catalog API (products and custom fields).

Wire shapes are validated leniently per ADR 0005; see
:class:`certinext.models._base.CertiNextModel` for the shared policy.
"""

from typing import Any

from pydantic import AliasChoices, Field, field_validator

from ._base import CertiNextModel, coerce_flag
from .domains import EMSIGN, SSLCOM, UNKNOWN_CA


class Product(CertiNextModel):
    """A single certificate product within a :class:`ProductCategory`.

    Instances are returned via :attr:`ProductCategory.products`. Use
    :attr:`product_code` as the ``X-Product-Code`` header value (handled
    automatically by the ``sess.ssl.create_*`` methods).

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for cat in sess.catalog.list_products():
            for p in cat.products:
                print(p.product_code, p.product_name, p.price)
    """

    product_code: str | None = Field(
        default=None,
        alias="productCode",
        description='Numeric product code string (e.g. ``"842"`` for DV SSL).',
    )
    product_name: str | None = Field(
        default=None,
        alias="productName",
        description='Human-readable product name (e.g. ``"DV SSL Certificate"``).',
    )
    price: str | None = Field(
        default=None,
        description="Unit price as a string.",
    )
    product_type_id: str | None = Field(
        default=None,
        alias="productTypeID",
        description="Internal product type identifier.",
    )
    subscription_price: dict[str, Any] = Field(
        default_factory=dict,
        alias="subscriptionPrice",
        description="Subscription pricing details (structure varies by product).",
    )

    @field_validator("subscription_price", mode="before")
    @classmethod
    def _subscription_price_dict_or_empty(cls, value: Any) -> dict[str, Any]:
        """Coerce non-dict wire values to an empty dict (0.3.x behavior).

        Args:
            value: The raw wire value for ``subscriptionPrice``.

        Returns:
            The value unchanged if it is a dict, else ``{}``.
        """
        return value if isinstance(value, dict) else {}

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"Product(product_code={self.product_code!r}, product_name={self.product_name!r})"


class ProductCategory(CertiNextModel):
    """A category of certificate products returned by the Catalog API.

    Each category groups related products (e.g. all SSL/TLS certificates)
    and carries a currency type. Access individual products via
    :attr:`products`.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for cat in sess.catalog.list_products():
            print(cat.category_name)
            for p in cat.products:
                print(" ", p.product_code, p.product_name)
    """

    category_name: str | None = Field(
        default=None,
        alias="categoryName",
        description='Category display name (e.g. ``"SSL/TLS Certificates"``).',
    )
    category_id: str | None = Field(
        default=None,
        alias="categoryID",
        description="Category identifier string.",
    )
    currency_type: str | None = Field(
        default=None,
        alias="currencyType",
        description='Currency code for prices in this category (e.g. ``"USD"``).',
    )
    products: list[Product] = Field(
        default_factory=list,
        description="List of :class:`Product` objects in this category.",
    )

    @field_validator("products", mode="before")
    @classmethod
    def _products_keep_dict_rows(cls, value: Any) -> list[Any]:
        """Drop non-dict entries from the wire products list (0.3.x behavior).

        Args:
            value: The raw wire value for ``products``.

        Returns:
            The dict entries of the list, or ``[]`` for non-list input.
        """
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    @property
    def ca(self) -> str:
        """Return the CA whose products this category holds, or :data:`UNKNOWN_CA`.

        Products carry no CA field; the category name is the only marker
        (sandbox 2026-11-06, prod 2026-11-09). Names are matched through an
        explicit table, :data:`CATEGORY_CA`, case- and punctuation-
        insensitively. An unlisted name — a new CA, or a non-CA category such
        as ``"Private PKI Products"`` — maps to :data:`UNKNOWN_CA`, **never**
        to emSign (ADR 0020: no "anything else is emSign" branch).

        This tells you which CA a *product* belongs to. It cannot tell you
        which CA an order will use: the API credential decides that (ADR
        0020 amendment), and the catalog lists every category either way.
        """
        return CATEGORY_CA.get(_category_key(self.category_name or ""), UNKNOWN_CA)

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"ProductCategory(category_name={self.category_name!r}, products={len(self.products)})"


def _category_key(name: str) -> str:
    """Normalise a catalog category name for lookup in :data:`CATEGORY_CA`.

    Args:
        name: The wire ``categoryName``.

    Returns:
        The name lower-cased with everything but letters and digits removed.
    """
    return "".join(ch for ch in name.lower() if ch.isalnum())


CATEGORY_CA: dict[str, str] = {
    _category_key("SSL/TLS Certificates"): EMSIGN,
    _category_key("SSL.com"): SSLCOM,
}
"""Catalog category name (normalised by :func:`_category_key`) to CA name.

Seen in both environments: ``"SSL/TLS Certificates"`` holds the emSign
(InCommon-branded) products and ``"SSL.com"`` holds codes 1011-1020. Add a
row when the vendor adds a CA category; until then its products report
:data:`UNKNOWN_CA`."""


class CustomField(CertiNextModel):
    """A custom field definition for a certificate product.

    Returned by :meth:`CatalogAccessor.get_custom_fields`. Custom fields may
    be required or optional when submitting a certificate order; pass them as
    the ``custom_fields`` dict argument to ``sess.ssl.create_*`` methods.

    The full raw field definition is available via :meth:`as_dict`.
    """

    field_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("fieldName", "name"),
        serialization_alias="fieldName",
        description="Machine-readable field name key used in the ``custom_fields`` dict.",
    )
    display_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("displayName", "label"),
        serialization_alias="displayName",
        description="Human-readable display label for the field.",
    )
    required: bool = Field(
        default=False,
        description="``True`` if this field must be supplied when creating a certificate order.",
    )

    @field_validator("required", mode="before")
    @classmethod
    def _required_flag(cls, value: Any) -> bool:
        """Coerce the wire ``required`` flag to bool leniently.

        Args:
            value: The raw wire value.

        Returns:
            The coerced boolean (string ``"0"`` is falsy).
        """
        return coerce_flag(value)

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"CustomField(field_name={self.field_name!r}, required={self.required!r})"
