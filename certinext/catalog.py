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

"""Catalog API: products and custom field definitions.

Provides the list of certificate products available to the account and
the custom fields that can be submitted with each product type.
"""

from typing import Any

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings

_PRODUCTS_BASE = "/api/certinext/v2/catalog/products"


class Product:
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

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API dict for this product.
        """
        self._data = data

    @property
    def product_code(self) -> str | None:
        """Numeric product code string (e.g. ``"842"`` for DV SSL).

        Pass this value as ``X-Product-Code`` when creating a certificate, or
        use the corresponding ``sess.ssl.create_*`` method which does so automatically.
        """
        return self._data.get("productCode")

    @property
    def product_name(self) -> str | None:
        """Human-readable product name (e.g. ``"DV SSL Certificate"``)."""
        return self._data.get("productName")

    @property
    def price(self) -> str | None:
        """Unit price as a string."""
        return self._data.get("price")

    @property
    def product_type_id(self) -> str | None:
        """Internal product type identifier."""
        return self._data.get("productTypeID")

    @property
    def subscription_price(self) -> dict[str, Any]:
        """Subscription pricing details (structure varies by product)."""
        val = self._data.get("subscriptionPrice")
        return val if isinstance(val, dict) else {}

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this product."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"Product(product_code={self.product_code!r}, product_name={self.product_name!r})"


class ProductCategory:
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

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API dict for this category.
        """
        self._data = data
        raw_products = data.get("products", [])
        self._products = [Product(p) for p in raw_products if isinstance(p, dict)]

    @property
    def category_name(self) -> str | None:
        """Category display name (e.g. ``"SSL/TLS Certificates"``)."""
        return self._data.get("categoryName")

    @property
    def category_id(self) -> str | None:
        """Category identifier string."""
        return self._data.get("categoryID")

    @property
    def currency_type(self) -> str | None:
        """Currency code for prices in this category (e.g. ``"USD"``)."""
        return self._data.get("currencyType")

    @property
    def products(self) -> list[Product]:
        """List of :class:`Product` objects in this category."""
        return self._products

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this category."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"ProductCategory(category_name={self.category_name!r}, products={len(self._products)})"


class CustomField:
    """A custom field definition for a certificate product.

    Returned by :meth:`CatalogAccessor.get_custom_fields`. Custom fields may
    be required or optional when submitting a certificate order; pass them as
    the ``custom_fields`` dict argument to ``sess.ssl.create_*`` methods.

    The full raw field definition is available via :meth:`as_dict`.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        """
        Args:
            data: Raw API dict for this custom field.
        """
        self._data = data

    @property
    def field_name(self) -> str | None:
        """Machine-readable field name key used in the ``custom_fields`` dict."""
        return self._data.get("fieldName") or self._data.get("name")

    @property
    def display_name(self) -> str | None:
        """Human-readable display label for the field."""
        return self._data.get("displayName") or self._data.get("label")

    @property
    def required(self) -> bool:
        """``True`` if this field must be supplied when creating a certificate order."""
        return bool(self._data.get("required"))

    def as_dict(self) -> dict[str, Any]:
        """Return the raw API response dict for this custom field."""
        return self._data

    def __repr__(self) -> str:
        """Return a concise developer representation."""
        return f"CustomField(field_name={self.field_name!r}, required={self.required!r})"


class CatalogAccessor:
    """Accessor for the CertiNext Catalog API.

    Mounted on a session as ``session.catalog``. Provides methods to list
    available certificate products and retrieve custom field definitions.

    Use :meth:`list_products` to discover which product codes are enabled for
    your account before creating certificates.

    Example::

        sess = certinext.session(client_id="...", client_secret="...")
        for cat in sess.catalog.list_products():
            for p in cat.products:
                print(p.product_code, p.product_name, p.price)
    """

    def __init__(self, client: CertiNextClient) -> None:
        """
        Args:
            client: The underlying HTTP client used for all API calls.
        """
        self._client = client

    def list_products(self) -> list[ProductCategory]:
        """Return all certificate product categories available to the account.

        Returns:
            List of :class:`ProductCategory` objects, each containing a list
            of :class:`Product` objects.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(_PRODUCTS_BASE)
        raw: list[Any] = []
        if isinstance(result, list):
            raw = result
        elif isinstance(result, dict):
            products = result.get("products", [])
            raw = products if isinstance(products, list) else []
        return [ProductCategory(item) for item in raw]

    def get_custom_fields(self, product_code: str) -> list[CustomField]:
        """Return the custom field definitions for a specific product.

        Args:
            product_code: The product code string (e.g. ``"842"`` for DV SSL).
                Use values from :attr:`Product.product_code`.

        Returns:
            List of :class:`CustomField` objects. May be empty if the product
            has no custom fields.

        Raises:
            CertiNextAPIError: On a non-2xx API response. Provides ``.status_code`` and ``.body``.
        """
        result = self._client.get(f"{_PRODUCTS_BASE}/{product_code}/custom-fields")
        raw: list[Any] = []
        if isinstance(result, list):
            raw = result
        elif isinstance(result, dict):
            for val in result.values():
                if isinstance(val, list):
                    raw = val
                    break
        return [CustomField(item) for item in raw]
