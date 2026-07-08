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

The response models (:class:`Product`, :class:`ProductCategory`,
:class:`CustomField`) live in :mod:`certinext.models.catalog` and are
re-exported here for backward compatibility.
"""

from typing import Any

from .client import CertiNextClient
from .exceptions import CertiNextAPIError  # noqa: F401 — referenced in Raises docstrings
from .models.catalog import CustomField, Product, ProductCategory

__all__ = ["CatalogAccessor", "CustomField", "Product", "ProductCategory"]

_PRODUCTS_BASE = "/api/certinext/v2/catalog/products"


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
        return [ProductCategory.model_validate(item) for item in raw if isinstance(item, dict)]

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
        return [CustomField.model_validate(item) for item in raw if isinstance(item, dict)]
