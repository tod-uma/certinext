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

"""Tests for certinext.catalog: Product, ProductCategory, CustomField, CatalogAccessor."""

from unittest.mock import MagicMock

from certinext.catalog import CatalogAccessor, CustomField, Product, ProductCategory
from certinext.client import CertiNextClient

_PRODUCTS_URL = "/api/certinext/v2/catalog/products"


def _make_client() -> tuple[CertiNextClient, MagicMock]:
    """Return a CertiNextClient with auth and HTTP session mocked out."""
    client = CertiNextClient(
        base_url="https://us-api.certinext.io",
        token_url="https://us-api.certinext.io/oauth/token",
        client_id="test",
        client_secret="secret",
    )
    client._auth = MagicMock()
    client._auth.get_token.return_value = "test-token"
    mock_session = MagicMock()
    client._session = mock_session
    return client, mock_session


def _ok_response(payload: object) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.is_error = False
    resp.json.return_value = payload
    resp.content = b"{}"
    return resp


_CATEGORY_DATA = {
    "categoryName": "SSL/TLS Certificates",
    "categoryID": "3",
    "currencyType": "USD",
    "products": [
        {"productCode": "842", "productName": "DV SSL Certificate", "price": "50.00", "productTypeID": "13"},
        {"productCode": "843", "productName": "DV Wildcard SSL Certificate", "price": "100.00"},
    ],
}


# ---------------------------------------------------------------------------
# Product
# ---------------------------------------------------------------------------

class TestProduct:
    """Product exposes expected attributes."""

    _DATA = {"productCode": "842", "productName": "DV SSL Certificate", "price": "50.00", "productTypeID": "13"}

    def test_product_code(self) -> None:
        """product_code reads productCode."""
        p = Product.model_validate(self._DATA)
        assert p.product_code == "842"

    def test_product_name(self) -> None:
        """product_name reads productName."""
        p = Product.model_validate(self._DATA)
        assert p.product_name == "DV SSL Certificate"

    def test_price(self) -> None:
        """price reads price."""
        p = Product.model_validate(self._DATA)
        assert p.price == "50.00"

    def test_product_type_id(self) -> None:
        """product_type_id reads productTypeID."""
        p = Product.model_validate(self._DATA)
        assert p.product_type_id == "13"

    def test_subscription_price_returns_dict(self) -> None:
        """subscription_price returns a dict (empty if missing)."""
        p = Product.model_validate(self._DATA)
        assert p.subscription_price == {}

    def test_subscription_price_when_present(self) -> None:
        """subscription_price returns the dict value when present."""
        p = Product.model_validate({"subscriptionPrice": {"annual": "45.00"}})
        assert p.subscription_price == {"annual": "45.00"}

    def test_subscription_price_non_dict_coerced_to_empty(self) -> None:
        """subscription_price coerces a non-dict wire value to {} (0.3.x behavior)."""
        p = Product.model_validate({"subscriptionPrice": "n/a"})
        assert p.subscription_price == {}

    def test_missing_fields_return_none(self) -> None:
        """Missing fields return None."""
        p = Product.model_validate({})
        assert p.product_code is None
        assert p.product_name is None
        assert p.price is None
        assert p.product_type_id is None

    def test_numeric_product_code_coerced_to_str(self) -> None:
        """A numeric productCode is coerced to string, not a ValidationError (ADR 0005)."""
        p = Product.model_validate({"productCode": 842})
        assert p.product_code == "842"

    def test_unknown_fields_retained(self) -> None:
        """Unknown wire keys are retained, never fatal (ADR 0005)."""
        p = Product.model_validate({"productCode": "842", "newVendorField": "x"})
        assert p.as_dict()["newVendorField"] == "x"

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        p = Product.model_validate(self._DATA)
        assert p.as_dict() is self._DATA

    def test_repr_contains_code_and_name(self) -> None:
        """repr() includes product_code and product_name."""
        p = Product.model_validate(self._DATA)
        r = repr(p)
        assert "842" in r
        assert "DV SSL Certificate" in r


# ---------------------------------------------------------------------------
# ProductCategory
# ---------------------------------------------------------------------------

class TestProductCategory:
    """ProductCategory nests Product objects and exposes expected attributes."""

    def test_category_name(self) -> None:
        """category_name reads categoryName."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        assert cat.category_name == "SSL/TLS Certificates"

    def test_category_id(self) -> None:
        """category_id reads categoryID."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        assert cat.category_id == "3"

    def test_currency_type(self) -> None:
        """currency_type reads currencyType."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        assert cat.currency_type == "USD"

    def test_products_is_list_of_product(self) -> None:
        """products is a list of Product instances."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        assert len(cat.products) == 2
        assert all(isinstance(p, Product) for p in cat.products)

    def test_products_have_correct_codes(self) -> None:
        """Products in the category have the correct product codes."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        codes = [p.product_code for p in cat.products]
        assert codes == ["842", "843"]

    def test_products_empty_when_no_products_key(self) -> None:
        """products is empty when the products key is missing."""
        cat = ProductCategory.model_validate({"categoryName": "Empty"})
        assert cat.products == []

    def test_products_skips_non_dict_entries(self) -> None:
        """Non-dict entries in the products list are dropped (0.3.x behavior)."""
        cat = ProductCategory.model_validate({"products": [{"productCode": "1"}, "junk", None]})
        assert len(cat.products) == 1

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        assert cat.as_dict() is _CATEGORY_DATA

    def test_repr_includes_category_name_and_count(self) -> None:
        """repr() includes category name and product count."""
        cat = ProductCategory.model_validate(_CATEGORY_DATA)
        r = repr(cat)
        assert "SSL/TLS" in r
        assert "2" in r


# ---------------------------------------------------------------------------
# CustomField
# ---------------------------------------------------------------------------

class TestCustomField:
    """CustomField exposes expected attributes."""

    def test_field_name_from_field_name_key(self) -> None:
        """field_name reads fieldName."""
        f = CustomField.model_validate({"fieldName": "purchaseOrderNumber", "required": True})
        assert f.field_name == "purchaseOrderNumber"

    def test_field_name_falls_back_to_name(self) -> None:
        """field_name falls back to 'name' when fieldName is absent."""
        f = CustomField.model_validate({"name": "poNumber"})
        assert f.field_name == "poNumber"

    def test_display_name_from_display_name_key(self) -> None:
        """display_name reads displayName."""
        f = CustomField.model_validate({"displayName": "PO Number"})
        assert f.display_name == "PO Number"

    def test_display_name_falls_back_to_label(self) -> None:
        """display_name falls back to 'label' when displayName is absent."""
        f = CustomField.model_validate({"label": "PO Number"})
        assert f.display_name == "PO Number"

    def test_required_true(self) -> None:
        """required is True when the field is marked required."""
        f = CustomField.model_validate({"required": True})
        assert f.required is True

    def test_required_false(self) -> None:
        """required is False when the field is not required."""
        f = CustomField.model_validate({"required": False})
        assert f.required is False

    def test_required_false_when_missing(self) -> None:
        """required is False when the key is absent."""
        f = CustomField.model_validate({})
        assert f.required is False

    def test_required_string_flags(self) -> None:
        """required coerces the vendor's "1"/"0" string flags."""
        assert CustomField.model_validate({"required": "1"}).required is True
        assert CustomField.model_validate({"required": "0"}).required is False

    def test_as_dict_returns_raw_data(self) -> None:
        """as_dict() returns the exact dict passed at construction."""
        data = {"fieldName": "x", "required": True}
        f = CustomField.model_validate(data)
        assert f.as_dict() is data

    def test_repr_contains_field_name(self) -> None:
        """repr() includes field_name."""
        f = CustomField.model_validate({"fieldName": "myField"})
        assert "myField" in repr(f)


# ---------------------------------------------------------------------------
# CatalogAccessor.list_products
# ---------------------------------------------------------------------------

class TestCatalogAccessorListProducts:
    """CatalogAccessor.list_products() returns ProductCategory objects."""

    _CATALOG_PAYLOAD = {
        "products": [_CATEGORY_DATA]
    }

    def test_calls_products_endpoint(self) -> None:
        """list_products() GETs /api/certinext/v2/catalog/products."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(self._CATALOG_PAYLOAD)
        accessor = CatalogAccessor(client)
        accessor.list_products()
        url = mock_session.get.call_args[0][0]
        assert url.endswith(_PRODUCTS_URL)

    def test_returns_list_of_product_categories(self) -> None:
        """list_products() returns a list of ProductCategory objects."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(self._CATALOG_PAYLOAD)
        accessor = CatalogAccessor(client)
        result = accessor.list_products()
        assert len(result) == 1
        assert isinstance(result[0], ProductCategory)

    def test_categories_contain_products(self) -> None:
        """Each ProductCategory returned contains the correct products."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response(self._CATALOG_PAYLOAD)
        accessor = CatalogAccessor(client)
        result = accessor.list_products()
        assert len(result[0].products) == 2

    def test_handles_bare_list_response(self) -> None:
        """list_products() handles a bare list response (no 'products' wrapper)."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([_CATEGORY_DATA])
        accessor = CatalogAccessor(client)
        result = accessor.list_products()
        assert len(result) == 1

    def test_returns_empty_when_no_categories(self) -> None:
        """list_products() returns [] when the products list is empty."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({"products": []})
        accessor = CatalogAccessor(client)
        assert accessor.list_products() == []


# ---------------------------------------------------------------------------
# CatalogAccessor.get_custom_fields
# ---------------------------------------------------------------------------

class TestCatalogAccessorGetCustomFields:
    """CatalogAccessor.get_custom_fields() returns CustomField objects."""

    def test_calls_custom_fields_endpoint(self) -> None:
        """get_custom_fields() GETs /catalog/products/{code}/custom-fields."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        accessor = CatalogAccessor(client)
        accessor.get_custom_fields("842")
        url = mock_session.get.call_args[0][0]
        assert url.endswith("/catalog/products/842/custom-fields")

    def test_returns_custom_fields_from_list_response(self) -> None:
        """get_custom_fields() returns a list of CustomField from a bare list."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([
            {"fieldName": "poNumber", "required": True},
        ])
        accessor = CatalogAccessor(client)
        fields = accessor.get_custom_fields("850")
        assert len(fields) == 1
        assert isinstance(fields[0], CustomField)
        assert fields[0].field_name == "poNumber"

    def test_returns_custom_fields_from_wrapped_response(self) -> None:
        """get_custom_fields() unwraps the first list from a dict response."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response({
            "customFields": [{"fieldName": "dept", "required": False}]
        })
        accessor = CatalogAccessor(client)
        fields = accessor.get_custom_fields("846")
        assert len(fields) == 1
        assert fields[0].field_name == "dept"

    def test_returns_empty_when_no_fields(self) -> None:
        """get_custom_fields() returns [] when there are no custom fields."""
        client, mock_session = _make_client()
        mock_session.get.return_value = _ok_response([])
        accessor = CatalogAccessor(client)
        assert accessor.get_custom_fields("842") == []
