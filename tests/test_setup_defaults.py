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

"""Tests for certinext-setup-defaults endpoint selection (flags and menu)."""

from typing import Any
from unittest.mock import MagicMock

import pytest

import certinext
from certinext._config import ConfigError
from certinext.accounts import Organization
from certinext.catalog import ProductCategory
from certinext.cli.setup_defaults import (
    _endpoint_default,
    _endpoint_from_flags,
    _endpoint_sandbox,
    _endpoint_url,
    _fatal_config_error,
    _filter_products,
    _org_location,
    _prompt_endpoint,
    _prompt_product,
)

INDIA = "https://api.certinext.io"


def test_fatal_config_error_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    """A config error exits 2, matching connect() and issue-cert.

    A bare ``SystemExit(str)`` would exit 1, which automation cannot tell
    apart from an ordinary runtime failure.
    """
    with pytest.raises(SystemExit) as excinfo:
        _fatal_config_error(ConfigError("Invalid TOML in /tmp/config.toml: boom"))

    assert excinfo.value.code == 2
    assert "Invalid TOML" in capsys.readouterr().err


# --- known endpoints registry ------------------------------------------------


def test_known_endpoints_includes_india() -> None:
    """The India production region is a known endpoint."""
    urls = dict(certinext.KNOWN_API_ENDPOINTS)
    assert urls["Production - India"] == INDIA


def test_known_endpoints_us_matches_base_url() -> None:
    """The US production entry reuses BASE_URL (single source of truth)."""
    assert ("Production - US", certinext.BASE_URL) in certinext.KNOWN_API_ENDPOINTS


# --- value builders ----------------------------------------------------------


def test_endpoint_default_clears_present_keys() -> None:
    """Selecting the default clears any stored endpoint keys, nothing else."""
    values, cleared = _endpoint_default({"sandbox": True, "type": "dv"})
    assert values == {}
    assert cleared == ["sandbox"]


def test_endpoint_sandbox_sets_flag_and_clears_urls() -> None:
    """Sandbox stores sandbox=true and clears any custom URL."""
    values, cleared = _endpoint_sandbox({"base_url": "https://x", "token_url": "https://x/t"})
    assert values == {"sandbox": True}
    assert set(cleared) == {"base_url", "token_url"}


def test_endpoint_sandbox_noop_when_already_sandbox() -> None:
    """Re-selecting sandbox when already sandbox writes nothing."""
    values, cleared = _endpoint_sandbox({"sandbox": True})
    assert values == {}
    assert cleared == []


def test_endpoint_url_derives_token_and_clears_sandbox() -> None:
    """A base URL derives <base>/oauth/token and clears a stored sandbox flag."""
    values, cleared = _endpoint_url(INDIA + "/", None, {"sandbox": True})
    assert values == {"base_url": INDIA, "token_url": f"{INDIA}/oauth/token"}
    assert cleared == ["sandbox"]


def test_endpoint_url_explicit_token() -> None:
    """An explicit token URL is kept as-is."""
    values, _ = _endpoint_url(INDIA, INDIA + "/custom/token", {})
    assert values == {"base_url": INDIA, "token_url": f"{INDIA}/custom/token"}


# --- flag-driven persistence -------------------------------------------------


def test_from_flags_sandbox() -> None:
    """--sandbox persists sandbox=true."""
    result = _endpoint_from_flags(True, None, None, {})
    assert result is not None
    values, cleared, _ = result
    assert values == {"sandbox": True}
    assert cleared == []


def test_from_flags_base_url_derives_token() -> None:
    """--base-url persists the URL and derives the token URL."""
    result = _endpoint_from_flags(False, INDIA, None, {})
    assert result is not None
    values, cleared, msgs = result
    assert values == {"base_url": INDIA, "token_url": f"{INDIA}/oauth/token"}
    assert cleared == []
    assert any(INDIA in m for m in msgs)


def test_from_flags_base_url_clears_sandbox() -> None:
    """An explicit --base-url supersedes a stored sandbox flag."""
    result = _endpoint_from_flags(False, INDIA, None, {"sandbox": True})
    assert result is not None
    _values, cleared, _ = result
    assert cleared == ["sandbox"]


def test_from_flags_no_flags_returns_none() -> None:
    """No connection flag means the caller should prompt instead."""
    assert _endpoint_from_flags(False, None, None, {}) is None


# --- interactive menu --------------------------------------------------------


def _mock_input(monkeypatch: pytest.MonkeyPatch, *answers: str) -> None:
    """Patch builtins.input to return the given answers in order."""
    monkeypatch.setattr("builtins.input", MagicMock(side_effect=list(answers)))


def test_prompt_menu_select_india(monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing the India menu entry stores its base/token URLs and reports them live."""
    _mock_input(monkeypatch, "3")  # 1=US prod, 2=sandbox, 3=India
    values, cleared, live = _prompt_endpoint({})
    assert values == {"base_url": INDIA, "token_url": f"{INDIA}/oauth/token"}
    assert cleared == []
    assert live == (INDIA, f"{INDIA}/oauth/token", False)


def test_prompt_menu_select_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing the sandbox menu entry stores sandbox=true and reports sandbox live."""
    _mock_input(monkeypatch, "2")
    values, _, live = _prompt_endpoint({})
    assert values == {"sandbox": True}
    assert live == (certinext.SANDBOX_BASE_URL, certinext.SANDBOX_TOKEN_URL, True)


def test_prompt_menu_select_default_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing the production-US default clears a stored sandbox flag."""
    _mock_input(monkeypatch, "1")
    values, cleared, live = _prompt_endpoint({"sandbox": True})
    assert values == {}
    assert cleared == ["sandbox"]
    assert live == (certinext.BASE_URL, certinext.TOKEN_URL, False)


def test_prompt_menu_custom_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """The custom option prompts for a URL and stores it."""
    custom = "https://my-region-api.certinext.io"
    _mock_input(monkeypatch, "6", custom)  # 6 = Custom URL…
    values, _, live = _prompt_endpoint({})
    assert values == {"base_url": custom, "token_url": f"{custom}/oauth/token"}
    assert live == (custom, f"{custom}/oauth/token", False)


def test_prompt_menu_empty_keeps_current(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pressing Enter accepts the current selection without a config change."""
    _mock_input(monkeypatch, "")  # default index points at current sandbox
    values, cleared, _ = _prompt_endpoint({"sandbox": True})
    assert values == {}
    assert cleared == []


# --- org location for signer_place default -----------------------------------


def _org(locality: str = "", state_code: str = "") -> Organization:
    """Build a minimal Organization with just the location fields populated."""
    return Organization.model_validate(
        {"organizationLocality": locality, "organizationStateCode": state_code}
    )


def test_org_location_city_and_state() -> None:
    """A locality and state render as 'City, ST'."""
    assert _org_location(_org("Orono", "ME")) == "Orono, ME"


def test_org_location_city_only() -> None:
    """A locality with no state renders as just the city."""
    assert _org_location(_org("Orono", "")) == "Orono"


def test_org_location_empty() -> None:
    """No locality yields an empty string (no default offered)."""
    assert _org_location(_org("", "ME")) == ""


# --- product filtering and menu ----------------------------------------------


def _cat(*product_dicts: dict[str, Any]) -> ProductCategory:
    """Build a ProductCategory holding the given raw product dicts."""
    return ProductCategory.model_validate(
        {"categoryName": "SSL/TLS Certificates", "products": list(product_dicts)}
    )


def _pd(name: str, code: str) -> dict[str, Any]:
    """Build a raw product dict with a name and code."""
    return {"productName": name, "productCode": code}


def test_filter_products_matches_level() -> None:
    """Filtering to OV keeps only OV-named products."""
    cats = [
        _cat(
            _pd("InCommon OV SSL Certificate", "1001"),
            _pd("InCommon DV SSL Certificate", "2001"),
            _pd("InCommon OV SSL Certificate UCC", "1002"),
        )
    ]
    matched = _filter_products(cats, "ov")
    assert {p.product_code for p in matched} == {"1001", "1002"}


def test_filter_products_falls_back_to_all_when_no_match() -> None:
    """An unrecognised naming scheme returns every product rather than hiding them."""
    cats = [_cat(_pd("Mystery Product", "9001"))]
    matched = _filter_products(cats, "ev")
    assert [p.product_code for p in matched] == ["9001"]


def test_filter_products_sorts_wildcards_last() -> None:
    """Wildcard products sink below non-wildcards; each group is alphabetical."""
    cats = [
        _cat(
            _pd("InCommon OV SSL Certificate Wildcard", "975"),
            _pd("InCommon OV SSL 90 Days", "967"),
            _pd("InCommon OV SSL Certificate UCC", "976"),
            _pd("InCommon OV SSL Certificate Wildcard UCC", "977"),
            _pd("InCommon OV SSL", "974"),
        )
    ]
    ordered = [p.product_code for p in _filter_products(cats, "ov")]
    # Non-wildcards (alphabetical) first, then wildcards (alphabetical).
    assert ordered == ["974", "967", "976", "975", "977"]


def test_prompt_product_select(monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing a product stores its code."""
    products = _filter_products(
        [_cat(_pd("InCommon OV SSL Certificate", "1001"), _pd("InCommon OV SSL Certificate UCC", "1002"))],
        "ov",
    )
    _mock_input(monkeypatch, "2")  # 0=API default, 1=first, 2=second
    values, cleared = _prompt_product(products, None)
    assert values == {"product": "1002"}
    assert cleared == []


def test_prompt_product_api_default_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing 'API default' clears a stored product."""
    products = _filter_products([_cat(_pd("InCommon OV SSL Certificate", "1001"))], "ov")
    _mock_input(monkeypatch, "0")
    values, cleared = _prompt_product(products, "1001")
    assert values == {}
    assert cleared == ["product"]


def test_prompt_product_keep_current(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pressing Enter keeps the current product (no change)."""
    products = _filter_products([_cat(_pd("InCommon OV SSL Certificate", "1001"))], "ov")
    _mock_input(monkeypatch, "")  # default index points at the current product
    values, cleared = _prompt_product(products, "1001")
    assert values == {}
    assert cleared == []
