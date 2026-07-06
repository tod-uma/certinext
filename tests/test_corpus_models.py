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

"""Corpus-parse tests: every pydantic model parses the live-payload corpus.

ADR 0005 Confirmation gate: each model must parse every captured payload
from both environment trees (``tests/fixtures/corpus/{prod,sandbox}``)
without raising. Unknown-field warnings are expected data; a
``ValidationError`` is a policy violation.

``REGISTRY`` maps a corpus filename to the model class and a row extractor;
modules add entries here as their models are migrated. ``NOT_YET_COVERED``
lists corpus files whose models have not landed — it must shrink to the
documented exclusions by the end of phase 1, and a new corpus file that is
neither registered nor excluded fails the coverage test loudly.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from certinext.models import CertiNextModel
from certinext.models.accounts import AccountInfo, Group, Organization
from certinext.models.catalog import ProductCategory
from certinext.models.domains import DcvInfo, DcvVerifyResult, Domain
from certinext.models.ledger import LedgerRecord
from certinext.models.orders import OrderRecord

_CORPUS_ROOT = Path(__file__).parent / "fixtures" / "corpus"
_ENVS = ("prod", "sandbox")


def _load_body(env: str, filename: str) -> Any:
    """Return the captured response body from a corpus file.

    Args:
        env: Corpus environment tree name (``prod`` or ``sandbox``).
        filename: Corpus file name within the tree.

    Returns:
        The ``response.body`` JSON value from the capture envelope.
    """
    path = _CORPUS_ROOT / env / filename
    with path.open(encoding="utf-8") as fh:
        capture = json.load(fh)
    return capture["response"]["body"]


def _rows_catalog_products(body: Any) -> list[dict[str, Any]]:
    """Extract product-category rows from the catalog-products body."""
    rows = body.get("products", []) if isinstance(body, dict) else body
    return [r for r in rows if isinstance(r, dict)]


def _single(body: Any) -> list[dict[str, Any]]:
    """Treat a single-object body as one row."""
    return [body] if isinstance(body, dict) else []


def _wrapped(key: str) -> Callable[[Any], list[dict[str, Any]]]:
    """Return an extractor for a ``{key: [rows]}`` wrapper body.

    Args:
        key: The wrapper key holding the row list.

    Returns:
        An extractor that also accepts a bare-list body (R07: list
        endpoints alternate between shapes).
    """

    def _extract(body: Any) -> list[dict[str, Any]]:
        rows = body.get(key, []) if isinstance(body, dict) else body
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    return _extract


# filename -> (model class, row extractor). One entry per corpus file whose
# model has been migrated; each row must model_validate without raising.
REGISTRY: dict[str, tuple[type[CertiNextModel], Callable[[Any], list[dict[str, Any]]]]] = {
    "catalog-products.json": (ProductCategory, _rows_catalog_products),
    "auth-me.json": (AccountInfo, _single),
    "groups.json": (Group, _wrapped("groups")),
    "organizations-list.json": (Organization, _wrapped("organizations")),
    "organizations-detail.json": (Organization, _single),
    "reports-ledger.json": (LedgerRecord, _wrapped("content")),
    "reports-orders.json": (OrderRecord, _wrapped("content")),
    "domains-list.json": (Domain, _wrapped("content")),
    "domains-list-default.json": (Domain, _wrapped("content")),
    "domains-detail.json": (Domain, _single),
    "domains-dcv-attempts.json": (DcvVerifyResult, _wrapped("content")),
    "domains-dcv-attempts-last.json": (DcvVerifyResult, _single),
}

# Registered files whose captured payload legitimately has zero rows (the
# non-empty assertion is waived; the account state, not the model, is why).
EMPTY_OK: dict[str, str] = {
    "reports-ledger.json": "ledger has totalElements=0 in both environments (2026-07-02 capture)",
}

# Corpus files whose models have not been migrated yet (phase 1 in
# progress) or that intentionally have no row model. Files listed with a
# reason string are permanent exclusions; the rest must move to REGISTRY.
NOT_YET_COVERED: dict[str, str] = {
    "domains-dcv.json": "covered by test_corpus_dcv_info_from_wire (DcvInfo is a value object, not a row model)",
    "ssl-certificates-detail.json": "pending: ssl_certificates migration",
    "ssl-certificates-certificate.json": "pending: ssl_certificates migration",
    "healthcheck-2026-07-02.json": "permanent: healthcheck report artifact, not an API payload",
}


def _registered_cases() -> list[tuple[str, str]]:
    """Return (env, filename) pairs for every registered corpus file present."""
    cases = []
    for env in _ENVS:
        for filename in sorted(REGISTRY):
            if (_CORPUS_ROOT / env / filename).exists():
                cases.append((env, filename))
    return cases


@pytest.mark.parametrize(("env", "filename"), _registered_cases())
def test_corpus_rows_parse(env: str, filename: str) -> None:
    """Every row in every registered corpus payload validates into its model."""
    model_cls, extract = REGISTRY[filename]
    rows = extract(_load_body(env, filename))
    assert rows or filename in EMPTY_OK, f"{env}/{filename}: extractor produced no rows"
    for row in rows:
        instance = model_cls.model_validate(row)
        # ADR 0005 escape hatch: the exact wire dict stays reachable.
        assert instance.as_dict() is row


@pytest.mark.parametrize("env", _ENVS)
def test_corpus_dcv_info_from_wire(env: str) -> None:
    """DcvInfo.from_wire parses the captured DCV payload from both environments."""
    body = _load_body(env, "domains-dcv.json")
    assert isinstance(body, dict)
    info = DcvInfo.from_wire(body)
    assert info.method == info.method.upper()


@pytest.mark.parametrize("env", _ENVS)
def test_corpus_coverage_accounted_for(env: str) -> None:
    """Every corpus file is either registered or explicitly listed as uncovered."""
    tree = _CORPUS_ROOT / env
    for path in tree.glob("*.json"):
        name = path.name
        assert name in REGISTRY or name in NOT_YET_COVERED, (
            f"corpus file {env}/{name} is neither registered nor excluded — "
            "add a model registry entry or an explicit exclusion with a reason"
        )
