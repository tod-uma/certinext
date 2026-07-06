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
from certinext.models.catalog import ProductCategory

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


# filename -> (model class, row extractor). One entry per corpus file whose
# model has been migrated; each row must model_validate without raising.
REGISTRY: dict[str, tuple[type[CertiNextModel], Callable[[Any], list[dict[str, Any]]]]] = {
    "catalog-products.json": (ProductCategory, _rows_catalog_products),
}

# Corpus files whose models have not been migrated yet (phase 1 in
# progress) or that intentionally have no row model. Files listed with a
# reason string are permanent exclusions; the rest must move to REGISTRY.
NOT_YET_COVERED: dict[str, str] = {
    "auth-me.json": "pending: accounts migration",
    "groups.json": "pending: accounts migration",
    "organizations-list.json": "pending: accounts migration",
    "organizations-detail.json": "pending: accounts migration",
    "reports-ledger.json": "pending: ledger migration",
    "reports-orders.json": "pending: orders migration",
    "domains-list.json": "pending: domains migration",
    "domains-list-default.json": "pending: domains migration",
    "domains-detail.json": "pending: domains migration",
    "domains-dcv.json": "pending: domains migration",
    "domains-dcv-attempts.json": "pending: domains migration",
    "domains-dcv-attempts-last.json": "pending: domains migration",
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
    assert rows, f"{env}/{filename}: extractor produced no rows"
    for row in rows:
        instance = model_cls.model_validate(row)
        # ADR 0005 escape hatch: the exact wire dict stays reachable.
        assert instance.as_dict() is row


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
