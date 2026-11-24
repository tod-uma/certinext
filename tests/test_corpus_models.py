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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from certinext.models import CertiNextModel
from certinext.models.accounts import AccountInfo, Group, Organization
from certinext.models.api_credentials import ApiCredential
from certinext.models.audit import AuditLogEntry
from certinext.models.catalog import ProductCategory
from certinext.models.dcv_attempts import DcvAttempt, DcvAttemptSummary
from certinext.models.domains import DcvInfo, Domain
from certinext.models.ledger import LedgerRecord
from certinext.models.orders import OrderRecord
from certinext.models.ssl_certificates import CertificateDownload, SslOrder
from certinext.models.users import CustomRole, GroupMember, RolePermission, User, UserDetail
from certinext.models.v3_orders import V3Order, V3OrderDetail

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
    "domains-dcv-attempts.json": (DcvAttemptSummary, _wrapped("content")),
    "domains-dcv-attempts-detail.json": (DcvAttempt, _single),
    "domains-dcv-attempts-last.json": (DcvAttempt, _single),
    "domains-dcv-attempts-sslcom.json": (DcvAttemptSummary, _wrapped("content")),
    "domains-dcv-attempts-sslcom-detail.json": (DcvAttempt, _single),
    "domains-dcv-attempts-last-sslcom.json": (DcvAttempt, _single),
    "ssl-certificates-detail.json": (SslOrder, _single),
    "ssl-certificates-certificate.json": (CertificateDownload, _single),
    # v3 CLM (2026-11-23 capture)
    "v3-apis.json": (ApiCredential, _wrapped("credentials")),
    "v3-audit-logs.json": (AuditLogEntry, _wrapped("auditLogs")),
    "v3-orders.json": (V3Order, _wrapped("orders")),
    "v3-orders-detail.json": (V3OrderDetail, _single),
    "v3-users.json": (User, _wrapped("users")),
    "v3-users-detailed.json": (UserDetail, _wrapped("users")),
    "v3-users-groups-members.json": (GroupMember, _wrapped("members")),
    "v3-users-roles.json": (CustomRole, _wrapped("customRoles")),
    "v3-users-roles-permissions.json": (RolePermission, _wrapped("permissions")),
}

# v3 files whose models declare every wire key: a key the model doesn't
# declare is a missed field, not tolerated drift, until the next capture.
V3_FULLY_MODELLED = frozenset(f for f in REGISTRY if f.startswith("v3-"))

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
    "healthcheck-2026-07-02.json": "permanent: healthcheck report artifact, not an API payload",
    "v3-audit-logs-modules.json": "covered by test_corpus_audit_modules (a list of strings, not a row model)",
    "v3-reports-certificates.json": "permanent until #35: body is only {'status': 'success'}, no rows to model",
    "v3-discovery-certificates.json": "pending: discovery is not read by any consumer yet; model when one needs it",
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


def _extras(instance: CertiNextModel, prefix: str = "") -> list[str]:
    """Return undeclared wire keys on ``instance`` and its nested models.

    Descends into nested models held directly, in lists, or as dict values,
    so a future ``list[SomeModel]`` field is covered too.

    Args:
        instance: A validated model.
        prefix: Dotted path of ``instance`` within its parent.

    Returns:
        Dotted names of every key that landed in ``model_extra``; list
        elements appear as ``field[i].key`` and dict values as ``field[k].key``.
    """
    found = [f"{prefix}{k}" for k in (instance.model_extra or {})]
    for name in type(instance).model_fields:
        value = getattr(instance, name)
        if isinstance(value, CertiNextModel):
            found.extend(_extras(value, f"{prefix}{name}."))
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                if isinstance(item, CertiNextModel):
                    found.extend(_extras(item, f"{prefix}{name}[{i}]."))
        elif isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, CertiNextModel):
                    found.extend(_extras(item, f"{prefix}{name}[{key}]."))
    return found


class _Leaf(CertiNextModel):
    """Throwaway nested model for :func:`test_extras_descends_into_lists_and_dicts`."""

    name: str | None = None


class _Parent(CertiNextModel):
    """Throwaway parent with a nested model, a list of them, and a dict of them."""

    one: _Leaf | None = None
    many: list[_Leaf] = []
    keyed: dict[str, _Leaf] = {}


def test_extras_descends_into_lists_and_dicts() -> None:
    """Undeclared keys inside list and dict elements are reported, with their path."""
    parent = _Parent.model_validate(
        {
            "one": {"name": "a", "x": 1},
            "many": [{"name": "b"}, {"name": "c", "y": 2}],
            "keyed": {"k": {"z": 3}},
            "top": 0,
        }
    )
    assert sorted(_extras(parent)) == ["keyed[k].z", "many[1].y", "one.x", "top"]


def _v3_cases() -> list[tuple[str, str]]:
    """Return (env, filename) pairs for the fully modelled v3 files."""
    return [(env, f) for env, f in _registered_cases() if f in V3_FULLY_MODELLED]


@pytest.mark.parametrize(("env", "filename"), _v3_cases())
def test_v3_models_declare_every_wire_key(env: str, filename: str) -> None:
    """No captured v3 key falls through to ``model_extra``."""
    model_cls, extract = REGISTRY[filename]
    missed = sorted({k for row in extract(_load_body(env, filename)) for k in _extras(model_cls.model_validate(row))})
    assert not missed, f"{env}/{filename}: undeclared keys {missed}"


@pytest.mark.parametrize(("env", "filename"), _v3_cases())
def test_v3_display_dates_parse(env: str, filename: str) -> None:
    """Every non-empty v3 date string parses (none silently drops to ``None``)."""
    model_cls, extract = REGISTRY[filename]

    def _check(instance: CertiNextModel, raw: dict[str, Any]) -> None:
        for name, field in type(instance).model_fields.items():
            value = getattr(instance, name)
            wire = raw.get(field.alias or name)
            if isinstance(value, CertiNextModel) and isinstance(wire, dict):
                _check(value, wire)
            elif field.annotation == (datetime | None) and isinstance(wire, str) and wire:
                assert isinstance(value, datetime), f"{env}/{filename}: {field.alias}={wire!r} did not parse"
                assert value.tzinfo == timezone.utc, f"{env}/{filename}: {field.alias} tzinfo {value.tzinfo!r}"

    for row in extract(_load_body(env, filename)):
        _check(model_cls.model_validate(row), row)


@pytest.mark.parametrize("env", _ENVS)
def test_corpus_audit_modules(env: str) -> None:
    """The audit module list is a non-empty list of strings."""
    body = _load_body(env, "v3-audit-logs-modules.json")
    assert isinstance(body, list) and body
    assert all(isinstance(m, str) and m for m in body)


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
