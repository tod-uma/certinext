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

"""Assumption-register probes against the live CertiNext API (read-only).

One probe per register row (R01-R24) of
``docs/plans/pydantic-typer-refactor/phase-0-guardrails-and-probe-suite.md``.
Each probe asserts the *currently believed* vendor-API behavior, so a vendor
fix or regression shows up as a failing probe — the signal to update the
code workaround, README known issues, the ``certinext-api-bugs`` skill, and
the GitLab issue together (ADR 0002).

Every implemented probe is a GET (safe against production). Register rows
that require sandbox mutations (issuance, DCV state changes) are present but
skipped with an explicit reason until a dedicated sandbox lifecycle run
implements them; rows resolved elsewhere point at their evidence.

Run against one environment at a time::

    CERTINEXT_PROBE_ENV=sandbox pytest -m probe   # default
    CERTINEXT_PROBE_ENV=prod    pytest -m probe   # read-only GETs only

Credentials resolve like the integration tests: OS keyring (default profile
for prod, ``sandbox`` profile for sandbox) or environment variables.
"""

import os
from typing import Any

import pytest
import requests

import certinext
from certinext._chain import order_certificate_chain
from certinext._keyring import keyring_get, keyring_service
from certinext.client import CertiNextClient
from certinext.domains import Domain
from certinext.exceptions import CertiNextAPIError
from certinext.ssl_certificates import CertificateDownload

pytestmark = pytest.mark.probe

_DOMAINS = "/api/certinext/v2/domains"
_ORGS = "/api/certinext/v2/organizations"
_ORDERS = "/api/certinext/v2/reports/orders"
_LEDGER = "/api/certinext/v2/reports/ledger"
_SSL = "/api/certinext/v2/ssl-certificates"


# ---------------------------------------------------------------------------
# Environment / session fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def probe_env() -> str:
    """Return the target environment: ``sandbox`` (default) or ``prod``."""
    env = os.environ.get("CERTINEXT_PROBE_ENV", "sandbox").lower()
    if env not in ("sandbox", "prod"):
        raise ValueError(f"CERTINEXT_PROBE_ENV must be 'sandbox' or 'prod', not {env!r}")
    return env


@pytest.fixture(scope="session")
def probe_session(probe_env: str) -> certinext.CertiNextSession:
    """Return a session for the probe environment, or skip when no credentials.

    Production probes are strictly read-only; every implemented probe below
    issues GETs only.
    """
    sandbox = probe_env == "sandbox"
    svc = keyring_service("certinext", "sandbox" if sandbox else None)
    prefix = "CERTINEXT_SANDBOX_" if sandbox else "CERTINEXT_"
    client_id = keyring_get(svc, "CERTINEXT_CLIENT_ID") or os.environ.get(prefix + "CLIENT_ID")
    client_secret = keyring_get(svc, "CERTINEXT_CLIENT_SECRET") or os.environ.get(prefix + "CLIENT_SECRET")
    if not client_id or not client_secret:
        pytest.skip(
            f"{probe_env} credentials not available — run certinext-setup-keyring"
            f"{' --sandbox' if sandbox else ''} or set {prefix}CLIENT_ID / {prefix}CLIENT_SECRET"
        )
    return certinext.session(client_id=client_id, client_secret=client_secret, sandbox=sandbox)


@pytest.fixture(scope="session")
def client(probe_session: certinext.CertiNextSession) -> CertiNextClient:
    """Low-level client for raw GETs that bypass the library's workarounds."""
    return probe_session._client


@pytest.fixture(scope="session")
def baseline_domains(probe_session: certinext.CertiNextSession) -> list[Domain]:
    """The full domain list via the library's paged/deduped path, once per run."""
    return probe_session.domain.get_list()


def _sandbox_only(probe_env: str) -> None:
    """Skip a sandbox-only probe when targeting production."""
    if probe_env != "sandbox":
        pytest.skip("sandbox-only probe (register marks this row sandbox)")


def _status_of(exc_or_none: CertiNextAPIError | None) -> int | None:
    """Return the HTTP status of a captured API error, or None for success."""
    return exc_or_none.status_code if exc_or_none else None


def _try_get(client: CertiNextClient, path: str, params: dict[str, Any] | None = None) -> tuple[int | None, Any]:
    """GET returning ``(error_status_or_None, body_or_None)`` instead of raising."""
    try:
        return None, client.get(path, params)
    except CertiNextAPIError as exc:
        return exc.status_code, None


def _rows(body: Any) -> list[Any]:
    """Unwrap a list payload (bare array or first list-valued key of a dict)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, list):
                return value
    return []


# ---------------------------------------------------------------------------
# R01-R04: domain listing and filtering
# ---------------------------------------------------------------------------


def test_probe_r01_search_exact_and_substring(
    probe_env: str, client: CertiNextClient, baseline_domains: list[Domain]
) -> None:
    """R01: ``search`` matches exact FQDNs *and* substrings (fixed since ~2026-06).

    History: originally ``search`` returned everything regardless of value;
    by 2026-06-05 exact-FQDN worked but substrings returned 0 rows; on
    2026-07-02 substring matching was observed working in the sandbox
    (probe run for GitLab issue #2). Server results are still capped at the
    default page size (~50), so the term below is chosen to match a small,
    predictable subset. A failure here means the behavior drifted again —
    update code/README/skill/issue #2 together.
    """
    named = sorted(d.name for d in baseline_domains if d.name and "." in d.name)
    if not named:
        pytest.skip("no named domains in this environment to search for")

    fqdn = named[0]
    err, body = _try_get(client, _DOMAINS, {"search": fqdn})
    assert err is None, f"exact-FQDN search errored: {err}"
    exact_rows = _rows(body)
    assert any(r.get("domainName") == fqdn for r in exact_rows if isinstance(r, dict)), (
        f"exact-FQDN search for {fqdn!r} did not return the domain (rows={len(exact_rows)})"
    )

    # Pick a dot-free label whose client-side match count is small enough to
    # be immune to the ~50-row default page cap.
    term = None
    expected: set[str] = set()
    for name in named:
        label = name.lstrip("*.").split(".")[0]
        if len(label) < 3:
            continue
        matches = {n for n in named if label in n}
        if 1 <= len(matches) <= 40:
            term, expected = label, matches
            break
    if term is None:
        pytest.skip("no domain label yields a small predictable substring-match set")

    err, body = _try_get(client, _DOMAINS, {"search": term})
    assert err is None, f"substring search errored: {err}"
    got = {str(r.get("domainName")) for r in _rows(body) if isinstance(r, dict) and r.get("domainName")}
    if probe_env == "sandbox":
        assert got == expected, (
            f"substring search for {term!r} returned {sorted(got)[:5]}... ({len(got)} rows), "
            f"expected the {len(expected)} matching domains — record drift on issue #2"
        )
    else:
        # Environment split confirmed 2026-07-02 (issue #2): production still
        # returns 0 rows for a substring while the sandbox matches correctly.
        assert got == set(), (
            f"prod substring search for {term!r} returned {len(got)} rows — the vendor fix "
            "reached production; update get_list()/README/skill/issue #2 together"
        )


def test_probe_r02_combined_status_filters(client: CertiNextClient) -> None:
    """R02: combining ``domainStatus`` and ``dcvStatus`` server-side.

    Contradiction under test: the ``get_pending_dcv`` workaround was built on
    a 400 for the combination, but GitLab issue #6 records
    ``domainStatus=ACTIVE&dcvStatus=PENDING,REJECTED`` as working. The probe
    asserts the combination is ACCEPTED (issue #6's newer evidence); if this
    fails with a 400 the fetch-all workaround must stay and the register/
    issues #2/#6 record the env split.
    """
    err, body = _try_get(client, _DOMAINS, {"domainStatus": "ACTIVE", "dcvStatus": "PENDING,REJECTED"})
    assert err is None, (
        f"combined domainStatus+dcvStatus filter rejected with HTTP {err} "
        "(issue #6 recorded it as working — record the outcome on issues #2/#6)"
    )
    assert isinstance(_rows(body), list)


def test_probe_r03_sortby_paging_stable(client: CertiNextClient, baseline_domains: list[Domain]) -> None:
    """R03: ``sortBy=domainName`` is accepted and offset-pages without skips/dups."""
    page_size = 50
    seen: list[str] = []
    offset = 0
    for _ in range(30):
        err, body = _try_get(
            client, _DOMAINS,
            {"sortBy": "domainName", "sortDir": "asc", "limit": page_size, "offset": offset},
        )
        assert err is None, f"sortBy=domainName paging rejected: HTTP {err}"
        rows = [r.get("domainId") for r in _rows(body) if isinstance(r, dict)]
        if not rows:
            break
        seen.extend(str(r) for r in rows)
        offset += page_size
    assert len(seen) == len(set(seen)), "sortBy=domainName paging returned duplicate rows"
    assert len(set(seen)) == len(baseline_domains), (
        f"sortBy paging total {len(set(seen))} != library baseline {len(baseline_domains)}"
    )


def test_probe_r04_default_page_truncates(client: CertiNextClient, baseline_domains: list[Domain]) -> None:
    """R04: a no-param request silently truncates to the server default page (~50)."""
    if len(baseline_domains) <= 50:
        pytest.skip(f"only {len(baseline_domains)} domains here — default-page truncation unobservable")
    err, body = _try_get(client, _DOMAINS)
    assert err is None
    rows = _rows(body)
    assert len(rows) < len(baseline_domains), (
        f"no-param request returned all {len(rows)} rows — server default page behavior changed"
    )
    assert len(rows) == 50, f"server default page is {len(rows)}, believed 50"


# ---------------------------------------------------------------------------
# R05-R06: certificate download behavior (sandbox)
# ---------------------------------------------------------------------------


def _find_downloadable_cert(client: CertiNextClient) -> tuple[str, dict[str, Any]] | None:
    """Return ``(cert_id, download_body)`` for an issued cert with a chain, if any."""
    err, body = _try_get(client, _ORDERS, {"page": 1, "size": 100})
    if err is not None:
        return None
    for row in _rows(body):
        if not isinstance(row, dict):
            continue
        # The ssl-certificates endpoints are keyed by the report row's
        # orderNumber (same derivation the healthcheck uses).
        cert_id = row.get("orderNumber")
        if not cert_id:
            continue
        derr, dbody = _try_get(client, f"{_SSL}/{cert_id}/certificate")
        if derr is None and isinstance(dbody, dict) and dbody.get("chainPem"):
            return str(cert_id), dbody
    return None


def test_probe_r05_chain_order_misordered(probe_env: str, client: CertiNextClient) -> None:
    """R05: raw ``chainPem`` is misordered (root before intermediate) — GitLab #4/#5."""
    _sandbox_only(probe_env)
    found = _find_downloadable_cert(client)
    if not found:
        pytest.skip("no downloadable issued certificate with a chain in the sandbox")
    _, body = found
    dl = CertificateDownload(body)
    raw = dl.chain_pem
    if len(raw) < 2:
        pytest.skip("chain has fewer than 2 certificates — order unobservable")
    ordered = order_certificate_chain(raw, leaf_pem=dl.certificate_pem)
    assert ordered != raw, (
        "raw chainPem is now correctly ordered — vendor fix? Update order_certificate_chain "
        "default, README, and GitLab issues #4/#5 together (vendor #134123)"
    )


def test_probe_r06_pkcs7_download_406(probe_env: str, client: CertiNextClient) -> None:
    """R06: PKCS#7 Accept header on certificate download returns 406 (ADR 0001)."""
    _sandbox_only(probe_env)
    found = _find_downloadable_cert(client)
    if not found:
        pytest.skip("no downloadable issued certificate in the sandbox")
    cert_id, _ = found
    with pytest.raises(CertiNextAPIError) as excinfo:
        client.get_bytes(f"{_SSL}/{cert_id}/certificate", accept="application/pkcs7-mime")
    assert excinfo.value.status_code == 406, (
        f"PKCS#7 download now returns HTTP {excinfo.value.status_code}, believed 406 — "
        "revisit ADR 0001 if the format became available"
    )


# ---------------------------------------------------------------------------
# R07-R08: payload shapes (corpus-backed)
# ---------------------------------------------------------------------------


def test_probe_r07_list_endpoint_shapes(client: CertiNextClient) -> None:
    """R07: every list endpoint's payload is a bare array or a dict with one list value."""
    cases = ((_DOMAINS, {"limit": 5}), (_ORDERS, {"page": 1, "size": 5}), (_LEDGER, {"page": 1, "size": 5}))
    for path, params in cases:
        err, body = _try_get(client, path, params)
        assert err is None, f"{path} errored: HTTP {err}"
        assert isinstance(body, (list, dict)), f"{path} returned {type(body).__name__}"
        if isinstance(body, dict):
            lists = [k for k, v in body.items() if isinstance(v, list)]
            assert lists, f"{path} wrapper dict has no list value — unwrap workaround would break"


def test_probe_r08_dcv_payload_keys(probe_env: str, client: CertiNextClient, baseline_domains: list[Domain]) -> None:
    """R08: DCV payloads use one of the known token-key variants (host may be absent)."""
    _sandbox_only(probe_env)
    token_keys = {"txtToken", "fileToken", "token", "dnsContents"}
    host_keys = {"dnsHost", "host"}
    checked = 0
    for domain in baseline_domains[:20]:
        err, body = _try_get(client, f"{_DOMAINS}/{domain.id}/dcv")
        if err is not None or not isinstance(body, dict):
            continue
        checked += 1
        present_token = token_keys & set(body)
        if present_token:
            found_host = host_keys & set(body)
            # Record for the register: which variant this environment uses now.
            print(f"R08: domain {domain.id} dcv keys: token={sorted(present_token)} host={sorted(found_host)}")
            return
    if not checked:
        pytest.skip("no domain DCV payloads retrievable")
    pytest.fail(f"none of {checked} DCV payloads contained a known token key {sorted(token_keys)}")


def test_probe_r09_dcv_inheritance_recon() -> None:
    """R09: resolved by the DCV-inheritance plan's Phase 0 recon (2026-07-02).

    Findings (docs/plans/dcv-inheritance-ga.md + PHASE0-FINDINGS.md): no
    verification-type field exists in the API; derive via verifiedAt-timing +
    validTill-equality fingerprints; exclusion is not queryable. Do not re-run
    the recon here.
    """
    pytest.skip("resolved 2026-07-02 by DCV-inheritance GA plan Phase 0 recon — see PHASE0-FINDINGS.md")


# ---------------------------------------------------------------------------
# R10-R15: order lifecycle (sandbox mutations — dedicated run required)
# ---------------------------------------------------------------------------

_LIFECYCLE_SKIP = (
    "requires sandbox order-lifecycle mutations — deferred to a dedicated sandbox "
    "issuance probe run (phase-0 register row not yet automated)"
)


def test_probe_r10_order_create_agreement_key() -> None:
    """R10: order create body key is ``agreement`` despite errors naming ``agreementDetails``."""
    pytest.skip(_LIFECYCLE_SKIP)


def test_probe_r11_post_issuance_download_lag() -> None:
    """R11: 422 lag between status=issued and first successful download (retry 5x5s)."""
    pytest.skip(_LIFECYCLE_SKIP)


def test_probe_r12_order_state_machine_races() -> None:
    """R12: duplicate CSR submit tolerated as 422; agreement/DCV advance errors swallowed."""
    pytest.skip(_LIFECYCLE_SKIP)


def test_probe_r13_token_revocation_semantics() -> None:
    """R13: tokens revocable early; token-endpoint errors carry ``invalid_client``."""
    pytest.skip("requires a long sandbox poll beyond token TTL — deferred to a dedicated run")


def test_probe_r14_retry_after_numeric() -> None:
    """R14: 429 ``Retry-After`` is numeric seconds, not an HTTP-date."""
    pytest.skip("requires deliberately triggering a 429 burst — deferred to a dedicated (opt-in) run")


def test_probe_r15_error_body_taxonomy() -> None:
    """R15: RFC 7807 + Spring error mix; 409 duplicate-domain may carry existingDomainId."""
    pytest.skip(_LIFECYCLE_SKIP)


# ---------------------------------------------------------------------------
# R16-R17: reports paging and exact-search reliance
# ---------------------------------------------------------------------------


def test_probe_r16_reports_paging_semantics(client: CertiNextClient) -> None:
    """R16: reports wrap rows in ``content``+``totalPages``; bad pages are clamped.

    Observed 2026-07-02: the wrapper is Spring-style (``content``, ``page``,
    ``size``, ``totalElements``, ``totalPages``) and an out-of-range ``page``
    is clamped to the valid range — a past-the-end request returns the *last*
    page's rows again, never an empty list. ``get_list`` therefore terminates
    on ``totalPages`` (short-page alone would loop forever when the total is
    an exact multiple of the page size).
    """
    err, body = _try_get(client, _ORDERS, {"page": 1, "size": 5})
    assert err is None, f"page=1&size=5 rejected: HTTP {err}"
    assert isinstance(body, dict), f"orders report is now a {type(body).__name__}, believed wrapper dict"
    missing = {"content", "totalPages", "totalElements"} - set(body)
    assert not missing, f"orders wrapper lost keys {sorted(missing)} — get_list termination depends on totalPages"
    first = _rows(body)
    assert len(first) <= 5, f"size=5 returned {len(first)} rows"
    total = body.get("totalElements")

    err, past = _try_get(client, _ORDERS, {"page": 99999, "size": 100})
    assert err is None, f"past-the-end page rejected: HTTP {err}"
    past_rows = _rows(past)
    if isinstance(total, int) and total > 0:
        assert past_rows, (
            "past-the-end page now returns an empty list (clamping stopped) — "
            "the totalPages-based termination in get_list is still correct, but update this probe"
        )


def test_probe_r17_exact_search_reliability(client: CertiNextClient, baseline_domains: list[Domain]) -> None:
    """R17: exact-FQDN ``search`` returns exactly the requested domain.

    ``Domain.get(name)`` currently iterates the full list because search was
    untrusted. Green here (and in the other env) is the evidence phase 1
    needs to switch ``get()`` to one filtered request.
    """
    named = sorted(d.name for d in baseline_domains if d.name and "." in d.name)
    if len(named) < 2:
        pytest.skip("need at least two named domains to check exact-search selectivity")
    fqdn = named[len(named) // 2]
    err, body = _try_get(client, _DOMAINS, {"search": fqdn})
    assert err is None
    names = [r.get("domainName") for r in _rows(body) if isinstance(r, dict)]
    assert fqdn in names, f"exact search missed {fqdn!r}"
    strangers = [n for n in names if n != fqdn and n is not None and not str(n).endswith(f".{fqdn}")]
    assert not strangers, f"exact search for {fqdn!r} also returned unrelated rows: {strangers[:5]}"


# ---------------------------------------------------------------------------
# R18-R19: DCV token lifecycle (sandbox mutations)
# ---------------------------------------------------------------------------


def test_probe_r18_expired_token_reissue() -> None:
    """R18: expired DCV token reads empty; same-method change mints a fresh token."""
    pytest.skip(_LIFECYCLE_SKIP)


def test_probe_r19_multiperspective_verify() -> None:
    """R19: DCV verify is multi-perspective; PENDING until globally propagated."""
    pytest.skip(_LIFECYCLE_SKIP)


# ---------------------------------------------------------------------------
# R20-R23: org payloads, OpenAPI-only fields, exceptions, contested enums
# ---------------------------------------------------------------------------


def test_probe_r20_org_list_vs_detail(client: CertiNextClient) -> None:
    """R20: org list/detail field sets differ; ``isPreVettingOrg`` is string '1'/'0'."""
    err, body = _try_get(client, _ORGS)
    assert err is None, f"organizations list errored: HTTP {err}"
    orgs = [o for o in _rows(body) if isinstance(o, dict) and o.get("organizationNumber")]
    if not orgs:
        pytest.skip("no organizations visible to these credentials")
    first = sorted(orgs, key=lambda o: str(o["organizationNumber"]))[0]
    err, detail = _try_get(client, f"{_ORGS}/{first['organizationNumber']}")
    assert err is None, f"organization detail errored: HTTP {err}"
    assert isinstance(detail, dict)
    list_keys, detail_keys = set(first), set(detail)
    assert list_keys != detail_keys, "org list and detail field sets converged — update workarounds"
    for source, payload in (("list", first), ("detail", detail)):
        if "isPreVettingOrg" in payload:
            value = payload["isPreVettingOrg"]
            assert isinstance(value, str) and value in ("0", "1"), (
                f"isPreVettingOrg in {source} is {value!r} ({type(value).__name__}), believed string '0'/'1'"
            )


def test_probe_r21_openapi_only_order_fields() -> None:
    """R21: preVettingToken/csr-in-create/delegation/recipientEmails/tags OpenAPI-only."""
    pytest.skip(
        "requires sandbox OV order creation with/without prevetting token — deferred to a "
        "dedicated run (also re-check the token-not-applying report for org 7956989)"
    )


def test_probe_r22_exception_hierarchy_invariant() -> None:
    """R22: ``CertiNextAPIError`` subclasses ``requests.HTTPError``.

    The healthcheck's catch-order depends on this; phase 2's reclassification
    must change this deliberately, not by accident.
    """
    assert issubclass(CertiNextAPIError, requests.HTTPError)


def test_probe_r23_contested_enum_values(probe_env: str, client: CertiNextClient) -> None:
    """R23: ``dcvStatus=EXPIRED`` rejected (400); ``domainStatus=DEACTIVATED`` contested.

    Vendor #135290 / GitLab issue #6. Hold ``DcvStatus``/``DomainStatus``
    edits until the vendor answers; this probe records each env's behavior.
    """
    err, _ = _try_get(client, _DOMAINS, {"dcvStatus": "EXPIRED"})
    print(f"R23: {probe_env} dcvStatus=EXPIRED -> {'HTTP ' + str(err) if err else 'accepted'}")
    assert err == 400, (
        f"dcvStatus=EXPIRED now returns {'HTTP ' + str(err) if err else 'success'}, believed 400 — "
        "record on issue #6 / vendor #135290"
    )
    err, _ = _try_get(client, _DOMAINS, {"domainStatus": "DEACTIVATED"})
    print(f"R23: {probe_env} domainStatus=DEACTIVATED -> {'HTTP ' + str(err) if err else 'accepted'}")
    assert err in (None, 400), (
        f"domainStatus=DEACTIVATED returned unexpected HTTP {err} (neither accepted nor 400)"
    )


def test_probe_r24_release_pipeline_semantics() -> None:
    """R24: ``needs: optional: true`` lets release jobs skip when sandbox reddens CI."""
    pytest.skip("observational row: verify on the next tag pipeline, not via the API")
