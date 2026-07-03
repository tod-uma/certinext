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

"""Capture a sanitized corpus of real CertiNext API payloads (read-only).

Performs GETs against one environment (production by default, sandbox with
``--sandbox``) and writes one JSON file per endpoint to
``tests/fixtures/corpus/{prod,sandbox}/<endpoint-slug>.json``. Each file
records the request (method, path, params), the response status, the
**response headers** (the presence or absence of ``ETag`` /
``Last-Modified`` / ``Cache-Control`` decides the future shape of caching
support, and headers cost nothing to keep), and the JSON body.

The corpus files are the ground-truth fixtures the 1.0 pydantic models must
parse (ADR 0005), and the shape evidence for assumption-register rows R07,
R08, and R20 (see docs/plans/pydantic-typer-refactor/).

Sanitization
------------

Bodies, params, and paths are pseudonymized **deterministically** before
writing, so a recapture of unchanged server state produces a clean diff.
The mapping (see :data:`_KEY_RULES` and the ``_pseudo_*`` functions):

- **Domain names** — each DNS label except the final (TLD) label is replaced
  with ``x`` + 7 hex chars of ``sha256("certinext-corpus|" + label)``.
  Hierarchy is preserved: equal labels map to equal pseudonyms, so
  parent/child relationships (DCV inheritance analysis) survive.
- **Emails** — ``user-<6 hex of sha256>@example.invalid``.
- **Phone numbers** — every digit replaced from a hash-derived decimal
  stream; non-digit formatting (``+``, dashes) kept, so the vendor's format
  variance survives.
- **Person / organization names** — ``Name-<6 hex>`` / ``Org-<6 hex>``.
- **Identifiers** (org / account / domain / order ids) — pseudo-ids derived
  from ``sha256`` of the real id, so cross-file correlation (a domain's list
  row vs its detail file) still works. Structure and digit-count are
  preserved for numeric ids.
- **Certificate PEM/DER blobs are left untouched** — issued certificates are
  public via Certificate Transparency logs, and rewriting a PEM would break
  the parse-round-trip value of the fixture.
- **Geography is kept** (``organizationStateName``, ``organizationLocality``,
  country fields): it appears verbatim in publicly-logged OV certificates and
  identifies nothing beyond the institution's public address.
- **Response headers** — ``Set-Cookie`` and auth-related headers are
  dropped; everything else is kept verbatim.

The pseudonymization salt is a fixed string committed in this file: the goal
is to avoid casually publishing the account's domain/org inventory, not
cryptographic secrecy (the domains themselves are public DNS names).

**Committing the output is a manual gate**: a human reviews the diff of
``tests/fixtures/corpus/`` before commit — see
``tests/fixtures/corpus/README.md``.

Usage::

    uv run python scripts/capture_corpus.py            # production (read-only)
    uv run python scripts/capture_corpus.py --sandbox  # sandbox
    uv run python scripts/capture_corpus.py --keep-raw /some/private/dir

Credentials resolve exactly like the integration tests: OS keyring profile
(default profile for production, ``sandbox`` profile for sandbox), falling
back to ``CERTINEXT_CLIENT_ID`` / ``CERTINEXT_CLIENT_SECRET`` (or the
``CERTINEXT_SANDBOX_*`` variants) environment variables.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import certinext  # noqa: E402
from certinext._keyring import keyring_get, keyring_service  # noqa: E402
from certinext.client import CertiNextClient  # noqa: E402
from certinext.exceptions import CertiNextAPIError  # noqa: E402

_SALT = "certinext-corpus|"

#: Response headers never written to the corpus. The correlation/request ids
#: are volatile per response and would make every recapture diff noisy.
_DROP_HEADERS = {
    "set-cookie", "authorization", "proxy-authenticate", "www-authenticate",
    "x-correlation-id", "x-request-id",
}

#: JSON keys whose string values are treated as domain names.
_DOMAIN_KEYS = {
    "domainname", "domain", "domains", "commonname", "cn", "dnshost", "host", "sans", "san",
    "subjectalternativenames", "parentdomain", "fqdn", "subject",
}

#: JSON keys whose string values are treated as email addresses.
_EMAIL_KEYS = {"email", "requestoremail", "contactemail", "adminemail", "techemail", "recipientemails"}

#: JSON keys whose string values are person names (or person-adjacent, like
#: the subscriber agreement's signing place).
_PERSON_KEYS = {
    "requestorname", "contactname", "createdby", "modifiedby", "firstname", "lastname",
    "signedplace", "signername",
}

#: JSON keys whose string values are organization names. Bare ``name`` is
#: intentionally absent — it is org-name only inside /organizations payloads,
#: which pass ``org_name_keys=True`` (product names etc. stay readable).
_ORG_NAME_KEYS = {"organizationname", "orgname", "companyname", "legalname", "groupname"}

#: JSON keys whose string values are phone numbers.
_PHONE_KEYS = {"phone", "phonenumber", "mobilenumber", "telephonenumber", "fax", "faxnumber"}

#: JSON keys treated as correlatable identifiers (pseudonymized, not dropped).
_ID_KEYS = {
    "id", "domainid", "orgid", "organizationid", "orderid", "ordernumber",
    "accountnumber", "certificateid", "parentid", "groupid",
    "organizationnumber", "groupnumber", "representativenumber",
    "requestnumber", "requestid", "attemptid",
}


def _hash(text: str, length: int = 7) -> str:
    """Return the first ``length`` hex chars of the salted SHA-256 of ``text``."""
    return hashlib.sha256((_SALT + text).encode("utf-8")).hexdigest()[:length]


def _pseudo_domain(value: str) -> str:
    """Pseudonymize a domain name label-by-label, keeping the final (TLD) label.

    Equal labels always map to equal pseudonyms so DNS hierarchy survives.
    Values that don't look like a domain (no dot) are returned unchanged.
    """
    if "." not in value:
        return value
    labels = value.lower().strip(".").split(".")
    return ".".join(["x" + _hash(lb) for lb in labels[:-1]] + [labels[-1]])


def _pseudo_email(value: str) -> str:
    """Pseudonymize an email address deterministically."""
    return f"user-{_hash(value, 6)}@example.invalid"


def _pseudo_id(value: Any) -> Any:
    """Pseudonymize an identifier, preserving type and digit-count.

    Integers (and all-digit strings) map to a same-width number derived from
    the hash — as int or str to match the input — so downstream ``int()``
    parsing and shape expectations still hold. Other strings map to
    ``id-<8 hex>``.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        digits = len(str(abs(int(value))))
        h = int(hashlib.sha256((_SALT + str(value)).encode()).hexdigest(), 16)
        low, high = 10 ** (digits - 1), 10**digits
        pseudo = low + h % (high - low)
        return pseudo if isinstance(value, int) else str(pseudo)
    return f"id-{_hash(str(value), 8)}"


def _pseudo_phone(value: str) -> str:
    """Pseudonymize a phone number, preserving its exact format.

    Every digit is replaced from a hash-derived decimal stream; non-digit
    characters (``+``, ``-``, spaces, parentheses) are kept in place, so the
    format variance the vendor sends (``2075551234`` vs ``+12075551234``) —
    which future models must parse — survives sanitization.
    """
    stream = str(int(hashlib.sha256((_SALT + value).encode()).hexdigest(), 16))
    out: list[str] = []
    i = 0
    for ch in value:
        if ch.isdigit():
            out.append(stream[i % len(stream)])
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _looks_like_email(value: str) -> bool:
    """Heuristic: does this string look like an email address?"""
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def sanitize(node: Any, *, org_name_keys: bool = False) -> Any:
    """Recursively pseudonymize a JSON structure per the documented mapping.

    Args:
        node: Parsed JSON value (dict, list, or scalar).
        org_name_keys: When True, bare ``name`` keys are treated as
            organization names (used for /organizations payloads).

    Returns:
        A sanitized deep copy; the input is not modified.
    """
    if isinstance(node, dict):
        # A dict with an email/phone sibling is a contact record: its bare
        # ``name`` is a person name (e.g. requestor.name, signer blocks).
        contact_record = any(
            k.lower() in _EMAIL_KEYS or k.lower() in _PHONE_KEYS or k.lower() == "emailid" for k in node
        )
        out: dict[str, Any] = {}
        for key, value in node.items():
            lk = key.lower()
            if isinstance(value, str) and value:
                if lk in _EMAIL_KEYS or _looks_like_email(value):
                    out[key] = _pseudo_email(value)
                elif lk in _DOMAIN_KEYS:
                    out[key] = _pseudo_domain(value)
                elif lk in _PERSON_KEYS or (contact_record and lk == "name"):
                    out[key] = f"Name-{_hash(value, 6)}"
                elif lk in _PHONE_KEYS:
                    out[key] = _pseudo_phone(value)
                elif lk in _ORG_NAME_KEYS or (org_name_keys and lk == "name"):
                    out[key] = f"Org-{_hash(value, 6)}"
                elif lk in _ID_KEYS:
                    out[key] = _pseudo_id(value)
                else:
                    out[key] = value
            elif lk in _ID_KEYS:
                out[key] = _pseudo_id(value)
            elif isinstance(value, list) and lk in _DOMAIN_KEYS:
                out[key] = [
                    _pseudo_domain(v) if isinstance(v, str) else sanitize(v, org_name_keys=org_name_keys)
                    for v in value
                ]
            elif isinstance(value, list) and lk in _EMAIL_KEYS:
                out[key] = [
                    _pseudo_email(v) if isinstance(v, str) else sanitize(v, org_name_keys=org_name_keys)
                    for v in value
                ]
            else:
                out[key] = sanitize(value, org_name_keys=org_name_keys)
        return out
    if isinstance(node, list):
        return [sanitize(item, org_name_keys=org_name_keys) for item in node]
    return node


def sanitize_path(path: str) -> str:
    """Pseudonymize numeric/opaque ids embedded in a request path."""
    return re.sub(
        r"(?<=/)(\d{2,})(?=/|$)",
        lambda m: str(_pseudo_id(int(m.group(1)))),
        path,
    )


def raw_get(client: CertiNextClient, path: str, params: dict[str, Any] | None = None) -> requests.Response:
    """Perform an authenticated GET and return the raw Response (with headers).

    Uses the client's internal session/token plumbing (`_execute` /
    `_headers`) because the public :meth:`CertiNextClient.get` returns only
    the parsed body; the corpus needs the response headers too. Raises
    the same typed errors as the public method on non-2xx.
    """
    resp = client._execute(
        lambda: client._session.get(f"{client.base_url}{path}", headers=client._headers(), params=params)
    )
    client._raise_api_error(resp)
    return resp


def build_client(sandbox: bool) -> CertiNextClient:
    """Resolve credentials (keyring, then env vars) and return a low-level client.

    Args:
        sandbox: Target the sandbox environment instead of production.

    Raises:
        SystemExit: When no credentials can be resolved.
    """
    import os

    profile = "sandbox" if sandbox else None
    svc = keyring_service("certinext", profile)
    env_prefix = "CERTINEXT_SANDBOX_" if sandbox else "CERTINEXT_"
    client_id = keyring_get(svc, "CERTINEXT_CLIENT_ID") or os.environ.get(env_prefix + "CLIENT_ID")
    client_secret = keyring_get(svc, "CERTINEXT_CLIENT_SECRET") or os.environ.get(env_prefix + "CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit(
            f"No credentials for {'sandbox' if sandbox else 'production'}: "
            f"run certinext-setup-keyring{' --sandbox' if sandbox else ''} "
            f"or set {env_prefix}CLIENT_ID / {env_prefix}CLIENT_SECRET."
        )
    base = certinext.SANDBOX_BASE_URL if sandbox else certinext.BASE_URL
    token = certinext.SANDBOX_TOKEN_URL if sandbox else certinext.TOKEN_URL
    return CertiNextClient(base, token, client_id, client_secret)


def _first_list(body: Any) -> list[Any]:
    """Return the first list value in a response body (bare array or wrapper dict).

    Mirrors the unwrap workaround catalogued as register row R07; the corpus
    itself records the raw shape, this helper just needs *a* list to derive
    tier-2 ids from.
    """
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, list):
                return value
    return []


def capture(client: CertiNextClient, out_dir: Path, raw_dir: Path | None) -> int:
    """Capture all corpus endpoints into ``out_dir``; return count of failures.

    Endpoint order matters: tier-2 captures derive their ids from tier-1
    bodies, always choosing the lexicographically-smallest candidate so
    recaptures pick the same record while server state is unchanged.

    Args:
        client: Authenticated low-level client.
        out_dir: Directory for sanitized corpus files (created if needed).
        raw_dir: Optional directory for unsanitized copies (never commit).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if raw_dir:
        raw_dir.mkdir(parents=True, exist_ok=True)

    captured: dict[str, Any] = {}
    failures = 0

    def one(slug: str, path: str, params: dict[str, Any] | None = None, *, org_names: bool = False) -> Any:
        """Capture one endpoint; record failures without aborting the run."""
        nonlocal failures
        try:
            resp = raw_get(client, path, params)
        except (CertiNextAPIError, requests.RequestException) as exc:
            print(f"  FAIL  {slug}: {exc}", file=sys.stderr)
            failures += 1
            return None
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_HEADERS}
        record = {
            "request": {"method": "GET", "path": sanitize_path(path), "params": sanitize(params) if params else None},
            "response": {
                "status": resp.status_code,
                "headers": headers,
                "body": sanitize(body, org_name_keys=org_names),
            },
        }
        (out_dir / f"{slug}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if raw_dir:
            raw_record = {
                "request": {"method": "GET", "path": path, "params": params},
                "response": {"status": resp.status_code, "headers": headers, "body": body},
            }
            (raw_dir / f"{slug}.json").write_text(
                json.dumps(raw_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        print(f"  ok    {slug}", file=sys.stderr)
        captured[slug] = body
        return body

    # --- Tier 1: no derived input ------------------------------------------
    one("auth-me", "/api/certinext/v2/auth/me")
    one("groups", "/api/certinext/v2/groups")
    orgs_body = one("organizations-list", "/api/certinext/v2/organizations", org_names=True)
    products_body = one("catalog-products", "/api/certinext/v2/catalog/products")
    domains_body = one(
        "domains-list", "/api/certinext/v2/domains",
        {"sortBy": "domainName", "sortDir": "asc", "limit": 100, "offset": 0},
    )
    # A second, param-less capture records the server-default page (register R04).
    one("domains-list-default", "/api/certinext/v2/domains")
    orders_body = one("reports-orders", "/api/certinext/v2/reports/orders", {"page": 1, "size": 100})
    one("reports-ledger", "/api/certinext/v2/reports/ledger", {"page": 1, "size": 100})

    # --- Tier 2: ids derived from tier-1 bodies -----------------------------
    orgs = _first_list(orgs_body)
    org_id = min(
        (str(o.get("organizationNumber")) for o in orgs if isinstance(o, dict) and o.get("organizationNumber")),
        default=None,
    )
    if org_id:
        one("organizations-detail", f"/api/certinext/v2/organizations/{org_id}", org_names=True)

    products = _first_list(products_body)
    codes: list[str] = []
    for cat in products:
        if isinstance(cat, dict):
            for prod in _first_list(cat) or cat.get("products", []):
                if isinstance(prod, dict) and prod.get("code"):
                    codes.append(str(prod["code"]))
            if cat.get("code"):
                codes.append(str(cat["code"]))
    if codes:
        one("catalog-custom-fields", f"/api/certinext/v2/catalog/products/{min(codes)}/custom-fields")

    domains = _first_list(domains_body)
    dom = min(
        (d for d in domains if isinstance(d, dict) and d.get("domainId")),
        key=lambda d: str(d.get("domainName", "")),
        default=None,
    )
    if dom:
        dom_id = dom["domainId"]
        one("domains-detail", f"/api/certinext/v2/domains/{dom_id}")
        one("domains-dcv", f"/api/certinext/v2/domains/{dom_id}/dcv")
        one("domains-dcv-attempts-last", f"/api/certinext/v2/domains/{dom_id}/dcv/attempts/last")
        one("domains-dcv-attempts", f"/api/certinext/v2/domains/{dom_id}/dcv/attempts")

    orders = _first_list(orders_body)
    # ssl-certificates endpoints are keyed by the report row's orderNumber.
    # Not every order is in a downloadable state (422 EMS-1165 otherwise), so
    # try candidates in sorted order and keep the first that downloads —
    # deterministic while server state is unchanged.
    cert_ids = sorted(str(o.get("orderNumber")) for o in orders if isinstance(o, dict) and o.get("orderNumber"))
    for cert_id in cert_ids[:20]:
        try:
            raw_get(client, f"/api/certinext/v2/ssl-certificates/{cert_id}/certificate")
        except (CertiNextAPIError, requests.RequestException):
            continue
        one("ssl-certificates-detail", f"/api/certinext/v2/ssl-certificates/{cert_id}")
        one("ssl-certificates-certificate", f"/api/certinext/v2/ssl-certificates/{cert_id}/certificate")
        break
    else:
        if cert_ids:
            print("  note  no downloadable certificate among first 20 orders", file=sys.stderr)

    return failures


def main() -> None:
    """Entry point: parse args, capture one environment's corpus."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--sandbox", action="store_true", help="capture the sandbox instead of production")
    parser.add_argument(
        "--out-root", default="tests/fixtures/corpus",
        help="root output directory (default: %(default)s); the env name is appended",
    )
    parser.add_argument(
        "--keep-raw", metavar="DIR", default=None,
        help="also write unsanitized copies to DIR (keep outside the repo; never commit)",
    )
    args = parser.parse_args()

    env = "sandbox" if args.sandbox else "prod"
    client = build_client(args.sandbox)
    out_dir = Path(args.out_root) / env
    raw_dir = Path(args.keep_raw) / env if args.keep_raw else None
    print(f"Capturing {env} corpus to {out_dir} (read-only GETs)", file=sys.stderr)
    failures = capture(client, out_dir, raw_dir)
    if failures:
        print(f"{failures} endpoint(s) failed — corpus incomplete", file=sys.stderr)
        raise SystemExit(1)
    print("Done. Review the diff before committing (sanitization gate).", file=sys.stderr)


if __name__ == "__main__":
    main()
