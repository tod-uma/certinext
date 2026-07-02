---
status: planned
depends-on: [phase-0]
implements-adr: [0003, 0005]
---

# Phase 1 — Pydantic models

Tracking: issue #14 · milestone %v1.0.0 · label ~"refactor-v1"

Replace the raw-dict + `@property` response classes with
[pydantic v2](https://docs.pydantic.dev/latest/) models under the leniency
policy of ADR 0005, without changing the *behavioral* surface consumers use.
On the refactor branch; merge `main` first (brings the phase-0 corpus).

## Scope

Response classes in `accounts.py` (AccountInfo, Group, Organization),
`catalog.py` (Product, ProductCategory, CustomField), `domains.py` (Domain,
DcvInfo, DcvVerifyResult), `ledger.py` (LedgerRecord), `orders.py`
(OrderRecord), `ssl_certificates.py` (DcvChallenge, CertificateDownload,
SslOrder), `csr.py` (CsrInfo). Accessors keep their method signatures;
`OrderWorkflow` logic is untouched apart from the types flowing through it.

## Design constraints (each traces to survey evidence)

- **Attribute surface is frozen.** `ums-certinext-scripts` uses, at minimum:
  `Domain.name/.status/.dcv_status/.needs_dcv/.get_dcv()/.verify()/
  .reinitiate_dcv()/.refresh()/.dcv_expires_soon(days)`, DCV objects'
  `.method/.token/.host`, `filter_needs_dcv(domains, all_names)`, and
  `get_list(pattern=...)`. Its mocked tests assert `get_list` called with
  `pattern=` exactly. These names and signatures do not change.
- **Verb methods need a client.** Domain/SslOrder call the API; models carry
  the client via a
  [`PrivateAttr`](https://docs.pydantic.dev/latest/concepts/models/#private-model-attributes)
  (excluded from validation/serialization), set by the accessor after
  `model_validate`.
- **`as_dict()` survives** (ADR 0005 raw-payload escape hatch) and returns
  the original wire-shaped dict (extras included) — with `extra="allow"`,
  wire keys not mapped to fields stay reachable; implement `as_dict()` to
  reconstruct the original payload (aliases + extras), and keep `to_row()`
  for table output.
- **Leniency policy per ADR 0005**: `extra="allow"`;
  [`AliasChoices`](https://docs.pydantic.dev/latest/concepts/alias/) for the
  DCV fallback chains (`dcvMethod|method`; `txtToken|fileToken|token|
  dnsContents`; `dnsHost|host`; `domain|domainName`) exactly as the 0.3.x
  code resolves them (order matters); `isPreVettingOrg` accepts `"1"`/`"0"`
  strings (field validator); status/enum fields fall back to the raw string
  on unknown values with a logged warning — encode as `KnownEnum | str` with
  a validator, do not touch the enum *membership* until issue #6 resolves.
- **Wrapper unwrap stays behavioral**: the first-list-valued-key scan in
  `domains.py`/`orders.py` remains at the accessor layer (it is about
  envelope shape, not row shape) unless phase-0 R07 shows the envelope is
  now stable and documented — then model it explicitly.
- **Lazy org detail fetch** (list-item Organization lazily GETs
  `/organizations/{id}` for detail-only fields, errors swallowed once) must
  be preserved or explicitly redesigned — flag at implementation; the
  healthcheck deliberately avoids triggering it (`_feed_context` reads
  list fields only).
- **Pagination workarounds are load-bearing** (`_LIST_PAGE_SIZE=200`,
  sortBy=domainName paging, dedupe, `_MAX_LIST_PAGES`): models change row
  parsing, not the paging loop. The wire-param assertions in
  `tests/test_domains.py` (exact `offset`/`limit=200`/`sortBy=domainName`/
  `sortDir` values, ~lines 362–575) are the paging *contract* — carry them
  over verbatim; if any stops passing, that's a behavior regression in the
  refactor, not a test to update.
- **Conditional scope from phase 0 (R02):** if the combined
  `domainStatus`+`dcvStatus` filter was confirmed working in BOTH
  environments, switch `get_pending_dcv()` to server-side filtering here
  (and update `pending_dcv_cli.py`'s comment, the docstring, and README);
  otherwise keep fetch-all + `needs_dcv` exactly as-is.

## Implementation steps

1. `certinext/models/` package (or per-domain modules — implementer's call,
   record it): base `CertiNextModel` with the ADR 0005 `ConfigDict`,
   lenient-enum helper, `as_dict()`/`to_row()` conventions, docstrings per
   house style.
2. Migrate one module end-to-end first (**catalog** — smallest, no verb
   methods) to prove the pattern including corpus-parse tests; then
   accounts, ledger, orders, domains, ssl_certificates in that order
   (roughly ascending coupling).
3. Corpus-parse test: parametrize over every file in
   `tests/fixtures/corpus/**`; each model parses its payloads with zero
   warnings for *known* fields (unknown-field warnings are expected data,
   assert they're logged not raised).
4. Port each module's unit tests as its model lands; keep the existing
   fixtures *in addition to* the corpus (they encode edge cases like
   `bad_domain_data.json`).
5. `pydantic>=2` joins runtime deps in `pyproject.toml`.

## Verification

- Full corpus parses (both env trees); `pytest -m "not integration and not
  probe"` green; `mypy certinext` strict green; pyright green.
- Consumer-surface check: run `ums-certinext-scripts`' test suite with the
  branch installed (`uv pip install -e ../python-libs/certinext` overriding
  the pin locally) — its mocks encode the frozen surface.
- Grep gate: no `self._data.get(` left in migrated modules.

## Documentation expectations

Docstrings on every model class/field group (house rule: all classes and
methods); README "Python library" examples updated for construction-by-
validation where visible; CHANGELOG notes `as_dict()` compatibility.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
