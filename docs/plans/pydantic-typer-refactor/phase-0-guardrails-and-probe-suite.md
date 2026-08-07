---
status: done
depends-on: []
implements-adr: [0005]
---

# Phase 0 — Guardrails and probe suite (lands on `main`)

> **Status note (2026-07-08):** executed 2026-07-02 (MRs !76/!77 merged on
> `main`); the frontmatter had been left at `planned`. The last open exit
> criterion — R08's `DcvInfo` docstring correction — landed with phase 5.
> Deliberately open: 11 sandbox-lifecycle probe skips (R10–R15, R18, R19,
> R21 need a mutating issuance run; R13/R14 need TTL/429 runs) and the
> R24 tag-pipeline observation.

Tracking: issue #13 · milestone %v1.0.0 · label ~"refactor-v1"

Before any rewrite: protect the production consumer from accidental 1.0
pickup, validate the validation instrument, build the probe suite + payload
corpus (ADR 0005), re-verify every catalogued vendor-API assumption in both
environments, and fix known-stale documentation. **All of this ships on
`main`** (normal MR flow, 0.3.x line) and merges into the refactor branch —
both lines need it, and none of it depends on refactor code.

Production access is **strictly read-only** (GETs). Anything mutating
(issuance, DCV state changes) is sandbox-only.

## Step 1 — Cap the consumer pin (first, small, own MR)

In `ums-certinext-scripts/pyproject.toml`, change `certinext>=0.2.2rc1` to
`certinext>=0.2.2rc1,<1`. Because the pin names a pre-release, uv resolves
pre-releases for this package, and no stable certinext exists anywhere — so
an uncapped pin resolves to 1.0.0aN the moment one is published. Per the
[version-specifier spec](https://packaging.python.org/en/latest/specifications/version-specifiers/#exclusive-ordered-comparison),
`<1` excludes pre-releases of 1.0.0 (`1.0.0a1 ∉ <1`); confirm at
implementation time with `uv lock` against an index that carries a 1.0.0aN,
or `uv pip compile --dry-run` equivalent.

**Verify (must prove the cap works, not just that it parses):** build a
1.0.0a1 wheel from the refactor branch (`uv build`), then resolve
ums-certinext-scripts against an index/`--find-links` dir containing BOTH
that wheel and 0.3.0rcN — resolution must still select 0.3.0rcN. Then
`uv lock` in-repo succeeds and the ums test suite is green.

## Step 2 — Validate the healthcheck (the instrument itself)

`certinext-healthcheck` has never been validated against live environments.
Run `certinext-healthcheck -v` (prod) and `certinext-healthcheck --sandbox -v`;
expect all probes PASS/SKIPPED. Investigate any EMPTY/SERVER_BUG before
trusting probe results in later steps. File issues for classification gaps
found. (Timing note: phase 0 runs the 0.3.x healthcheck, which contains no
pydantic — the `ValidationError` classification gap cannot bite here. It
opens when phase 1's models land and is closed by phase 2's classification
rewrite; run phase-0 sign-off with `main`'s code, not the refactor branch.)

**Verify:** both runs exit 0; output archived (`--json`) alongside the corpus.

## Step 3 — Probe suite + payload corpus

New pytest module `tests/test_probes.py` behind a new `probe` marker
(register in `pyproject.toml` next to the existing `integration` marker),
plus a capture mode:

- **Probes**: one test per register row below; each asserts the *currently
  believed* behavior, so a vendor fix or regression = a failing probe, which
  is a signal to update code, README, skill, and GitLab issue together.
- **Capture**: `scripts/capture_corpus.py` (argparse is fine on `main`)
  performs read-only GETs against one environment and writes raw JSON to
  `tests/fixtures/corpus/{sandbox,prod}/<endpoint-slug>.json`, **including
  the response headers** (stored alongside each body) — the presence or
  absence of `ETag`/`Last-Modified`/`Cache-Control` decides the future
  shape of wishlist IDEA-006 (caching), and headers cost nothing to keep. Endpoints:
  everything the healthcheck already probes (auth/me, groups, organizations
  list + detail, catalog products + custom-fields, domains list + detail +
  dcv + dcv attempts, reports/orders, reports/ledger, ssl-certificates
  detail + certificate download JSON).
- **Sanitization is a manual gate**: the capture script pseudonymizes domain
  names and drops/obfuscates org names, contact emails, and identifiers per a
  documented mapping; a human reviews the diff before commit. Keep the
  sanitizer deterministic so recaptures diff cleanly.
- Corpus files become the ground-truth fixtures phase 1 models must parse
  (ADR 0005 Confirmation).

**Verify:** `pytest -m probe` green against sandbox and against prod;
corpus committed and reviewed; `pytest -m "not integration and not probe"`
still what CI runs by default (update `.gitlab-ci.yml` unit-test selector).

## Step 4 — The assumption register

Re-test each item in **both** environments unless marked sandbox-only.
Every drifted result updates, together: the code workaround, README known
issues, `.claude/skills/certinext-api-bugs/SKILL.md`, and the GitLab issue
(per ADR 0002). Numbers are stable IDs for probe names (`probe_r01`...).

| # | Assumption / workaround (code site) | Probe | Env |
| --- | --- | --- | --- |
| R01 | `search` param: exact-FQDN works, substring returns 0 → client-side `pattern` regex (`domains.py` get_list; issue #2) | `GET /domains?search=<substring-no-dot>` vs unfiltered baseline; also exact FQDN | both |
| R02 | `domainStatus`+`dcvStatus` together → HTTP 400 → `get_pending_dcv` fetches all + `needs_dcv` client-side (`domains.py`) | Send combined filters. **Contradiction to resolve:** issue #6 records combo `domainStatus=ACTIVE&dcvStatus=PENDING,REJECTED` as working. **Conditional scope change:** if confirmed in BOTH envs, phase 1 switches `get_pending_dcv()` to server-side filtering (and fixes `pending_dcv_cli.py`'s comment + README); if prod still 400s, the fetch-all workaround stays and the sandbox/prod split is recorded on issue #2/#6 | both |
| R03 | Raw offset paging under default `createdAt desc` sort skips/dups rows → `get_list` pages under `sortBy=domainName&sortDir=asc`, dedupes, `_MAX_LIST_PAGES` ceiling | Loop raw offset pages under default sort, diff IDs across pages; confirm `sortBy=domainName` still accepted; **prod specifically** — issue #1 was CLOSED while its own text said the prod vendor fix was still pending, so closure is NOT prod evidence; keep the dedupe/ceiling defenses regardless (ordering-drift insurance) | both |
| R04 | Server default page ≈50 silently truncates when no `limit` sent | No-param request row count vs sortBy-paged total | both |
| R05 | Chain order: root at position 2 not last → `order_certificate_chain` re-sort default-on (issues #4/#5, vendor #134123) | Inspect raw `chainPem` order on a sandbox-issued cert | sandbox |
| R06 | PKCS#7 download → 406, removed per ADR 0001; format downloads non-fatal | PKCS#7 Accept header on certificate GET | sandbox |
| R07 | List endpoints alternate bare-array vs wrapper dict → first-list-valued-key unwrap (`domains.py`, `orders.py`) | Corpus capture of /domains, /reports/orders, /reports/ledger — record actual shape per env | both |
| R08 | DCV field-name variance (`txtToken`/`fileToken`/`token`/`dnsContents`; `dnsHost`/`host`); host may be absent → implied `_emudhra-challenge.<domain>` | Corpus of domain-DCV + order-DCV payloads; record keys present. **Discrepancy to resolve:** `DcvInfo` docstring implies `_emudhra-challenge.<domain>`, `examples/dns_txt_dcv.py:267-269` falls back to apex — determine which is correct, fix the other | sandbox |
| R09 | DCV-inheritance heuristic (`dcv_covering_parent`, NS-boundary rule) is pre-GA anecdote; GA "Verification Type" field name unknown | = DCV-inheritance plan Phase 0 recon: read-only prod /domains rows, look for verification-type / exclusion fields (see `docs/plans/dcv-inheritance-ga.md`) | prod RO |
| R10 | Order create body: key is `agreement`, though error messages say `agreementDetails` | Sandbox POST with `agreement` block; cross-check sandbox OpenAPI schema | sandbox |
| R11 | Post-issuance 422 lag before certificate downloadable → retry loop (5×5s) in `OrderWorkflow` | Time status=issued → first successful download during sandbox issuance | sandbox |
| R12 | Order state machine races: duplicate CSR submit → 422 tolerated; agreement/DCV errors during advance swallowed | Sandbox lifecycle with csr-in-create-body vs separate submit | sandbox |
| R13 | Tokens revocable early; token-endpoint errors carry `invalid_client` in body (healthcheck string-matches this) | Long sandbox poll beyond TTL; inspect 401 + token-error bodies | sandbox |
| R14 | 429 `Retry-After` is numeric seconds (HTTP-date would parse to None) | Burst GETs on sandbox; capture a real 429 | sandbox |
| R15 | Error bodies: RFC 7807 + Spring mix; EMS code in free text; 409 duplicate-domain sometimes has `existingDomainId` | Sandbox: duplicate domain create, malformed CSR, bogus path | sandbox |
| R16 | Reports use 1-based `page`/`size` (max 100), short-page termination; no server-side domain/CN filter on /reports/orders → client-side `find_by_domain`. **Resolved 2026-08-07:** OpenAPI now documents `from`/`to` date params (YYYY-MM-DD, both inclusive, `to` expanded to end-of-day server-side); confirmed filtering correctly in sandbox and added as `since`/`until` on `get_list()`/`get_page()`/`_fetch_page()` (`orders.py`). No domain/CN filter still exists — `find_by_domain` workaround stands. **Also found while probing this:** the `status` param's OpenAPI enum only allows `issued`/`revoked`/`expired`/`cancelled`/`rejected`/`pending-approval` — the other 5 documented pending-`*` substates (`pending-dcv`, `pending-organization-verification`, `pending-csr`, `pending-documents`, `pending-agreement`) return HTTP 422 in sandbox, confirmed empirically. Not a `certinext` code issue (no code here passes those values), but `certinext-zabbix`'s daily `--order-health` job reportedly filters across all 6 pending-`*` values — flagged back to that workspace, not actioned here. | Check current OpenAPI for new filter params; verify page-size max + empty-page shape | both |
| R17 | `Domain.get(name)` iterates full list because exact `search` was untrusted | Same probe as R01; if exact-FQDN search reliable both envs, `get()` can switch to one filtered request | both |
| R18 | Expired DCV token: `get_dcv` returns empty token; same-method `change_dcv_method` mints fresh token + invalidates old artifact | Sandbox domain with lapsed token: get → change(same) → get → old TXT fails verify | sandbox |
| R19 | DCV verify is multi-perspective; PENDING until globally propagated | Sandbox verify pre- vs post-propagation; confirm `overallStatus`/`diagnostics.consensus` keys | sandbox |
| R20 | Org list vs detail field sets differ; `isPreVettingOrg` is string `"1"`/`"0"` | Diff corpus list-item keys vs detail keys | both |
| R21 | `preVettingToken`/`preVetted`, csr-in-create, `delegation`, `recipientEmails`, `tags` exist only in OpenAPI (absent from Postman docs); memory: token reportedly not applying to org 7956989 in prod | Sandbox OV order with/without token (auto-approve vs manual queue); confirm fields still in sandbox OpenAPI | sandbox |
| R22 | Healthcheck catch-order invariant: `CertiNextAPIError` subclasses `requests.HTTPError` (breaks in phase 2 — reclassification must be deliberate) | `pytest tests/test_healthcheck.py` + live runs (step 2) | both |
| R23 | Enum sets contested: `dcvStatus=EXPIRED` → 400 in sandbox; `domainStatus=DEACTIVATED` spec-absent (issue #6, vendor #135290) | Filter by each contested value per env; hold `DcvStatus`/`DomainStatus` edits until vendor answers | both |
| R24 | Release pipeline: sandbox outage reddens `integration-cert-issuance`; `needs: optional: true` semantics let GitLab release jobs skip while GitHub→PyPI publishes | Observe next tag pipeline; phase 6 must preserve job-name/needs semantics | n/a |

## Step 5 — Fix known-stale text (on `main`)

- `README.md:1025-1041` — rewrite the "#131869 /domains 422" outage narrative:
  it was a credentials/provisioning issue, resolved 2026-06-25 with new OAuth
  creds; do not carry the "vendor regression" framing forward.
- `.claude/skills/certinext-api-bugs/SKILL.md` — `search` description is
  outdated (current: exact-FQDN works, substring returns 0) and the
  fix-checklist names methods that don't exist (`list()`/`list_pending_dcv()`
  → `get_list()`/`get_pending_dcv()`). Update pagination section to describe
  the shipped sortBy paging.
- `certinext/pending_dcv_cli.py:79-80` — comment claims server-side
  filtering; it fetches all + filters client-side.
- `tests/test_issue_cert_output.py:178` — docstring references removed
  `pkcs7_out`.
- `docs/plans/dcv-inheritance-ga.md:39-44` — line-number links into
  `domains.py` have drifted; refresh or de-line-number them.
- Housekeeping: delete stale `build/`, `certinext.egg-info/`, old `dist/`
  artifacts and gitignore them; reconcile or delete stale `requirements.txt`
  (lists `python-dotenv`, omits `structlog`) in favor of `pyproject.toml`.

## Verification (phase gate)

- Pin-cap MR merged in ums-certinext-scripts; lock resolves to 0.3.x.
- Healthcheck green (exit 0) against prod and sandbox, outputs archived.
- `pytest -m probe` green both envs; corpus committed post-sanitization
  review; register outcomes recorded (GitLab issues updated/opened per
  ADR 0002, README/skill corrected).
- R02 and R08 contradictions resolved, where "resolved" means: probe
  outcome (either direction) commented on the relevant GitLab issue per
  ADR 0002 (R02 → issues #2/#6), AND the affected text corrected — R02:
  `get_pending_dcv()` docstring + `pending_dcv_cli.py` comment + README;
  R08: `DcvInfo` docstring + `examples/dns_txt_dcv.py` host fallback.
- `main` merged into `feat/pydantic-typer-refactor` afterward.

## Documentation expectations

README known-issues section, `certinext-api-bugs` skill, and GitLab issues
all reflect probe outcomes; capture/sanitization procedure documented in
`scripts/capture_corpus.py` docstring + a short `tests/fixtures/corpus/README.md`.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
