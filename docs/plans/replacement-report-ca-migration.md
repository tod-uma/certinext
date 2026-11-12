---
status: in-progress
depends-on: [replacement-report, replacement-report-cache]
implements-adr: [0021]
---

# Plan: replacement-report tracks the emSign → SSL.com DV migration

**Status:** in progress. Approved by Tod 2026-11-12. Phase 0 is done: !147 merged, v1.4.0rc6 released (GitLab,
GitHub and PyPI verified), and branch `feat/replacement-report-ca-migration` was cut with a bump to 1.4.0rc7.
This file supersedes the plan-mode draft (moved from `~/.claude/plans/`).

## Context

`certinext replacement-report` (ADR 0018/0019; archived plans `docs/plans/archive/replacement-report*.md`) was
built for the October 2026 eMudhra **ECC G3** distrust. By default it flags valid certs whose issuer is
`InCommon Intermediate CA - OVG3C`, whose key is EC, and whose chain contains `emSign ECC Root CA - G3`.

The problem is bigger now. Apple distrusts the **emSign G1** root on **2026-11-30**, and Chrome/Firefox reject
emSign certs issued on or after **2026-11-16**. eMudhra is leaving the issuance business, so **every** emSign
cert is being replaced with an **SSL.com DV** cert (prod SSL.com is DV-only, codes 1011–1014). The report has
to become the tool that answers: *how many emSign certs are still out there, which ones, who owns them, and
which have already been replaced?*

The report has no notion of CA today. `product_code` is carried through but never mapped. `mark_superseded()`
doesn't look at CA (a newer emSign cert "supersedes" an older one exactly as an SSL.com cert would), and it
records only a flag, never *which* order did the superseding.

### Findings (prod, read-only probe 2026-11-12)

Valid issued orders grouped by CA (through `catalog.ca_by_product_code()`):

| CA | Count | Detail |
| --- | --- | --- |
| EMSIGN | **494** | All OV codes (848, 823, 846, 849, 847, 835). By originator: 257 ACME, 222 portal, 13 API |
| SSLCOM | 58 | 1013 (UCC), 1011, 1012. By originator: 52 ACME, 4 portal, 2 API |
| unmapped | **0** | Every product code maps to a CA |

- The product-code join alone labels every order. No issuer heuristic is needed, and none should be used,
  because emSign issues from InCommon-branded intermediates and SSL.com may later too (`certinext-api-bugs`
  skill).
- SSL.com issuer names seen: `SSL.com TLS Issuing RSA CA R1`, `SSL.com TLS Issuing ECC CA R2`.
- Every emSign cert is OV, so every replacement is OV → DV. That's expected; Tod confirmed DV is the
  replacement.

## Decisions

1. **A new `ca` signal, and it becomes the default.** `ReplacementCriteria` gains `cas: list[str]`
   (default `["EMSIGN"]`). The issuer, key and chain lists **default to empty**, so they're off unless config
   or flags set them. Out of the box the report means: *every valid emSign cert needs replacing.*
   <details><summary>Why make CA the default instead of an opt-in flag (Tod, 2026-11-12)</summary>

   G3 certs are a strict subset of the emSign exit, so the G3 defaults are obsolete. An opt-in flag would
   mean disabling three signals on every run. The old criteria stay reachable through `--issuer/--key-type/
   --chain-ca` or the `[replacement]` config table. This changes the default output, which is acceptable in a
   1.4 pre-release; it goes in the tag changelog.
   </details>

2. **The CA comes from the product code only**, through `CatalogAccessor.ca_by_product_code()`
   (`certinext/catalog.py:84`). An order whose code is unmapped, or maps to `UNKNOWN_CA`, leaves `ca` unevaluated,
   so with only the `ca` signal active its verdict is `UNKNOWN`.
   <details><summary>Why not fall back to the issuer name</summary>

   emSign issues from InCommon-branded intermediates (`OVG2C`/`OVG3C`), and InCommon-branded SSL.com
   intermediates are expected later, so the issuer name can't identify the CA. The probe found 0 unmapped
   codes, so the fallback would buy nothing today and mislabel certs later.
   </details>

3. **If the catalog can't be read, the report fails when the `ca` signal is active.** It raises
   `CertiNextAPIError` exactly as an orders-report failure does. When `ca` isn't active (G3 mode), it logs a
   warning and leaves the CA column blank, which matches `list_certificates._ca_map()`.
   <details><summary>Why fail instead of degrading</summary>

   A monitoring report that silently turns 494 REPLACE rows into UNKNOWN looks like progress. Failing loudly
   is safer.
   </details>

4. **"Replaced" means covered by a newer cert that itself passes the criteria** (verdict `OK`). Under the
   default criteria that is exactly "a newer SSL.com cert". New `ReportRow` fields: `replaced_by` (the
   covering order number, newest first), `replaced_by_ca`, and `possibly_replaced_by` for a match on CN alone
   (SANs unknown without `--inspect`). This mirrors `superseded`/`possibly_superseded`.
   <details><summary>Why tie it to the verdict, and keep `superseded` unchanged (Tod chose "only a newer SSL.com cert")</summary>

   - Tying it to the verdict keeps the logic CA-agnostic. It also gives G3 mode the right answer for free (a
     newer G3 cert doesn't count as a replacement), and it works for any future CA move.
   - `superseded` (any newer cert, CA-blind) still drives `--latest-only` de-duplication. An old emSign cert
     superseded by a newer *emSign* cert shouldn't be counted twice, since its newer sibling carries the
     work. Changing `superseded` would break that.
   </details>

5. **Migration counts in the summary.** `summarize()` adds:
   - `replaced`: needs replacing and has `replaced_by`.
   - `possibly_replaced`.
   - `outstanding`: needs replacing, with no `replaced_by`, `possibly_replaced_by` or `superseded`. This is
     the work left to do.

   The text summary line leads with the outstanding count. Example: `412 emSign certificates outstanding;
   82 replaced (31 unconfirmed without --inspect); 0 unknown`.

6. **New CLI controls, all in the existing style:**
   - `--ca CA` (repeatable). It replaces `cas`, the same way `--issuer` replaces `issuers`.
   - `ca` added to `--disable-signal` and `--group-by`.
   - `--outstanding`, which shows only outstanding rows (the actionable list). It implies the `--latest-only`
     filtering.
   - `--issued-since DATE`, which keeps orders with `order_date >= DATE`. Example:
     `--issued-since 2026-11-16` lists emSign certs issued after the Chrome/Firefox cutoff, which are untrusted
     from day one. These usually come from ACME clients still on an emSign account.
   - Table columns `ca` and `replaced_by`. JSON/CSV gain `ca`, `replaced_by`, `replaced_by_ca` and
     `possibly_replaced_by`.
   <details><summary>Why `--issued-since` instead of a hard-coded cutoff</summary>

   A date baked into the library goes stale and is specific to one CA. A generic filter answers the same
   question and still works for the next distrust.
   </details>

7. **Library constants:** add `ECC_G3_ISSUERS`, `ECC_G3_KEY_TYPES`, `ECC_G3_CHAIN_CAS` and
   `DEFAULT_CAS = ("EMSIGN",)`. `DEFAULT_ISSUERS`/`DEFAULT_KEY_TYPES`/`DEFAULT_CHAIN_CAS` stay exported as
   aliases of the `ECC_G3_*` names, with a docstring saying they are no longer defaults (removal at 2.0).
   README shows the G3 recipe as a `[replacement]` config example.

8. **Record it as ADR 0021**, "replacement-report defaults to the CA signal; replaced means covered by a
   passing cert". It amends ADR 0018's defaults section: add a "Superseded in part by 0021" note there rather
   than rewriting it. Use the `adr` skill.

## Implementation

### Phase 0 — prerequisites

1. Merge the open `docs/sslcom-ov-product-code` branch (1.4.0rc6) with the `mr` skill, then tag rc6
   (`certinext-release`). The new branch then starts from a clean `main`.
2. `/start-work` on certinext with branch `feat/replacement-report-ca-migration`, bumping to **1.4.0rc7**
   (bump `pyproject.toml` and run `uv lock` together; see the `version-scheme` skill). Move this plan into
   `docs/plans/`.

### Phase 1 — library (`certinext/replacement.py`)

- `Signal`/`SIGNALS` gain `"ca"`, evaluated **first** (cheapest, no inspection needed).
- `ReplacementCriteria`: add `cas`, set the issuer/key/chain defaults to empty, add `cas=` to
  `with_overrides()` and `active_signals()`. Upper-case the CA names in a `field_validator` (constants in
  `certinext/models/domains.py:71-78`: `EMSIGN`, `SSLCOM`, `UNKNOWN_CA`).
- `CertificateFacts.ca: str | None`, set in `_facts_from_record()` from a `ca_map` argument.
- `classify()`: when `"ca"` is active and `facts.ca` is set and not `UNKNOWN_CA`, evaluate
  `facts.ca in criteria.cas`.
- `ReportRow`: add `replaced_by`, `replaced_by_ca`, `possibly_replaced_by`, and include them in `to_dict()`.
- `mark_superseded()` (line 784) keeps today's flags and also finds the **newest** covering row whose
  `classification.verdict is Verdict.OK`, recording its order number and CA. This runs after classification,
  which `build_report()` already does (`rows = [...classify...]` precedes `mark_superseded(rows)`).
  Considered a separate `mark_replaced()`, but it would rebuild the same name index, so it's one pass.
- `build_report()`: read the catalog once before building facts (Decision 3 governs failure). Add the
  `issued_since` filter beside `originators`/`groups`.
- `summarize()`: add `replaced`, `possibly_replaced` and `outstanding`. `breakdown()` accepts
  `group_by="ca"`. `population()`/`select()` gain an `outstanding` option.
- Constants and `__all__` per Decision 7. Every new or changed function gets a full docstring.

### Phase 2 — CLI (`certinext/cli/replacement_report.py`)

- Options: `--ca`, `--outstanding`, `--issued-since` (a `typer` `datetime` option, date-only format, read as
  UTC), `ca` added to the `--disable-signal` and `--group-by` choices.
- `_table_row` (lines 202-231): add `ca` and `replaced_by` columns. A CN-only match shows `maybe:<order>`,
  following the `superseded` `yes/maybe` convention.
- `_summary_line` (lines 234-267): lead with outstanding/replaced (Decision 5).
- `_config.replacement_criteria()` (lines 171-206): accept `cas` in the `[replacement]` table.
- Regenerate the help golden `tests/goldens/help/replacement-report.txt`.

### Phase 3 — tests (`tests/test_replacement.py`)

- `_FakeApi`/`_routes()` (lines 417-519): add a route for `/api/certinext/v2/catalog/products` that maps the
  fixture codes (the default `productCode "100"` → EMSIGN, plus an SSL.com code). Otherwise every
  `build_report` test fails with `unexpected GET`.
- New cases:
  - `ca`-signal classification: EMSIGN → REPLACE, SSLCOM → OK, unmapped → UNKNOWN.
  - G3 criteria still work when set explicitly.
  - Catalog failure raises when `ca` is active, and warns when it isn't.
  - `replaced_by`: an emSign cert covered by a newer SSL.com cert is replaced. Covered by a newer emSign
    cert, it is superseded but not replaced. A CN-only match gives `possibly_replaced_by`. With two SSL.com
    coverers, the newest wins.
  - `outstanding` counts and the filter.
  - `--issued-since`.
  - CLI JSON/CSV fields and the summary line.
- Update existing tests that assumed the G3 defaults: give them explicit G3 criteria using the `ECC_G3_*`
  constants, rather than rewriting their expectations.

### Phase 4 — docs

- README CLI section (lines 939-1102): rewrite the intro around the CA migration; document the new flags,
  columns and summary; add a "Legacy: ECC G3 criteria" config example; and give a monitoring recipe:
  `certinext replacement-report --inspect --cache --outstanding --group-by originator` and
  `--json -o …` for tracking over time.
- README library section (lines 2092-2117): add `cas`, `replaced_by` and the new constants.
- ADR 0021, plus an amendment note on ADR 0018 and an index row.
- Changelog in the annotated tag message (feedback: tag messages carry the changelog). **BREAKING:** the
  default criteria are now `ca=EMSIGN`, and the issuer/key/chain defaults are empty.

## Verification

> **Prod load (Tod, 2026-11-12):** CertiNext is having load issues. **Every `--inspect` run passes `--cache`**
> (and keeps `--workers` at 4 or lower). Do a single cold run, then reuse the cache (7-day max age) for every
> rerun. Never pass `--refresh-cache` during verification. A run without `--inspect` reads only the paged orders
> report, the catalog and the groups, so it needs no cache.

1. Gates: `uv run --extra dev pytest`, `ruff check`, `mypy certinext`, `pyright`. **Don't run `ruff format`**
   on this repo (61-file churn). Help-golden snapshot test passes after regeneration.
2. Prod, read-only, no `--inspect` (fast):
   `uv run --extra keyring certinext replacement-report --all --group-by ca --json -o <scratchpad>/r.json`.
   Expected: about 494 EMSIGN rows with verdict REPLACE and about 58 SSLCOM rows with verdict OK (both drift
   as work proceeds); 0 UNKNOWN; JSON totals match the probe.
3. Prod with `--inspect --cache --workers 4` (about 20 min cold, under 1 min warm): `replaced` should be
   non-zero (at least the ACME SSL.com renewals). Pick 2–3 `replaced_by` pairs and confirm by hand that the
   SSL.com cert's SANs cover the emSign cert's.
4. `--issued-since 2026-11-16 --ca EMSIGN` lists any emSign certs issued after the cutoff. Before 11-16 it
   should show only certs from the last few days; check that the count is plausible.
5. G3 regression: `--issuer "InCommon Intermediate CA - OVG3C" --key-type EC --chain-ca "emSign ECC Root CA - G3"
   --disable-signal ca` reproduces the old verdict counts.
6. Don't commit real report output. The repo mirrors to public GitHub; put JSON/CSV in the scratchpad or
   `~/Downloads`.

## Follow-ups (not in this plan)

- A certinext-zabbix item for the `outstanding` count, so progress shows on the dashboard.
- Revoking emSign certs once replaced (`replaced_by` set). That's a separate decision: needs Tod's call, and
  is a write.
- Vendor #187868: SSL.com OV in prod (currently DV-only).

## References

- Typer options and `datetime` parameters: <https://typer.tiangolo.com/tutorial/parameter-types/datetime/>
- Pydantic validators: <https://docs.pydantic.dev/latest/concepts/validators/>
- CertiNext OpenAPI spec (canonical, per the `certinext-api-bugs` skill): `https://us-api.certinext.io/v3/api-docs/certinext-v2`
- In-repo: ADR 0018, ADR 0019, ADR 0020 (multi-CA), `docs/plans/archive/replacement-report.md`
