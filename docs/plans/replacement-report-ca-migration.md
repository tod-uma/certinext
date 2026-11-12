---
status: in-progress
depends-on: [replacement-report, replacement-report-cache]
implements-adr: [0021]
---

# Plan: replacement-report tracks the emSign → SSL.com DV migration

**Status:** in progress. Approved by Tod 2026-11-12. Phase 0 is done: !147 merged, v1.4.0rc6 released (GitLab,
GitHub and PyPI verified), and branch `feat/replacement-report-ca-migration` was cut with a bump to 1.4.0rc7.
**Phase 1 is done (2026-11-12)**; see the "Done" note under Phase 1 for what was pulled forward from Phases 2–3.
**Phase 2 is done (2026-11-12)**, including the Phase 3 CLI tests; see its "Done" note. The Codex external review
of Phases 1 and 2 was **processed on 2026-11-12**; see "External review" after Phase 3. **Phase 4 is done
(2026-11-12)**; see its "Done" note. **Next: Verification 3–5** (prod, read-only), then MR and the rc7 tag.
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
   - `possibly_replaced`: outstanding rows whose only replacement evidence is a CN match.
   - `outstanding`: needs replacing, with no `replaced_by` and not `superseded`. This is the work left to do.
     **Amended 2026-11-12 (external review, finding 1):** a CN-only match (`possibly_replaced_by`) no longer
     clears a row. It originally did. Without `--inspect`, an SSL.com cert with the same CN but fewer SANs then
     hid real work: prod's 87 CN-only matches dropped out of the headline and out of the `--outstanding` list.
     Only confirmed coverage removes work, so the count may over-state but never under-state.

   The text summary line leads with the outstanding count. Example: `443 EMSIGN certificates outstanding
   (31 possibly replaced; confirm with --inspect); 51 replaced; 494 of 552 valid certificates need replacing`.

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

8. **The inspection cache keeps entries for 30 days by default, and `--cache-max-age DAYS` overrides that**
   (Tod, 2026-11-12). `DEFAULT_MAX_AGE` in `certinext/_inspection_cache.py` goes from 7 to 30 days. The new
   flag implies `--cache`, exactly as `--refresh-cache`/`--cache-dir` do, and accepts 1 or more days. When the
   **chain** signal is active and the max age is over 7 days, the run logs a warning that a re-rooted chain
   may be shown stale, and that `--refresh-cache` gives a live answer.
   <details><summary>Why relax ADR 0019's 7-day bound</summary>

   - CertiNext is heavily overloaded (Tod, 2026-11-12). A cold `--inspect` run is about 20 minutes of
     per-certificate GETs, and with a 7-day bound every weekly migration check does one. Avoiding that load
     is the goal.
   - The 7-day bound guarded one risk: CertiNext changing a certificate's served **chain** without changing
     its serial (ADR 0019, "Consequences"). Under the new default criteria (Decision 1) the chain signal is
     off. The cache now feeds SANs (for `replaced_by`), key type and the orderer. Entries are keyed by order
     number and serial, so SANs and key can't change for an entry. Only the orderer name/email can go stale,
     and it doesn't affect the verdict.
   - The warning keeps the original risk visible for anyone who turns the chain signal back on (G3 mode).
   - Pruning follows the max age, so a single run with a short `--cache-max-age` deletes older entries that
     a later run could have reused. Accepted, and the help text says so.
   </details>

9. **Record it as ADR 0021**, "replacement-report defaults to the CA signal; replaced means covered by a
   passing cert". It amends ADR 0018's defaults section: add a "Superseded in part by 0021" note there rather
   than rewriting it. ADR 0021 also records Decision 8 (30-day cache default) and amends ADR 0019's
   "Bounded age" bullet and its 7-day "Consequences" item the same way. Use the `adr` skill.

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

> **Done 2026-11-12.** Implemented as above, plus these choices and pull-forwards:
>
> - `replaced_by` is set only on rows whose own verdict is **not** OK (an SSL.com cert covered by a newer
>   SSL.com cert isn't "replaced"). `mark_superseded()` now resets all flags first, so a second call is safe.
> - `ReportRow.outstanding` is a property and is also in `to_dict()` (`"outstanding"`), for the planned
>   certinext-zabbix follow-up. `breakdown()` keeps `outstanding`/`replaced` and drops `possibly_replaced`.
> - The catalog read lives in `_read_ca_map(sess, required=...)`; it catches `CertiNextAPIError` and
>   `httpx.HTTPError`.
> - **Pulled forward from Phase 3** to keep the suite green: the fake catalog route (`_catalog()`, wrapped in
>   `{"products": [...]}` because `_FakeApi` treats a bare list of dicts as a response queue), test `CRITERIA`
>   pinned to `cas=[]`, `G3_CONFIG`/`NO_CA_CONFIG` for the CLI tests, and all the library cases listed in
>   Phase 3 except the CLI JSON/CSV/summary ones.
> - **Pulled forward from Phase 2:** `_summary_line` no longer lists `ca` in its "not inspected; use --inspect"
>   hint (it printed on every default run). The rest of `_summary_line` is still Phase 2.
> - Known limit, as decided (Decision 5): without `--inspect`, an emSign cert and its newer emSign renewal are
>   only `possibly_superseded`, so both count as `outstanding`. The same now holds for an emSign cert with a
>   same-CN SSL.com cert (Decision 5 as amended). Run with `--inspect --cache` for accurate counts.

### Phase 2 — CLI (`certinext/cli/replacement_report.py`)

- Options: `--ca`, `--outstanding`, `--issued-since` (a `typer` `datetime` option, date-only format, read as
  UTC), `ca` added to the `--disable-signal` and `--group-by` choices.
- `_table_row` (lines 202-231): add `ca` and `replaced_by` columns. A CN-only match shows `maybe:<order>`,
  following the `superseded` `yes/maybe` convention.
- `_summary_line` (lines 234-267): lead with outstanding/replaced (Decision 5).
- `_config.replacement_criteria()` (lines 171-206): accept `cas` in the `[replacement]` table.
- Cache lifetime (Decision 8):
  - `certinext/_inspection_cache.py`: `DEFAULT_MAX_AGE = dt.timedelta(days=30)`.
  - `--cache-max-age DAYS` (`typer` int option, `min=1`), defaulting to `DEFAULT_MAX_AGE.days`. Add it to
    the implies-`--cache` set in the cache-mode resolver (lines ~120–145, beside `--refresh-cache`/
    `--cache-dir`, including the `--no-cache` conflict check and its error message). Pass
    `max_age=dt.timedelta(days=N)` where the CLI builds `InspectionCache` (line ~184).
  - The terminal prompt (line ~160) and `--cache` help (line ~343) currently interpolate `_MAX_AGE_DAYS`.
    Show the effective value, and state in the help that pruning uses it too.
  - Warn on stderr when `"chain" in criteria.active_signals()` and the max age is over 7 days (see the
    Decision 8 rationale for the wording).
- Regenerate the help golden `tests/goldens/help/replacement-report.txt`.

> **Done 2026-11-12.** Implemented as above, with these choices:
>
> - `--cache-max-age` defaults to `None`, not 30, so the CLI can tell it was given (it must imply `--cache`).
>   The help states the effective default. The terminal prompt only appears when it wasn't given, so it keeps
>   showing the default.
> - Summary line: `<outstanding> [<CAS>] certificates outstanding; <n> replaced (<m> unconfirmed without
>   --inspect | SANs unknown); [<k> superseded by newer certificates that also need replacing;] <needs> of
>   <valid> valid certificates need replacing`. CA names are the codes (`EMSIGN`), shown only when `ca` is the
>   sole active signal; there is no display-name map and adding one buys nothing. The "superseded" part
>   accounts for the rest of `needs_replacing` (emSign renewed as emSign), so the numbers add up.
>   `N conflicts to review` now appears only when more than one signal is active or a conflict occurred.
>   A conflict needs two signals, so with `ca` alone it always printed 0.
> - The chain-signal staleness warning fires only when the cache is in use; threshold `_CHAIN_SAFE_DAYS = 7`.
> - `--inspect` help now leads with "confirms replacements", its main use under the CA default.
> - `_config.replacement_criteria()` needed no code change: the table is validated whole through the model,
>   so `cas` already worked. Only its docstring example changed.
> - **Phase 3 CLI tests done in the same commit** (CA/`replaced_by` columns, JSON/CSV fields, summary line,
>   `--outstanding`, `--ca`, `--issued-since`, `--group-by ca`, cache max-age hit/miss/implies/conflicts, the
>   chain warning). The library cache-expiry test now derives its boundary from `DEFAULT_MAX_AGE`.
> - Open point for review: `cas` is `list[str]`, so `--ca SSL.COM` (a typo) is accepted and silently matches
>   nothing. `CertificateAuthority` (`models/domains.py:59`) could validate it; not done, Phase 1's type.
> - Verification 2 run against prod (read-only, no `--inspect`, 5.9 s): 558 valid, **494 EMSIGN all REPLACE**
>   (= the probe), 64 SSLCOM all OK (+6 since the probe), 0 UNKNOWN; 407 outstanding, 87 possibly replaced
>   (CN match), 255 possibly superseded.

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
  - Cache lifetime: the default is 30 days (an entry 20 days old is a hit). `--cache-max-age 3` makes it a
    miss, prunes it, and reports `max_age_days: 3` in the JSON `cache` block and "up to 3 days old" in the
    summary. `--cache-max-age` alone turns the cache on without prompting. `--no-cache --cache-max-age 3`
    exits 2. The chain-signal warning appears only when the chain signal is active and the max age is over 7.
    The existing cache tests live in `tests/test_replacement.py` (there is no separate cache test file).
    It, `certinext/_inspection_cache.py` and `README.md` contain hard-coded 7-day references; update each.
- Update existing tests that assumed the G3 defaults: give them explicit G3 criteria using the `ECC_G3_*`
  constants, rather than rewriting their expectations.

### External review (Codex, Phases 1 + 2) — processed 2026-11-12

Reviewed `17809e6`. Reviewer: self-reported GPT-6, in the Codex VS Code extension, 2026-11-12. The review files
are in gitignored `.review/` (`REVIEW-BRIEF-codex-ca-migration.md`, `REVIEW-codex-ca-migration.md`). All four
findings were re-derived at that commit and held up. Each commit carries an `External-review:` trailer.

1. **CN-only match cleared `outstanding`** (finding 1, real). Tod chose to change it: a CN-only match never
   clears a row. Decision 5 is amended above. `97bd013`.
2. **An OK coverer with the CA unevaluated counted as a replacement** (finding 2, real, needs several active
   signals). Fixed. Fixing it exposed a broader gap the review missed: `superseded` (CA-blind) also cleared the
   row when the newer cert was UNKNOWN/CONFLICT/OK-without-CA, and that happens under the default criteria
   too. New `ReportRow.renewed`: a supersede clears a row only when its newer coverer itself needs replacing.
   `--outstanding` no longer implies `--latest-only`. JSON/CSV gain `renewed`. `50774ed`.
3. **An empty catalog read wasn't fatal** (finding 3, real, and worse than the review said: the headline would
   have read "0 outstanding"). An empty catalog is now fatal under `ca` (`ValueError`, CLI exits 1). Unmapped
   product codes and `--ca` names the catalog doesn't know now get warnings, which settles the `--ca SSL.COM`
   open point. `71be5ca` (+ `125cb71` made the test order-independent).
4. **`--originator`/`--group` hide out-of-scope replacements** (finding 4, real, over-count only). Tod chose to
   document it and track it in an issue: help text + docstring in `0264d4c`; fix tracked in certinext **#40**.

For Phase 4: ADR 0021 must record Decision 5 as amended, `renewed`, and the output-shape additions (`ca`,
`replaced_by`, `replaced_by_ca`, `possibly_replaced_by`, `renewed`, `outstanding`, plus summary keys). The
review noted that only the criteria change was labelled breaking, so the tag changelog must list these too.
Verification 2's prod figures (407 outstanding) date from before finding 1. Expect about 494 without
`--inspect` now.

### Phase 4 — docs

- README CLI section (lines 939-1102): rewrite the intro around the CA migration; document the new flags,
  columns and summary; add a "Legacy: ECC G3 criteria" config example; and give a monitoring recipe:
  `certinext replacement-report --inspect --cache --outstanding --group-by originator` and
  `--json -o …` for tracking over time.
- README library section (lines 2092-2117): add `cas`, `replaced_by` and the new constants.
- README cache section: 30-day default, `--cache-max-age`, the pruning caveat, and the chain-signal caveat.
  Search the README and `llms.txt`/`AGENTS.md` for "7 days" and update every hit about the cache.
- ADR 0021, plus amendment notes on ADR 0018 (defaults) and ADR 0019 (cache age), and an index row.
- Changelog in the annotated tag message (feedback: tag messages carry the changelog). **BREAKING:** the
  default criteria are now `ca=EMSIGN`, and the issuer/key/chain defaults are empty. Also note the cache
  default moving from 7 to 30 days. Existing entries become valid for longer at once, since age comes from
  each entry's `fetched_at`.

> **Done 2026-11-12.** CI pipeline 55949 on `9fea4ad` was green first.
>
> - ADR 0021 written (options and outcome per Decisions 1–4, 5-as-amended, 8; `renewed`; the output-shape
>   additions listed as breaking). ADR 0018/0019 got 0011-style "superseded in part" notes; index rows updated.
> - README CLI section rewritten: CA-migration intro, `ca` signal row, a "Replaced, renewed and outstanding"
>   subsection, a "Legacy: ECC G3 criteria" recipe, new flags in the argument block, a 30-day cache section
>   (`--cache-max-age`, pruning and chain caveats), an "Output" subsection with columns, JSON/CSV fields and the
>   summary shape, and the monitoring recipe. `--outstanding` is documented as **not** implying `--latest-only`
>   (the review changed that; Decision 6's bullet is stale on this point).
> - README library section: `cas`, `select(outstanding=True)`, `replaced_by`, summary keys, `breakdown(..., "ca")`,
>   catalog failure exceptions, `issued_since=`, and the `ECC_G3_*`/`DEFAULT_*` constants. The example was run
>   against the code.
> - `llms.txt` and `AGENTS.md` had no "7 days" or replacement-report hits; nothing to change.
> - `--issued-since` filters before replacement matching like `--originator`/`--group`, but needs no caveat: a
>   replacement is always newer than the row it replaces, so it is never filtered out when that row is kept.
> - Tag changelog (rc7) must list as **BREAKING**: default criteria `ca=EMSIGN` with issuer/key/chain empty; new
>   row fields `ca`, `replaced_by`, `replaced_by_ca`, `possibly_replaced_by`, `renewed`, `outstanding`; summary
>   keys `outstanding`/`replaced`/`possibly_replaced`; table columns `ca`/`replaced_by`; the summary line's new
>   shape. Also: cache default 7 → 30 days, `--cache-max-age`, `--outstanding`, `--issued-since`, `--ca`, and
>   exit 1 on an empty catalog.

### External review (Codex, rc7) — processed 2026-11-12

Reviewed `9bd981a` (v1.4.0rc7). Reviewer: self-reported GPT-6.1, in the Codex VS Code extension, 2026-11-12.
The files are in gitignored `.review/` (`REVIEW-BRIEF-codex-rc7.md`, `REVIEW-codex-rc7.md`). Both findings were
re-derived at that commit. The review reported no Risk or Style findings.

1. **A coverer with unknown SANs could clear an inspected row** (finding 1, real in code, scenario
   implausible). `mark_superseded()` checked only the older row's `sans_known`. The review's counterexample needs
   a newer cert whose SANs omit its own CN, which CABF BR 7.1.4.3 forbids. Tod chose to fix it anyway: coverage
   is now confirmed only when both SAN sets are known, so the "never under-states" guarantee no longer depends on
   BR compliance. This also fixed a newer CN-only match beating a confirmed replacement in `replaced_by`.
   `344a804`.
2. **The `maybe` warning blamed `--latest-only` under `--outstanding` alone** (finding 2, real, message only).
   Fixed in the commit below.

**`--outstanding` summary (rc8, known before the review).** Tod chose the review's design: `--outstanding`
chooses only the listed rows; the summary/breakdown cover `population(latest_only, expiring_within)` and say so
("counts cover only certificates …", JSON `summary_scope`). `01beeec`.

## Verification

> **Prod load (Tod, 2026-11-12):** CertiNext is having load issues. **Every `--inspect` run passes `--cache`**
> (and keeps `--workers` at 4 or lower). Do a single cold run, then reuse the cache for every rerun (30-day
> max age once Phase 2 lands; 7 days before that). Never pass `--refresh-cache`, and never pass a small
> `--cache-max-age` against the production cache, because it prunes the entries and forces another cold run.
> Test `--cache-max-age` against a throwaway `--cache-dir` in the scratchpad. A run without `--inspect` reads only the paged orders
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
