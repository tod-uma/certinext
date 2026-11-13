---
status: accepted
date: 2026-11-12
---

# replacement-report defaults to the CA signal; "replaced" means covered by a passing certificate

## Context and problem statement

[ADR 0018](0018-classify-replacement-on-configurable-signals.md) built
`certinext replacement-report` for the October 2026 eMudhra **ECC G3** distrust:
its default signals matched the `OVG3C` issuer, EC keys, and the
`emSign ECC Root CA - G3` chain.

The problem grew. Apple distrusts the **emSign G1** root on 2026-11-30, and
Chrome and Firefox reject emSign certificates issued on or after 2026-11-16.
eMudhra is leaving issuance, so **every** emSign certificate is being replaced
with an SSL.com DV certificate (production's SSL.com products are DV only). The
report has to answer: *how many emSign certificates are still out there, which
ones, and which have already been replaced?*

It could not. It had no notion of CA. `superseded` was CA-blind (a newer emSign
certificate "superseded" an older one exactly as an SSL.com one would) and
recorded only a flag, never which order did it. A read-only production probe on
2026-11-12 found 494 valid emSign certificates and 58 SSL.com ones, and every
product code mapped to a CA through the catalog.

## Decision drivers

- The headline must never under-state the remaining work. Over-stating is
  acceptable; hiding work looks like progress.
- Nothing account-specific is hardcoded (the library is public), and the next
  CA move should need config, not code (carried over from 0018).
- CertiNext is overloaded (Tod, 2026-11-12), so repeat `--inspect` runs should
  not re-download every certificate each week.
- Existing G3 criteria must stay reachable.

## Considered options

Each question had a chosen option and the alternative(s) discussed:

1. **Default criteria.** (a) A new `ca` signal as the default, G3 lists empty;
   (b) `ca` as an opt-in flag, keeping the G3 defaults.
2. **Where the CA comes from.** (a) The product code only, through the catalog;
   (b) the product code with a fallback to the issuer name.
3. **Catalog read fails.** (a) Fail the report when `ca` is active; (b) degrade
   to a blank CA column and carry on.
4. **What "replaced" means.** (a) A new `replaced_by`: the newest covering
   certificate whose own verdict is `OK`, leaving `superseded` CA-blind;
   (b) make `superseded` itself CA-aware.
5. **Does a common-name-only match clear a row?** (a) No: only confirmed
   coverage removes work; (b) yes, as the plan first decided.
6. **Inspection-cache age.** (a) 30 days by default with `--cache-max-age`;
   (b) keep 0019's 7-day bound.

## Decision outcome

Chosen: **1a, 2a, 3a, 4a, 5a, 6a.**

- **CA signal (1a).** `ReplacementCriteria.cas` defaults to `["EMSIGN"]`, and
  `issuers`/`key_types`/`chain_cas` now default to **empty**. Out of the box,
  every valid emSign certificate needs replacing. `ca` is evaluated first and
  needs no download. It is settable through `--ca`, the `[replacement]` table's
  `cas` key, `--disable-signal ca`, and `--group-by ca`. The G3 values live on as
  `ECC_G3_ISSUERS`/`ECC_G3_KEY_TYPES`/`ECC_G3_CHAIN_CAS`; the old
  `DEFAULT_ISSUERS`/`DEFAULT_KEY_TYPES`/`DEFAULT_CHAIN_CAS` names stay exported as
  aliases of them (no longer defaults; removal at 2.0).
- **Product code only (2a).** An order whose code is unmapped, or maps to
  `UNKNOWN_CA`, leaves `ca` unevaluated; with only `ca` active its verdict is
  `unknown`. Unmapped codes and `--ca` names the catalog doesn't know log a
  warning.
- **Fail closed (3a).** With `ca` active, a failed catalog read raises
  `CertiNextAPIError`, and a catalog that lists no products raises `ValueError`
  (CLI exit 1). Without `ca` (G3 mode) a failure logs a warning and the CA column
  stays blank.
- **Replaced (4a).** `mark_superseded()` also records, on rows whose own verdict
  is not `OK`, the newest covering certificate that classifies `OK` (and, when
  `ca` is active, has its CA evaluated): `replaced_by` and `replaced_by_ca`. A match on common name alone
  (SANs unknown) sets `possibly_replaced_by` instead. `superseded` stays CA-blind
  and still drives `--latest-only`. A new `renewed` flag marks a row superseded
  by a newer certificate that itself needs replacing, which carries the work
  forward so it isn't counted twice.
- **Outstanding (5a).** A row is `outstanding` when it needs replacing and is
  neither `replaced_by` nor `renewed`. `possibly_replaced_by` and
  `possibly_superseded` never clear it. `summarize()` gains `outstanding`,
  `replaced` and `possibly_replaced`, and the summary line leads with the
  outstanding count. `--outstanding` lists only those rows.
- **30-day cache (6a).** `DEFAULT_MAX_AGE` is 30 days; `--cache-max-age DAYS`
  overrides it, implies `--cache`, and also sets the pruning age. When the
  `chain` signal is active and the age is over 7 days, the run warns that a
  re-rooted chain may be shown stale.
- **Also added:** `--issued-since DATE`, a generic filter (no hardcoded cutoff)
  that answers "which emSign certificates were issued after 2026-11-16?".

### Consequences

- Good: one default run answers the migration question, and a future CA move is
  `--ca`/`cas`, not code.
- Good: the outstanding count can over-state but never under-state. Without
  `--inspect`, the 87 production CN-only matches stay outstanding; run
  `--inspect --cache` to confirm them.
- **Bad (breaking, 1.4 pre-release):** the default output changes. Default
  criteria are now `ca=EMSIGN` with the issuer/key/chain lists empty. JSON/CSV
  rows gain `ca`, `replaced_by`, `replaced_by_ca`, `possibly_replaced_by`,
  `renewed` and `outstanding`; the summary gains `outstanding`, `replaced` and
  `possibly_replaced`; the table gains `ca` and `replaced_by` columns. The tag
  changelog lists all of it, not only the criteria change.
- Bad: the report now needs the product catalog when `ca` is active, one more
  endpoint that can fail it.
- Bad (fixed in 1.4.0rc10, certinext #40): `--originator`/`--group` hid
  replacements placed outside the filter, so their predecessors stayed
  outstanding (over-count only; 13 of 100 portal rows in production on
  2026-11-13). The filters now choose listed rows after matching; under
  `--inspect`, an out-of-scope certificate is inspected only if it is newer
  than a listed certificate that carries its common name.
- Bad: with the 30-day bound, a re-rooted chain can be shown stale for up to 30
  days if someone turns the chain signal back on. The warning names
  `--refresh-cache`. A short `--cache-max-age` also prunes entries a later run
  could have reused; the help says so.
- Neutral: existing cache entries become valid for longer at once, since age
  comes from each entry's `fetched_at`.

### Confirmation

`tests/test_replacement.py` covers the `ca` verdicts, explicit G3 criteria,
catalog failure and empty catalog, `replaced_by`/`possibly_replaced_by`/
`renewed` (including newest-wins and an unevaluated-CA coverer), the
`outstanding` counts and filter, `--issued-since`, the CLI JSON/CSV fields and
summary line, and the cache max-age rules. Production verification steps are in
[the plan](../plans/replacement-report-ca-migration.md). An external review
(self-reported GPT-6, Codex VS Code extension, 2026-11-12) found the issues behind
5a, the unevaluated-CA coverer, the empty-catalog case, and the scoped-filter
limit; all were fixed or documented.

## Pros and cons of the options

### 1b. `ca` as an opt-in flag

- Good, because the G3 default output wouldn't change.
- Bad, because G3 certificates are a strict subset of the emSign exit, so the G3
  defaults were obsolete, and every run would need three signals disabled.

### 2b. Fall back to the issuer name

- Bad, because emSign issues from InCommon-branded intermediates and SSL.com
  ones are expected later, so the name can't identify the CA.
- Bad, because the probe found 0 unmapped codes: it would buy nothing today and
  mislabel certificates later.

### 3b. Degrade on catalog failure

- Bad, because 494 `replace` rows silently turning `unknown` looks like
  progress.

### 4b. CA-aware `superseded`

- Bad, because `--latest-only` relies on it: an old emSign certificate renewed
  as emSign must not be counted twice.
- Neutral: tying "replaced" to the verdict instead keeps it CA-agnostic and
  gives G3 mode the right answer (a newer G3 certificate is not a replacement).

### 5b. A CN-only match clears the row

- Good, because the headline would read lower without `--inspect`.
- Bad, because an SSL.com certificate with the same CN but fewer SANs hid real
  work: 87 production rows left the headline and the `--outstanding` list.

### 6b. Keep 7 days

- Good, because 0019's served-chain staleness risk stays bounded at a week.
- Bad, because a cold `--inspect` is about 20 minutes of per-certificate GETs
  against an overloaded API, every week. Under the new default the chain signal
  is off, and the cached data that feeds the verdict (SANs, key) can't change
  for a given order number and serial.

## More information

- [MADR](https://adr.github.io/madr/): the format this record follows.
- [Typer `datetime` parameters](https://typer.tiangolo.com/tutorial/parameter-types/datetime/):
  `--issued-since`.
- [Pydantic validators](https://docs.pydantic.dev/latest/concepts/validators/):
  upper-casing `cas`.
- [CertiNext OpenAPI spec](https://us-api.certinext.io/v3/api-docs/certinext-v2):
  the catalog products endpoint the CA map comes from.
- Amends [0018](0018-classify-replacement-on-configurable-signals.md) (default
  criteria) and [0019](0019-command-local-opt-in-inspection-cache.md) (7-day
  age bound). Related: [0020](0020-multi-ca-domains-fail-closed-and-opt-in-create-recovery.md)
  (multi-CA branching), [the plan](../plans/replacement-report-ca-migration.md),
  certinext #40.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre; the decisions it
> records were made in earlier sessions on 2026-11-12. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before
> relying on them.
