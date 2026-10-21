---
status: in-progress
depends-on: []
implements-adr: []
---

# Plan: `certinext replacement-report` — find valid certs that chain to a distrusted root

**Status:** in progress: Phases 0–1 done 2026-10-21; Phase 2 on branch `feat/replacement-report`.
This repo copy supersedes the private plan-mode draft it was moved from.

## Context

Mozilla removed **`emSign ECC Root CA - G3`** from NSS on 2026-10-20 (bug 2083449, the eMudhra
ECC key compromise), and Chrome is removing it too. Every certificate whose chain runs through that
root is now untrusted by updated clients. For our CertiNext certificates that means ECDSA leaves
issued by **`InCommon Intermediate CA - OVG3C`**. RSA leaves from **OVG2C** chain to
`emSign Root CA - G1` and are unaffected.

The ACME proxy's certificates are already tracked in Splunk ("Certificate Key Migration": 87 ECC /
20 RSA on 2026-10-21). That proxy log never sees **portal and API orders**, such as long-lived
appliance certs. CertiNext's own records are the only inventory that covers those. This command
lists every currently valid certificate that still needs replacing. It shows its origin, and the
replacement criteria can be configured, because CertiNext may re-root ECC issuance onto G1. After
that, key type alone would give the wrong answer.

Constraints: read-only against production (no reissue, revoke or modify). The repo publishes to
GitHub and PyPI, so **no real hostnames, order IDs, group numbers or CNs** go in code, tests,
fixtures, docs or commits. Use `host.example.edu` and `ORDER-XXXXX`. Nothing account-specific (such
as "group N is our ACME proxy") is hardcoded. Follow typer/pydantic/structlog patterns, give every
class and method a docstring, and keep logic in a library module with a thin CLI body
(IDEA-001/002).

## Findings (live prod, read-only, 2026-10-21; healthcheck 14 PASS / 1 SKIPPED)

| Signal | Where | Cost | Result |
|---|---|---|---|
| Issuer CN | orders report `issuerCA` (already on every row, **unmodelled**) | free | `InCommon Intermediate CA - OVG3C` / `- OVG2C` |
| Key type/size | leaf from `GET /ssl-certificates/{id}/certificate`, parsed locally | 1–2 calls/order | 8/8 sample agreed: OVG3C→EC P-384, OVG2C→RSA-2048/3072 |
| Chain CAs | same download, `chainPem` (**a list** in live data) | same | OVG3C chain ends at `emSign ECC Root CA - G3`; OVG2C ends at `emSign Root CA - G1` |
| Origin | report `originator` | free | `ACME` / `CERTInext` (portal) / `CERTInext API` |
| Group | report `groupNumber` | free | ACME orders span 3 groups; one holds all the ≤45-day certs |

- **No API field gives the key algorithm.** The OpenAPI spec types every response as a bare
  `object`. The CLM endpoint `GET /api/v3/certinext/reports/certificates` has `filterKeyAlgorithm`
  and `filterIssuer`, but our API account gets back only `{"status":"success"}`, and
  `GET /api/v3/certinext/orders` returns **403** (missing permission). → Classify locally.
- **Valid** = `status=issued` (the spec says this excludes revoked/expired/cancelled/pending)
  **and** `certificateExpiryDate > now`. Prod has 574 issued, 573 valid; 297 of the valid are OVG3C
  (213 ACME, 82 portal, 2 API).
- **Superseded copies inflate the counts.** 324 valid certs have a newer valid cert with the same
  CN, mostly ACME renewals that were never revoked. Newest-per-CN ACME certs expiring within 31 days
  come to **86 OVG3C / 21 RSA**, which **reconciles with Splunk's 87 / 20.**
- The `certinext-api-bugs` skill covers only `/domains`. The quirks that matter here, from code and
  probes: report termination must use `totalPages`, report dates are offset-less UTC, PKCS#7
  download returns 406, and a download straight after issuance can return 422.

### Portal "Manage Orders" export vs the API

An xlsx export from the web UI, taken 2026-10-20 and inspected locally (aggregates only), has
**no key-type column either**. Every other column it carries is reachable through the API:

- Issuer, Originator, both statuses, Expires On, CN, Org and Tags are orders-report fields.
- Group *name* comes from `groupNumber` → `accounts.list_groups`. The proxy's group has a
  self-describing name in our account, so showing names makes it obvious without hardcoding.
- Product is a name in the export but only `productCode` in the API.
- Ordered By / Requestor come from the per-order `GET /ssl-certificates/{id}` (`orderedBy`,
  `requestor`). That is the useful "who do I chase" field for portal certs.
- The export also contains Expired/Revoked rows. Our `status=issued` already excludes those.

### Spec-watch drift (2026-10-21)

Prod and sandbox both show **SUBSTANTIVE** drift against the 2026-09-22 snapshot:
- The CLM module moved from `/api/v2/certinext/*` to `/api/v3/certinext/*` (+276 / −223 ops) and
  gained `cas`, `keys/reports` and `orders/{id}`.
- The library's surface, `/api/certinext/v2/*`, lost no operations. The only changes are
  operationId renames, plus the **SSL revoke request schema `RevokeRequest` → `SslRevokeRequest`**.
  Triaged in Phase 1.

## Decisions

**1. Classify on configurable signals: issuer, key type, chain CA.** A cert is `REPLACE` when
it is valid and **every evaluated signal matches**. If the evaluated signals disagree, its
verdict is `CONFLICT`: it is listed and flagged, and counted **separately from the headline**
("N need replacing; M conflicts to review"). One signal is never silently preferred over
another.

<details><summary>Why conflicts are not in the headline (decided after the live --inspect run)</summary>

The full prod inspection found 19 EC-key certificates issued by **OVG2C**, which chain to the
trusted `emSign Root CA - G1`. All were ordered between 2026-05-29 and 2026-07-14, so this is
not a re-root; CertiNext has always issued some EC keys through the RSA-rooted intermediate.
Counting them as "need replacing" made the headline 316 against a true 297. The user chose a
separate count and kept all three default signals, since the conflicts are useful information:
a key-type-only view such as the Splunk dashboard would wrongly count them as unmigrated.
</details>

<details><summary>Why three signals, and why "chain"</summary>

- Issuer is free and exact today, but it is a proxy for the real question.
- Key type is what the brief names, and it breaks the moment CertiNext re-roots ECC onto G1 (a new
  EC cert would be fine).
- Chain CA *is* the real question ("would it chain to the distrusted root?"), and the served
  `chainPem` contains the root. It survives a re-root without config changes, and it generalises to
  any future distrust event.
- A `CONFLICT` verdict is exactly the signal that a re-root has happened, so it must be visible
  rather than resolved by picking a winner.
</details>

**2. Issuer-only by default; `--inspect` downloads and parses each leaf and chain.** Without
`--inspect`, the key-type and chain signals are reported as *not evaluated*: the columns show `—`
and the summary says so. Disagreement detection therefore needs `--inspect`, and the help text says
that plainly.

<details><summary>Why (user decision)</summary>
About 573 downloads take several minutes. The free issuer signal answers today's question
instantly, and `--inspect` is the audit pass.
</details>

**3. Superseded certs are shown and marked, not hidden.** A `superseded` column marks a valid cert
whose name set is covered by a newer valid cert. The name set is the SANs when inspected, otherwise
the CN. `--latest-only` collapses the list.

<details><summary>Why (user decision)</summary>
A portal cert reused on several appliances under one CN is still deployed. Hiding older copies by
default could hide a live risk.
</details>

**4. Origin is the vendor's `originator`, not a hardcoded mapping.** The command shows
`originator` and the group *name* (from `accounts.list_groups`). `--group-by originator|group|issuer`
prints a breakdown that lets any site identify its own automated or proxy groups from the data (for
example, the group whose ACME certs are all short-lived). No group numbers are hardcoded or
documented.

<details><summary>Why (user decision)</summary>
The tool is public. Our proxy's group means nothing to another institution, while `originator` is
vendor-defined and universal.
</details>

**5. Criteria come from built-in defaults, then a `[replacement]` table in `config.toml`, then CLI
flags.** Each signal's list is *replaced*, not merged, by the higher layer, and
`--disable-signal NAME` turns a signal off.

```toml
[replacement]
issuers   = ["InCommon Intermediate CA - OVG3C"]   # leaf issuer CN, case-insensitive exact match
key_types = ["EC"]                                  # EC | RSA | Ed25519 | Ed448 | DSA
chain_cas = ["emSign ECC Root CA - G3"]             # any CA CN in the served chain
```

<details><summary>Why a top-level table, and why replace rather than merge</summary>

- `[defaults]` and `[profiles.X]` warn `unknown key` for anything outside
  `CONFIG_KEYS`/`CONNECTION_KEYS` (`_config.py:226-230`), and `save_defaults` rejects other keys.
  `_sections` ignores other top-level tables, so `[replacement]` needs no change to that machinery.
- Replacing a list makes an override predictable: `--issuer X` means "exactly X", which is how
  spec-watch's `--modern-prefix` already behaves.
- An invalid `[replacement]` table exits 2 rather than falling back to the defaults, in the spirit of
  ADR 0017 (fail closed).
</details>

**6. No new dependency.** `cryptography` is already in the `csr` extra and imported lazily
(`_chain.py:233-240`). Only `--inspect` needs it. Without it, `--inspect` exits 1 with the same
"install `certinext[csr]`" message that `issue-cert` gives.

## Phase 0: Pre-flight release state — done 2026-10-21

Every workspace repo is on a clean `main`, identical to GitLab `main`. No repo has an open MR.
**Nothing needs tagging or pushing before this work starts.**

| Repo | Version | Last tag | Unreleased on `main` |
|---|---|---|---|
| certinext | 1.3.0rc3 (bumped, **untagged**) | v1.3.0rc2 | hook fix + 2 wishlist docs only |
| nm | 1.2.0a2 | v1.2.0a2 | hook fix only |
| ums-certinext-scripts | 0.4.0rc3 | v0.4.0rc3 | hook fix only |
| certinext-zabbix | 0.1.0rc11 (bumped, **untagged**) | v0.1.0rc10 | wishlist docs only |
| certinext-spec-watch | 0.1.0a1 | none | none |

- **certinext:** don't tag rc3 now. Nothing user-facing has landed since rc2, so rc3 should carry
  this feature. `/start-work` must therefore **keep** `1.3.0rc3` rather than bump again. The
  alternative is `1.4.0a1` if this is treated as a new minor; that's decided at `/start-work`.
- **Loose ends, not blocking:**
  - Remote branch `release/0.3.x` (certinext): a maintenance line, leave it.
  - Remote branch `docs/publish-spec-watch-tooling-plan` (spec-snapshots): unmerged, no MR, one
    plan doc from 2026-08-25. The work it planned has shipped. Decide whether to archive the doc
    on `main` or delete the branch.

## Phase 1: Spec refresh and drift triage — done 2026-10-21

**Outcome:** the refreshed snapshots merged in `certinext-spec-snapshots` (MR !5).

- `reports/orders`, `ssl-certificates/{orderId}` and `/certificate` are byte-identical in the old
  and new snapshots, so the new tool's dependencies are stable.
- The revoke schema rename only dropped `privilege-withdrawn`. Triage also found that
  `RevocationReason` has **always** been camelCase against a kebab-case spec enum, for both
  revoke and reissue. That is filed as **#34** and left for later by explicit decision: it is
  latent, nothing passes a reason, and this tool never revokes.
- Nothing in the library keys on operationIds.

Original steps, for the record:

1. In `certinext-spec-snapshots`, start a branch and run spec-watch **with** writes (prod +
   sandbox). Commit the new snapshots with a summary of the drift.
2. Triage each drift item against the certinext library:
   - **SSL revoke body schema `RevokeRequest` → `SslRevokeRequest`:** diff the two schemas.
     If required fields or enum values changed, `ssl.revoke()` is affected, so fix or open an
     issue *before* the new tool.
   - operationId renames on `/domains` and revoke: cosmetic. Confirm nothing keys on them.
   - The CLM `/api/v2/certinext/*` → `/api/v3/certinext/*` migration: the library doesn't use it.
     Record it, plus our account's 403 / empty-payload result on `v3/orders` and
     `v3/reports/certificates`.
   - Re-check that `GET /reports/orders` and `GET /ssl-certificates/{id}/certificate` params and
     descriptions are unchanged, since the new tool depends on both.
3. Gate: Phase 2 starts only when triage finds no library-breaking change, or once any such change
   is fixed or filed with an explicit decision to proceed.

## Phase 2: Implementation

Branch `feat/replacement-report`, version kept at `1.3.0rc3` (user decision; rc3 is untagged and
nothing user-facing landed since rc2). The first commit is this plan.

1. **Model the report fields** in `certinext/models/orders.py` `OrderRecord`: `issuer_ca`
   (`issuerCA`), `certificate_serial_number`, `group_number`. These are corpus-validated (ADR 0005),
   so extend `tests/test_corpus_models.py`.
2. **Library module `certinext/replacement.py`:**
   - `ReplacementCriteria` (pydantic): `issuers`, `key_types`, `chain_cas` (eMudhra values by
     default) plus `disabled`. It also gets `from_config(doc)` and `with_overrides(...)`.
   - `CertificateFacts`: order number, CN, SANs, key type/size, issuer, chain CA CNs, valid-to,
     order date, originator, group number and name, product code, serial, and `ordered_by` (only
     when inspected).
   - `inspect_download(download) -> (key_type, key_size, sans, issuer_cn, chain_cas)`. It reuses
     `split_pem_certificates` (`_chain.py:56`), handles `chain_pem` as a str **or a list**, and
     lazy-imports `cryptography`.
   - `classify(facts, criteria) -> Verdict` with `REPLACE` / `OK` / `CONFLICT`, plus
     `matched_signals` and `evaluated_signals`.
   - `mark_superseded(facts_list)`.
   - `build_report(sess, criteria, *, inspect, originators, groups, progress) -> ReplacementReport`
     returns rows and summary counts: valid, needs-replacing, conflict, not-inspected, errors, and an
     optional group-by breakdown. It calls `sess.orders.get_list(status="issued")`, filters on
     expiry > now, and for `--inspect` fetches the download with `sess.ssl.get(n).download_certificate()`
     (or a direct accessor if one exists).
   - Per-order failures, including 429 after one `retry_after` wait, are recorded on the row as
     errors and don't abort the run.
3. **Config:** add `replacement_criteria()` to `certinext/_config.py`. It reads `[replacement]`
   through `load_config()` (`:123`) and validates with the pydantic model; a bad table exits 2.
4. **CLI `certinext/cli/replacement_report.py`**, registered in `certinext/cli/__init__.py:35-47`:
   - Signal options: `--inspect`, `--all` (include `OK` rows to measure progress), `--latest-only`.
   - Filters: `--originator` (repeatable), `--group` (name or number, repeatable),
     `--expiring-within DAYS`, `--group-by originator|group|issuer`.
   - Criteria overrides: `--issuer` / `--key-type` / `--chain-ca` (repeatable, replace config),
     `--disable-signal`.
   - Output: `--csv`. The global `--json` already exists.
   - Columns: verdict, CN, SANs, key, issuer, valid-to (soonest first), days left, order, origin,
     group name, superseded.
   - With `--inspect`, also show `ordered_by` (name). That data comes from the `ssl.get` call
     already being made, so it costs nothing extra. Emails appear only in JSON/CSV.
   - Table output uses `data_console()` + `rows_table` (`cli/_shared.py:175,190`), followed by the
     summary line: *"N of M valid certificates need replacing (C conflicts; key/chain not inspected)"*.
   - JSON output is `{"criteria":…, "summary":…, "certificates":[…]}`.
   - CSV goes to stdout through the stdlib `csv` module (the repo has no CSV yet), with the summary
     sent to stderr.
   - Progress for `--inspect` goes to stderr via `progress_disabled`.
   - Exit codes: 0 on success, 1 if any per-order inspection failed (report incomplete), 2 on
     usage or config error.
5. **Tests** (no real data), using synthetic certs built with `cryptography`'s EC/RSA keygen and
   placeholder CA CNs (the pattern in `tests/test_chain_order.py`):
   - `classify`: all agree, a re-root `CONFLICT` (EC leaf on a G1 chain), disabled signals, and
     not-evaluated signals.
   - Criteria layering: default → config → CLI, and a bad config exits 2.
   - `mark_superseded`, by CN and by SANs.
   - `chain_pem` as both a list and a str.
   - CLI JSON/CSV goldens through the `_FakeApi` + `run_json` fixture
     (`tests/test_cli_json_goldens.py:139,166`).
   - Help golden (`tests/test_cli_help_snapshots.py:32`).
   - An optional `probe`-marked live test asserting that report rows carry `issuerCA` and
     `originator`.
6. **Docs:**
   - README CLI section after `list-certificates` (`README.md:856`): purpose, criteria config,
     examples, and the "issuer-only unless `--inspect`" caveat.
   - README library section: `OrderRecord` property table (`:1710`) plus `certinext.replacement`.
   - Docstrings everywhere and a CHANGELOG entry if the repo keeps one.
   - Suggest an ADR, "classify replacement need on configurable issuer/key/chain signals", since the
     pattern outlives this incident.

## External review (GPT-6 Sol Light, Codex VS Code extension, 2026-10-21)

Pre-merge review of `d7aefbd`, briefed for false negatives (the brief and raw findings are in the
git-excluded `.review/`). All six findings held up against the source. Fixed on this branch:

- **B1 — issued rows missing an order number or expiry were dropped silently.** They are now
  logged, listed in `ReplacementReport.incomplete` (and `--json`), and make the run exit 1.
  Production showed 574 issued and 573 valid, so this is probably zero rows today (not verified).
- **B2 — an empty `chainPem` evaluated the chain signal as *False*,** which turned an affected
  certificate into `conflict` and dropped it from the headline count. An empty chain now leaves
  the signal unevaluated and records a row error.
- **B3 — a malformed download aborted the whole run** (pydantic `ValidationError` escaped the
  per-row handler). The review missed a second path: `ssl.get()` raises a plain `ValueError` on a
  non-dict response. Both are now row errors. One sub-claim was wrong: a non-string `chainPem`
  member does *not* always raise, because numbers are coerced to strings.
- **B4 — `--latest-only` could hide a certificate whose SANs were unknown** (CN-only fallback).
  `superseded` now needs known SANs. A CN-only match sets `possibly_superseded` instead (shown as
  `maybe`), which `--latest-only` keeps, with a warning on stderr.
- **R2 — a failed group lookup emptied a `--group <name>` filter and still exited 0.** The brief had
  called this fallback cosmetic, which was wrong for filtering. With a group filter, the lookup
  error is now raised.
- README "one report read" corrected (it omitted the group-list GET).
- Also found while fixing: `x509.DuplicateExtension` is not a `ValueError`, so it could escape
  `inspect_download`. It is now converted.

<details>
<summary>Why B4 keeps CN-only matches instead of hiding them</summary>

A common name alone can hide extra SANs the newer certificate lacks, and hiding a valid affected
certificate is the false negative this command exists to prevent. The cost: `--latest-only` only
fully works with `--inspect`, so the Splunk reconciliation above now needs it. The `maybe` flag and
the stderr warning keep the CN signal visible instead of discarding it.
</details>

**R1 is closed by evidence (no code change).** The concern: `status=issued` is the only check that
a certificate is still valid, and order status is independent of certificate status. The
2026-10-20 Manage Orders export (963 orders, aggregates only) shows no certificate with a future
expiry in a state the filter could miss:

| Expires on | Order status (portal) | Certificate status (portal) | Rows |
|---|---|---|---|
| future | Order Fulfilled | Certificate Downloaded | 300 |
| future | Order Accepted | Certificate Generated | 250 |
| future | Order Fulfilled | Certificate Generated | 16 |
| future | Order Fulfilled | Certificate Revoked | 3 |
| past | Order Fulfilled / Accepted | Certificate Expired | 276 |
| past | Order Fulfilled | Certificate Downloaded | 1 |
| none | Auto Save / Accepted / Cancelled | Pending, Approved, or Rejected | 117 |

- The 566 future, non-revoked rows match the API's 573 valid the next morning; the gap fits
  ACME issuance overnight. API `issued` must therefore include the portal's "Order Accepted +
  Certificate Generated" (250 rows), or it would count about 316.
- The one expired "Downloaded" row matches the API's 574 issued minus 573 valid.
- Every row with no expiry is pre-issuance or cancelled, so B1 likely finds nothing in
  production today.
- All 31 reissue-suffixed orders, and the one original they came from, are expired or cancelled.
  No currently valid certificate comes from a reissue, so the reissue question (#27) doesn't
  affect this report today.

This is a count reconciliation across one day, not a row-by-row join against the API.

## Follow-ups (separate work, not this branch)

- **#34:** fix revoke/reissue reason casing.
- **Recorded 2026-10-21:** the decision is now [ADR 0018](../adr/0018-classify-replacement-on-configurable-signals.md).
  The two items below are parked as wishlist ideas
  ([IDEA-014](../wishlist/IDEA-014-clm-certificate-report-access.md),
  [IDEA-015](../wishlist/IDEA-015-list-certificates-status-values.md)), so as not to bother
  the vendor mid-incident.
- **Vendor question:** ask whether the API account can get CLM `reports/certificates` / `v3/orders`
  permission, which would give a server-side key-algorithm filter.
- **Existing bug:** `list-certificates --status` help advertises `pending-dcv`/`pending-csr`, which
  return 422. File an issue.

## Verification results (2026-10-21, read-only prod)

- Tests: 984 passed, 13 skipped. ruff, mypy and pyright are clean.
- Default (issuer only): **297 of 573** need replacing. By originator: ACME 213, portal 82,
  API 2, matching the planning probe exactly.
- `--originator ACME --latest-only --expiring-within 31 --all --group-by issuer`:
  **86 OVG3C / 21 OVG2C**, against Splunk's 87 / 20.
- `--inspect`, across all 573 certificates:
  - 0 errors.
  - The leaf issuer equals the report's `issuerCA` on 573/573.
  - Chains end at `emSign ECC Root CA - G3` for 297 and `emSign Root CA - G1` for 276.
  - Every OVG3C leaf is EC.
  - **19 conflicts**, all EC keys under OVG2C (see Decision 1).
  - `ordered_by` and SANs are populated on every row.
- `--group-by group` resolves group names; the short-lived ACME group stands out without
  hardcoding.

## Verification

1. Run `uv run pytest`, `ruff check`, and `mypy certinext`. Don't run `ruff format` on this repo.
2. `certinext healthcheck`, then these **read-only prod** runs:
   - `certinext replacement-report`: OVG3C needs-replacing roughly 297 of 573 valid (expect drift
     since 2026-10-21).
   - `certinext replacement-report --inspect`: expect **0 CONFLICT**, with key and issuer agreeing on
     every row.
   - `certinext replacement-report --originator ACME --inspect --latest-only --expiring-within 31 --all --group-by issuer`:
     should land near Splunk's ECC/RSA split (86/21 vs 87/20 at planning time). This needs
     `--inspect` since the external review (B4): without SANs, CN matches are only `maybe` and are kept.
   - `--originator CERTInext --originator "CERTInext API"`: the portal/API gap list the proxy log
     can't see.
   - `--group-by group`: confirm that the short-lived ACME group stands out with no hardcoding.
   - Cross-check totals per issuer and originator against a fresh portal "Manage Orders" export,
     filtered to Downloaded/Generated status.
   - Override check: `--issuer "InCommon Intermediate CA - OVG2C" --disable-signal key --disable-signal chain`
     flips the verdicts as expected.
   - `--json | python -m json.tool` and `--csv` parse cleanly, and stdout holds no log lines.
3. Scan the diff for real CNs, order numbers or group numbers before every commit.

## References

- Mozilla bug 2083449 — <https://bugzilla.mozilla.org/show_bug.cgi?id=2083449>
- typer — <https://typer.tiangolo.com/> · pydantic — <https://docs.pydantic.dev/latest/> ·
  structlog — <https://www.structlog.org/> · rich tables — <https://rich.readthedocs.io/en/stable/tables.html>
- cryptography X.509 — <https://cryptography.io/en/latest/x509/reference/> (public key types:
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/>)
- Python `csv` — <https://docs.python.org/3/library/csv.html> · `tomllib` — <https://docs.python.org/3/library/tomllib.html>
- certbot fleet response: sysadmin-ansible `tower-projects/docs/adr/0009-certbot-issues-rsa-keys-during-emudhra-ecc-distrust.md`
