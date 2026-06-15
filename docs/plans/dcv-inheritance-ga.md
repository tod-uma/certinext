---
status: planned
depends-on: []
implements-adr: []
---

# Plan: Support CertiNext DCV Inheritance (GA) in the certinext library

**Status:** proposed (draft — awaiting approval; Phase 0 reconnaissance gates the rest)
**Scope:** this repo only (the `certinext` Python library and its CLIs).
**Companion plan:** `ums-certinext-scripts` has a dependent plan
(`docs/plans/dcv-inheritance-ga.md` in that repo) that consumes the
`Domain.verification_type` property added here. **That plan depends on this one being
implemented and released first.**
**Date drafted:** 2026-06-15

---

## Goal and context

On 2026-06-15 CertiNext announced that **DCV Inheritance is now generally available** in
Sandbox and Production:

- Inheritance is **enabled by default**; **qualifying subdomains** automatically inherit DCV
  from a validated parent, and CertiNext generates/stores the attestation automatically.
- A **new "Verification Type" column** appears in the Domains list. Observed portal values:
  `Auto-verified (Inherited)`, `Verified Independently`, and `-` (for `Pending` domains).
- Primary Admins can **disable inheritance account-wide** or **exclude individual subdomains**
  (forcing independent validation).
- Inheritance does **not** bypass issuance controls — CertiNext still evaluates TXT/CAA/CNAME/
  DNSSEC before issuance.

### Why this library must change

This library already contains a **client-side predictive model of DCV inheritance**, built
*before* the feature was official, from an InCommon cert-users mailing-list discussion dated
**2026-06-01**:

- `Domain.dcv_covering_parent()` ([certinext/domains.py:297-355](../../certinext/domains.py#L297-L355))
  walks the domain tree for a registered ancestor and uses `_has_ns_records()`
  ([certinext/domains.py:102-126](../../certinext/domains.py#L102-L126)) to assume propagation
  **stops at DNS zone boundaries** (a subdomain with its own NS records is treated as *not*
  inheriting).
- `filter_needs_dcv()` ([certinext/domains.py:522-556](../../certinext/domains.py#L522-L556))
  removes domains a parent covers. It is exported from `__init__.py` and consumed by the
  scripts repo.

GA changes the ground truth in ways the heuristic does not model: the API now reports an
**authoritative Verification Type**, and **admin exclusion** means a subdomain with a
registered parent may still require direct validation.

### The central open question

> **Does the NS zone-boundary assumption still hold under GA, and what is the real JSON field
> name + value set for "Verification Type"?**

An adversarial review of the heuristic returned **"broken" at low confidence** — i.e. it
cannot be confirmed from the repo or vendor materials alone. The vendor's **"Domain Management
Guide" PDF predates GA** (its documented Domains list has columns Domain Name / Organization /
DCV Method / DCV Status / Domain Status / Created By — **no Verification Type**), so it does
**not** resolve the field name. **Only the live API can.** Hence Phase 0 gates everything.

<details>
<summary>Adversarial review — evidence for / against the assumption</summary>

**Still plausibly holds:** NS records define DNS zone boundaries by design; UMD/LSU admins
observationally confirmed NS-delegated subdomains never inherited; the GA email says
inheritance still evaluates DNS signals.

**Plausibly broken:** the email never mentions NS/zone boundaries; the API now reports the
answer authoritatively (heuristic redundant once a parent is verified); admin exclusion makes
inheritance non-deterministic from DNS alone; the mailing-list source was pre-GA and anecdotal.

**Recommended synthesis (D2):** prefer the authoritative API field when populated; keep the
NS heuristic only as a *predictor for the window before a parent is verified*. Confirm
empirically in Phase 0.
</details>

## Constraints

- **Phase 0 is gating.** Do not hard-code a guessed JSON field name or value set.
- **Production is the immediate recon target.** GA inheritance is enabled by default and the
  production portal already shows `Auto-verified (Inherited)` values, so the field is live now.
  Recon is **read-only** (`get_list` / `get` / `refresh`), so it is safe to run against
  production. The earlier sandbox `/domains` listing outage (reported 2026-06-10) was
  **resolved 2026-06-11**, so sandbox is usable too — but previously-validated sandbox domains
  will not show inherited status until the **backfill support ticket** ("Sandbox DCV
  Inheritance Request") is processed.
- Coordinate with the **pydantic migration** (a tracked TODO to move `Domain` from raw dict +
  property to a pydantic model) so the new field is modelled once, not twice.
- This repo's release tag message is the source of truth for GitLab release notes; curate a
  changelog in the annotated tag (see the `certinext-release` skill).

## Decisions (with rationale)

### D1 — Expose Verification Type as a first-class `Domain` property
Add `Domain.verification_type` (reads the Phase-0-confirmed field), a `VerificationType`
`Literal` next to `DcvStatus`, export it from `__init__.py`, and add a `verification_type`
column to `to_row()`.
<details><summary>Why a property + Literal, not the raw dict?</summary>
Every other field (`dcvStatus`, `status`, `validTill`) is a typed read-only property and the
portal surfaces this as a first-class column; callers will filter/report on it. Burying it in
`as_dict()` breaks the pattern. The `Literal` documents the contract like `DcvStatus` does.
</details>

### D2 — Prefer the authoritative field; keep the NS heuristic only as a pre-verification predictor
Do **not** delete `dcv_covering_parent` / `filter_needs_dcv` / `_has_ns_records`. When a
covering parent is `VERIFIED`, trust `verification_type`; fall back to the NS heuristic only
when the parent is still `PENDING` (the API cannot yet report inheritance).
<details><summary>Why keep the heuristic at all?</summary>
The API can only report inheritance *after* a parent verifies. Consumers (the scripts repo)
run while parents are still pending and need to predict which subdomains to skip. Deleting the
heuristic would regress that. But once a parent *is* verified, the API is ground truth and the
heuristic must not override it. Final shape confirmed by Phase 0.
</details>

### D3 (library half) — Expose any admin-exclusion signal the API provides
If Phase 0 shows the API exposes a per-subdomain "excluded from inheritance" flag, expose it as
a `Domain` property so consumers can avoid silently skipping a subdomain that genuinely needs
direct DCV. If the API does not expose it, document the gap. *(Using this signal in the
work-queue filter lives in the scripts plan.)*

### D4 — Mark the mailing-list rationale as historical, not authoritative
Reword the `dcv_covering_parent` docstring
([certinext/domains.py:319-331](../../certinext/domains.py#L319-L331)) and the README so the
2026-06-01 mailing-list source reads as historical pre-GA context, with the API's Verification
Type as the source of truth and the NS check as a pre-verification fallback.

## Phases

> **Dependency:** Phase 0 gates all others; Phase 1 before Phase 2; Phases 3–4 finish the repo.

### Phase 0 — Live API reconnaissance (GATING)

Use existing read-only calls against **Production** (sandbox `/domains` is down) to capture a
**list** response (`sess.domain.get_list()`) and a **detail** response (`domain.refresh()`)
for one domain of each verification type. Portal candidates: `cm-unet1.its.maine.edu`
(inherited), `maineren.net` (independent), `uma.edu`/`umaine.edu` (pending).

Record into a findings note + a sanitized fixture, answering:
1. exact **JSON field name** for Verification Type (ranked guesses: `verificationType`,
   `verification_type`, `dcvType`, `verificationSource`, `inheritedFrom`);
2. exact **value strings** (and whether portal labels wrap different internal codes);
3. whether **`dcvStatus` flips to `VERIFIED`** for inherited domains (screenshot shows
   inherited rows as `Validated`, implying yes — confirm);
4. the field value for **`Pending`** domains (`null` / absent / `"-"`);
5. whether the field is on the **list** endpoint, the **detail** endpoint, or both;
6. whether an **`inheritedFrom`/parent-name** field exists;
7. whether **account-level disable** or **per-subdomain exclusion** is queryable (drives D3);
8. whether a real **NS-delegated subdomain** with a verified parent reports `Inherited` or
   `Independent` (drives D2);
9. what value **un-backfilled sandbox** domains show (handle `null` gracefully).

**Verification:** the note answers all nine with evidence quoted from real responses; a
sanitized list+detail fixture pair is saved for Phase 3.

### Phase 1 — Domain model (`certinext/domains.py`, `certinext/__init__.py`)

Implements D1, D2, D3-library-half, D4.

- Add `VerificationType` `Literal` near `DcvStatus`
  ([certinext/domains.py:29-37](../../certinext/domains.py#L29-L37)); export it from
  `__init__.py` ([certinext/__init__.py:53-62](../../certinext/__init__.py#L53-L62) and
  `__all__`).
- Add `Domain.verification_type` reading the confirmed field; return `None` for absent/`null`
  (Pending and un-backfilled sandbox domains).
- Add `verification_type` to `Domain.to_row()`
  ([certinext/domains.py:361-373](../../certinext/domains.py#L361-L373)).
- Reconcile the heuristic per **D2** in `dcv_covering_parent` / `filter_needs_dcv`; reword
  docstrings per **D4**. If Phase 0 found an exclusion signal, add a property (D3) and have
  `filter_needs_dcv` keep excluded subdomains.
- Re-evaluate `needs_dcv` ([certinext/domains.py:273-275](../../certinext/domains.py#L273-L275))
  and `get_pending_dcv` ([certinext/domains.py:648-669](../../certinext/domains.py#L648-L669)):
  - if Phase 0 confirms inherited domains flip to `VERIFIED`, no logic change — add a
    clarifying docstring only;
  - if they stay `PENDING`, add `needs_independent_dcv`
    (`needs_dcv and verification_type != Inherited`) and migrate consumers to it.

**Verification:** `pytest`, `mypy`, and `pyright` clean; the new property returns the right
value for the Phase-0 fixture rows; `to_row()` emits the new column.

### Phase 2 — CLIs

- `certinext/parent_dcv_status_cli.py`
  ([:15-24](../../certinext/parent_dcv_status_cli.py#L15-L24),
  [:197-214](../../certinext/parent_dcv_status_cli.py#L197-L214)): its premise is the NS
  heuristic. Reword docstring/`--help` per **D4**; add `verification_type` to `_build_row()`;
  make its "needs direct DCV" set use the reconciled Phase-1 logic.
- `certinext/pending_dcv_cli.py` and `certinext/domains_cli.py`: no code change — they render
  via `to_row()` and inherit the new column. **Verify** it renders; add a docstring note to
  `pending_dcv` that inherited domains drop out once their parent verifies.
- `certinext/domain_cert_count_cli.py`: no change (orthogonal to DCV).

**Verification:** run each CLI against Production (read-only) and the Phase-0 fixture; confirm
the column renders and `parent-dcv-status` matches the API's verification types.

### Phase 3 — Tests

- **Fixtures are inline in `tests/conftest.py`** (`SAMPLE_DOMAIN_DATA`, `SAMPLE_DOMAIN_DATA_2`,
  `SAMPLE_DOMAIN_DETAIL_DATA`, [tests/conftest.py:38-79](../../tests/conftest.py#L38-L79)) —
  **there is no `domains_list.json`**. Add `Inherited` and `Independent` examples carrying the
  new field from Phase 0.
- **Close the existing coverage gap:** `dcv_covering_parent`, `filter_needs_dcv`, and
  `_has_ns_records` currently have **zero tests**. Add unit tests (mock NS via `check_ns`)
  covering: account-level parent, covered subdomain, zone-boundary subdomain, and — per
  D2/D3 — verified-parent-prefers-API and (if applicable) admin-excluded subdomain.

**Verification:** `pytest` green; new tests fail if the reconciliation logic regresses.

### Phase 4 — Docs, changelog, release

- **README:** update the `certinext-parent-dcv-status` section (~L858-893), the
  "List domains needing DCV" section, and the `dns_txt_dcv` example section so Verification
  Type is the source of truth and the NS rule is a pre-GA/predictor fallback.
- **`examples/dns_txt_dcv.py`:** note in the module docstring + `--include-subdomains` help
  that GA may make manual TXT publishing unnecessary for `Inherited` domains.
- **`certinext-api-bugs` skill:** no change unless Phase 0 reveals a new bug (e.g. filtering by
  the new field hits the known `domainStatus`+`dcvStatus` 400). If GA also fixed the `search`
  bug, follow that skill's "when fixed, update" checklist.
- **Release:** bump `pyproject.toml`, curate a changelog in the annotated tag message
  (`certinext-release` skill), and release **before** the scripts repo can depend on the new
  property. Confirm the separate sandbox `/domains` outage does not block a production-only
  feature release.

## Documentation expectations (definition of done)
- New/changed public symbols (`VerificationType`, `Domain.verification_type`, any
  `needs_independent_dcv`, any exclusion property) have docstrings per the repo's docstring rule.
- README + example reflect GA semantics.
- Consider an ADR for **D2** (API-authoritative, NS-fallback) since future work will follow it.
- Commit messages pull the relevant D1–D4 rationale into their bodies.

## Open questions (resolve in Phase 0 unless noted)
1. Exact JSON field name for Verification Type.
2. Exact value strings; do portal labels wrap internal codes?
3. Does `dcvStatus` flip to `VERIFIED` for inherited domains? (screenshot implies yes)
4. Verification Type value for `Pending` domains.
5. List endpoint, detail endpoint, or both?
6. Is there an `inheritedFrom`/parent-name field?
7. Is account-level disable / per-subdomain exclusion queryable? (drives D3)
8. Does a real NS-delegated subdomain with a verified parent report `Inherited`? (drives D2)
9. Value shown by un-backfilled sandbox domains.
10. **External:** official CertiNext API doc URL for this field — the "Domain Management Guide"
    PDF predates GA and does not cover it; await the vendor KB and link when published.

## References
- CertiNext DCV Inheritance announcement — vendor email, 2026-06-15.
- "CERTInext — InCommon: Adding and Validating a Domain" PDF (pre-GA; no Verification Type).
- InCommon cert support: <https://incommon.org/certificates/support-for-certificates/>
- CertiNext support portal / KB: <https://incommonsupport.certinext.io/portal/en/home>
- CertiNext API schema for Verification Type — **URL unknown; await KB.**
- dnspython (NS lookups): <https://dnspython.readthedocs.io/>
- tabulate: <https://pypi.org/project/tabulate/>
- structlog: <https://www.structlog.org/>
- pytest: <https://docs.pytest.org/>
