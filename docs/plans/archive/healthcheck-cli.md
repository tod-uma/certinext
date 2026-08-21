---
status: planned
implements-adr: []
---

# Plan: `certinext-healthcheck` — read-only API health & coverage probe

## Goal

Ship a read-only CLI that exercises (nearly) every CertiNext **read** endpoint the
`certinext` library exposes, classifies each result, and prints a scannable report of
what works and what doesn't for the credentials it was given.

Two motivating problems:

1. **Vendor inconsistency.** The CertiNext API changes behaviour that affects some orgs
   and environments but not others (the cert-users mailing list is full of this), and
   changes drift over time. We need a fast, repeatable way to answer "what should work
   with our library right now, against this account?" — and, with run history, "what
   changed since last time?"
2. **RBAC readiness (future).** When fine-grained API keys arrive, the same probe answers
   "does this key have access to exactly what it should — no more, no less?" The v1
   classification is designed so this falls out cheaply later (a 401/403 *is* the
   permission-denied signal).

Non-goal for v1: any mutation. The probe must be provably safe to run against production —
it only ever issues GETs.

## Context & constraints

- **Lives in the `certinext` library** as `certinext/healthcheck_cli.py`, registered as
  `certinext-healthcheck` in `[project.scripts]`. Rationale below.
- **House style, no new dependencies.** `argparse` + `structlog` + `tabulate` (all already
  present), `--json` for machine output, data→stdout / diagnostics→stderr — matching
  [`pending_dcv_cli.py`](../../certinext/pending_dcv_cli.py) and
  [`parent_dcv_status_cli.py`](../../certinext/parent_dcv_status_cli.py). No `rich`, no
  Textual (see rejected alternatives).
- **Reuse the shared `_cli.py` helpers** — do not hand-roll connection/credential/logging
  plumbing. They already exist: `add_connection_args`, `apply_sandbox`, `build_session`,
  `_setup_logging`, `fatal_api_error`.
- Python floor is 3.10 (matches the rest of the library).

<details>
<summary>Why the certinext library, not ums-certinext-scripts?</summary>

The probe tests the library's *own* API surface, every `_cli` helper it needs already
lives in `certinext/_cli.py`, and it sits naturally next to the existing read-only CLIs
(`certinext-pending-dcv`, `certinext-parent-dcv-status`, `certinext-domain-cert-count`).
Shipping it with the library means it's public/`uv`-installable and shareable with other
CertiNext consumers (e.g. people hitting the same issues on the cert-users list), rather
than pinned behind the internal GitLab PyPI index that `ums-certinext-scripts` uses.

`ums-certinext-scripts` was considered and is the right home for *UMS-specific* later
layers — an RBAC expectation matrix encoding UMS site policy, or a future `nm` adapter —
because those don't belong in a single-vendor library. Decision: core probe in the
library; UMS-specific harness in scripts if/when needed.
</details>

<details>
<summary>Why argparse + tabulate, and why not Textual or rich?</summary>

- **Textual (rejected):** the probe is print-and-exit — its output must be greppable,
  pipeable, and cron-friendly. A TUI forces an event loop and a foreground interactive
  app and breaks redirection entirely. It would only make sense as a *separate* future
  "endpoint explorer" command, never as the probe.
- **rich (rejected for now):** would give coloured PASS/FAIL but adds a dependency and
  diverges from every other CLI in the repo. The user chose to stay consistent with the
  existing argparse/structlog/tabulate scripts. Revisit only if a human-facing colour
  report becomes a real need.
- **tabulate (chosen):** already a hard dependency, pipes cleanly, matches house style.
</details>

## Endpoint registry (what gets probed)

Two tiers. **Tier 1** needs no input and runs always. **Tier 2** needs an ID derived from
a Tier-1 result; if the input isn't available it is reported `SKIPPED`, never `FAIL`.
Source of truth for signatures: the resource modules in [`certinext/`](../../certinext/).

### Tier 1 — no input

| Probe | Call | Endpoint |
|---|---|---|
| `accounts.me` | `sess.accounts.me()` | `GET /auth/me` — auth canary |
| `accounts.list_groups` | `sess.accounts.list_groups()` | `GET /groups` |
| `accounts.list_organizations` | `sess.accounts.list_organizations()` | `GET /organizations` |
| `catalog.list_products` | `sess.catalog.list_products()` | `GET /catalog/products` |
| `domain.get_list` | `sess.domain.get_list()` | `GET /domains` — **baseline count source; currently 422 in prod** |
| `ledger.get_page` | `sess.ledger.get_page(page=1)` | `GET /reports/ledger` |
| `orders.get_page` | `sess.orders.get_page(page=1)` | `GET /reports/orders` |

### Tier 2 — derived input (skipped if input unavailable)

| Probe | Input from | Call | Endpoint |
|---|---|---|---|
| `accounts.get_organization` | `list_organizations[0].organization_number` | `sess.accounts.get_organization(id)` | `GET /organizations/{id}` |
| `catalog.get_custom_fields` | `list_products[…].product_code` | `sess.catalog.get_custom_fields(code)` | `GET /catalog/products/{code}/custom-fields` |
| `domain.get` (by id) | `get_list[0].id` | `sess.domain.get(id)` | `GET /domains/{id}` |
| `domain.get_dcv` | a `Domain` | `domain.get_dcv()` | `GET /domains/{id}/dcv` |
| `domain.last_dcv_attempt` | a `Domain` | `domain.last_dcv_attempt()` | `GET /domains/{id}/dcv/attempts/last` |
| `domain.dcv_attempt_history` | a `Domain` | `domain.dcv_attempt_history()` | `GET /domains/{id}/dcv/attempts` |
| `ssl.get` | an **issued** `OrderRecord.order_number` from `orders` | `sess.ssl.get(order_id)` | `GET /ssl-certificates/{id}` |
| `ssl.download_certificate` | an issued `SslOrder` | `order.download_certificate()` | `GET /ssl-certificates/{id}/certificate` |

> **Gotcha — silent lazy fetch:** `Organization` objects from `list_organizations` fire a
> hidden `GET /organizations/{id}` (swallowing all exceptions) the first time a detail-only
> property or `as_dict()` is touched. The probe must read only `organization_number` off the
> list results, and test the detail path explicitly via `get_organization` so failures are
> visible, not swallowed.

### Mutating methods the probe must NEVER call

`DomainAccessor.create/deactivate`, `Domain.deactivate/verify/change_dcv_method/reinitiate_dcv`,
all `SslAccessor.create_*`, `SslOrder.verify_dcv/submit_csr/accept_agreement/cancel/reject/revoke/reissue`,
`OrderWorkflow.submit_csr/verify_dcv/advance/poll/run`. (`OrderWorkflow.from_order_id`,
`.download`, `.download_chain` are read-only and safe.) Enforce by construction: the probe
registry only ever references the read calls above.

## Result classification

Every probe yields one `ProbeResult` with an `outcome` from this set. Classification leans
on the library's typed exceptions, which carry `.status_code`, `.body`, `.ems_code`,
`.field_errors` (see [`exceptions.py`](../../certinext/exceptions.py) and
[`tests/test_error_handling.py`](../../tests/test_error_handling.py)).

| Outcome | Trigger | Exit-affecting? |
|---|---|---|
| `PASS` | 2xx, non-empty (or empty-and-expected) | no |
| `EMPTY` | 2xx but empty where a baseline says it shouldn't be (suspect) | `--strict` only |
| `DENIED` | `CertiNextAPIError.status_code` ∈ {401, 403}; or token `RuntimeError` whose message contains 401/403/`invalid_client` | yes |
| `NOT_FOUND` | `status_code == 404` (note: 404 can also be a *soft* RBAC denial — see RBAC phase) | yes |
| `SERVER_BUG` | `status_code == 422` or 5xx — **capture the raw RFC7807 body verbatim** | yes |
| `RATE_LIMITED` | `status_code == 429` (`CertiNextRateLimitError.retry_after`) | no (retry/skip) |
| `NETWORK` | `requests` `ConnectionError`/`Timeout`/`RequestException` (no HTTP response) | yes |
| `SKIPPED` | Tier-2 input unavailable | no |

<details>
<summary>Classification gotchas (these are the bug-shaped edge cases)</summary>

- **Catch order matters.** `CertiNextAPIError` subclasses `requests.HTTPError`, so catch
  `CertiNextAPIError` first, then the broad `requests.RequestException`, or API errors get
  swallowed as "network".
- **Token failures are different.** Bad OAuth credentials raise a plain `RuntimeError` from
  `auth.py` with **no** `.status_code` — the status is only in `str(e)`. Handle that path
  separately and substring-match for 401/403.
- **`422` is overloaded.** It's also the normal validation rejection for malformed bodies
  (with an `ems_code` / `field_errors`). The current prod `/domains` outage returns a
  *generic* 422 with **no** EMS code and **no** `errors[]`, identical for well-formed,
  malformed, and absent filters — so the cause is indeterminate from the body. Record the
  raw body and label it "contract-or-outage, indeterminate"; do not infer a root cause.
- **Empty ≠ healthy.** `get_list()` deliberately returns `[]` on odd response shapes
  (Spring page-wrapper vs bare array). A "did it raise?" check reports HEALTHY on a masked
  failure. Use the unfiltered count as a baseline and mark suspicious-empty as `EMPTY`.
- **Accessor-level `KeyError`/`ValueError`** (e.g. name lookup with no match) come from a
  *2xx* response — classify as works/empty, not as an error.
</details>

## Architecture

Single module `certinext/healthcheck_cli.py`:

- **`ProbeResult` dataclass** — `name, tier, outcome, http_status, ems_code, count,
  baseline_count, detail, duration_ms, message`.
- **`Probe` descriptor** — `name`, `tier`, `requires` (key into the run context, or none),
  and a `call(session, ctx) -> payload` closure. The registry is an ordered list of these.
- **`classify(fn) -> ProbeResult`** — the single try/except wrapper implementing the table
  above. Every probe goes through it.
- **`run(session, *, tier) -> list[ProbeResult]`** — run Tier 1, accumulate a context dict
  (`org_id`, `product_code`, `domain`, `issued_order_id`, `baseline_domain_count`), then run
  Tier 2 against that context, skipping where input is missing.
- **Renderers** — `_render_table(results)` via `tabulate(rows, headers="keys",
  tablefmt="simple")` with a one-line summary (`PASS 6 · SERVER_BUG 1 · SKIPPED 3`); and a
  `--json` path emitting `[asdict(r) for r in results]` with the raw RFC7807 bodies intact.
- **`main()`** — order matches the other CLIs: `build_parser().parse_args()` →
  `_setup_logging(args.verbose)` → `apply_sandbox(args)` → `build_session(args)` → `run` →
  render → `sys.exit(code)`. Wrap `KeyboardInterrupt` → `print("\nAborted.", file=sys.stderr);
  raise SystemExit(130)`. Catch `CertiNextAPIError` at the top with `fatal_api_error` only
  for connection-level failure (a probe-level API error is a *result*, not a crash).
- **Exit code** — `0` if no outcome in {`DENIED`, `NOT_FOUND`, `SERVER_BUG`, `NETWORK`};
  non-zero otherwise. `--strict` also fails on `EMPTY`.

CLI flags: connection group via `add_connection_args` (gives `--profile/--sandbox/
--base-url/--token-url/--account-number/--client-secret`), `-v/--verbose` count, `--json`,
`--tier {1,2,all}` (default `all`) / `--quick` (Tier-1 only), `--strict`. Phase 2 adds
`--history`.

## Phases

### Phase 1 — core probe (v1, ship this)

1. Create `certinext/healthcheck_cli.py` with the registry, `classify`, `run`, renderers,
   `main()` as above. Apache-2.0 header block to match the other library modules.
2. Add `certinext-healthcheck = "certinext.healthcheck_cli:main"` to `[project.scripts]` in
   [`pyproject.toml`](../../pyproject.toml).
3. Tests in `tests/test_healthcheck.py` against a mocked session (mirror
   `tests/test_domains_list.py` fixtures): one test per outcome — PASS, EMPTY (the
   `{"total":0,"domains":[]}` wrapper), DENIED (401/403), SERVER_BUG (the generic prod
   `/domains` 422 body), NETWORK, SKIPPED (no issued order), and the token-`RuntimeError`
   path. Assert the exit code mapping.
4. README section under the read-only CLIs.

### Phase 1.5 — known-bug watchers (optional flag, `--watch-known-bugs`)

Opt-in diagnostic probes that track *known* vendor bugs so we notice when a fix lands (this
is the "did CertiNext change something for our org?" signal). Each is reported as its own
row with the known-bug status as context, not counted as a generic failure:

- `domain.get_list(search="<exact FQDN>")` vs `get_list(search="<substring>")` — compare
  counts against the unfiltered baseline; substring returning 0 is the known partial-fix
  state (see [certinext-api-bugs skill](../../.claude/skills/certinext-api-bugs/SKILL.md)).
- `domain.get_list(domain_status=…, dcv_status=…)` together — the known combined-filter 400.
- Record which serialization was sent so the `DomainListFilter` GA contract migration can be
  validated here once the endpoint is healthy.

### Phase 2 — run-history cache & regression diff

Opt-in via `--history [DIR]`. Turns the stateless probe into a trend detector.

- **Snapshot:** after a run, write `{timestamp, env, account_or_org_id, results[]}` as JSON.
- **Storage:** `--state-dir` or `CERTINEXT_STATE_DIR`; default
  `$XDG_STATE_HOME/certinext/healthcheck` (POSIX) / `%LOCALAPPDATA%\certinext\healthcheck`
  (Windows), computed with a tiny helper (no new dependency).
- **Key by `(env, account_or_org_id)`** so prod is never diffed against sandbox.
- **Diff & highlight:** compare against (a) the most recent snapshot for the same key, and
  (b) a **last-known-good high-water mark**. Report count deltas beyond a threshold
  (e.g. domains `43 → 0`), outcome flips (`PASS → DENIED/SERVER_BUG`), new failures, and
  recoveries.
- **Retention:** keep the last N snapshots per key (default 30), prune older.

<details>
<summary>Why diff against a high-water mark, not just the previous run?</summary>

If the previous run was itself during an outage (0 domains), a previous-run-only diff shows
"0 → 0, no change" and silently hides the regression. Keeping a last-known-good baseline
makes a sustained outage keep flagging until it recovers, which is the behaviour an operator
actually wants from a nightly cron.
</details>

### Phase 3 — RBAC expectation matrix (deferred, design only)

When fine-grained keys exist: a config (per profile/key) of which endpoints *should* be
allowed vs denied; the probe compares actual outcome to expectation and reports deviations
(denied-but-expected-allowed, allowed-but-expected-denied). Note the 404-as-soft-RBAC
ambiguity — a 404 may mean "no access" rather than "absent". This layer is UMS-policy-specific
and may instead live in `ums-certinext-scripts`.

## Verification

- `uv run certinext-healthcheck --sandbox -v` against sandbox — confirm Tier-1 all `PASS`
  (or the expected sandbox `/domains` state), Tier-2 runs or `SKIPPED` cleanly.
- `uv run certinext-healthcheck -v` against **production** — this should currently surface
  `domain.get_list` as `SERVER_BUG` (the live 422) while accounts/catalog/orders/ledger
  stay `PASS`. That selective failure is the headline validation that the probe does its job.
- `certinext-healthcheck --json | python -m json.tool` — valid JSON, raw RFC7807 bodies
  present for any 422.
- `pytest tests/test_healthcheck.py` green; `ruff`, `mypy`/`pyright` clean per repo config.
- Exit code is non-zero when any probe is `SERVER_BUG`/`DENIED`/`NETWORK`.

## Documentation expectations

- README: new "`certinext-healthcheck`" subsection (usage, outcome legend, exit codes,
  `--json`, and Phase 2 `--history`).
- Docstrings on every class/function (repo standard).
- Changelog line in the annotated release tag when this ships (GitLab CI reads tag messages).
- If Phase 2 or 3 introduces a durable pattern (state-dir layout; expectation-matrix
  format), record it as an ADR and link it from this plan's `implements-adr` frontmatter.

## References

- argparse — https://docs.python.org/3/library/argparse.html
- structlog — https://www.structlog.org/en/stable/
- tabulate — https://pypi.org/project/tabulate/
- RFC 7807 (problem+json error bodies) — https://datatracker.ietf.org/doc/html/rfc7807
- OAuth 2.0 client-credentials grant (RFC 6749 §4.4) — https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
- `requests` exceptions — https://requests.readthedocs.io/en/latest/api/#exceptions
- XDG Base Directory (state dir) — https://specs.freedesktop.org/basedir-spec/latest/
- In-repo: [`_cli.py` helpers](../../certinext/_cli.py), [`exceptions.py`](../../certinext/exceptions.py),
  [`certinext-api-bugs` skill](../../.claude/skills/certinext-api-bugs/SKILL.md),
  [DCV-inheritance plan](dcv-inheritance-ga.md) (the live `/domains` 422 context).
