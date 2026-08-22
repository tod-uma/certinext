---
status: done
depends-on: [phase-4, phase-5]
implements-adr: []
---

# Phase 6 — Docs, CI, and the 1.0.0 release

Tracking: issue #19 · milestone %v1.0.0 · label ~"refactor-v1"

The closing gate. Most items accrue during phases 1–5 (each phase's
"documentation expectations" section); this document is the checklist that
proves none were skipped, plus the release mechanics.

## Documentation

- **README** (~1700 lines) restructured: uv-first install kept (house
  style), CLI section around `certinext` subcommands + alias table, Python
  library section rewritten for models, credentials section re-verified
  (phase 3), known-issues section reflecting phase-0 probe outcomes.
- **Migration guide 0.3 → 1.0** (new `docs/migrating-to-1.0.md`): exception
  base-class change with before/after `except` blocks; `certinext._cli` →
  `certinext.cli_support`; alias table; "no config/keyring changes
  required"; anything the phases logged as divergent.
- **`.claude/skills/`** in-repo (certinext-api-bugs, certinext-release,
  first-stable-release) re-read against the new reality.
- README example accuracy is manual (no doctest infra) — one deliberate
  pass executing each Python example against sandbox. (Durable fix is
  wishlist IDEA-004, deferred.)
- **AI/agent affordances** (cheap subset of wishlist IDEA-003, in scope for
  1.0): a hand-curated `llms.txt` at repo root per the
  [llms.txt convention](https://llmstxt.org/) pointing at README sections,
  the migration guide, and examples; an `AGENTS.md` per the
  [agents.md convention](https://agents.md/) carrying the same operational
  facts as `CLAUDE.md` for non-Claude tooling; and a short "AI-agent
  quickstart" README subsection (install, `session()`, healthcheck-first,
  where the known-issues live).

## Tests & typing

- Target: `mypy` strict across **package and tests** — the tests are being
  rewritten anyway, which retires the standing "~592 missing annotations in
  tests/" debt; then widen CI from `mypy certinext` to `mypy .`.
- Corpus-parse tests + probe suite are permanent CI citizens: probes stay
  opt-in (`-m probe`, needs creds), corpus tests run everywhere.

## CI

- `.gitlab-ci.yml`: keep stage/job structure; **preserve the
  `needs: optional: true` semantics** around `integration-cert-issuance` →
  release jobs (register R24 — sandbox outages must skip, not block,
  GitLab releases while GitHub→PyPI proceeds independently). If job or test
  files are renamed, re-verify that graph deliberately
  ([GitLab needs docs](https://docs.gitlab.com/ci/yaml/#needs)).
- `.github/workflows/ci.yml`: delete the disabled `publish-main`/`release`
  leftovers (pre-existing TODO) while touching it.
- Dependency hygiene: `requests`/`tabulate`/`types-*` removed, final dep set
  matches ADR 0003's confirmation clause.

## Release train

Versioning per house scheme: `1.0.0aN` while phases land → `1.0.0rcN` when
the surface freezes (phase 5 runs against rc) → **1.0.0 stable**. Stable is
this repo's first-ever non-prerelease tag — the `release_job` has never run
on a stable tag; follow the repo's `first-stable-release` skill checklist
when tagging. Annotated tag carries the curated changelog (house rule; CI
reads it for release notes). Push tags to the `gitlab` remote; PyPI publish
rides GitHub Actions OIDC as today.

Post-release: merge the branch, delete it, close the roadmap (statuses →
done), close the phase issues (#13–#19) and the %v1.0.0 milestone, and file
wishlist ideas for anything consciously deferred (pkcs7 revisit is
contingent on R06's probe outcome).

## Verification

- Fresh-machine walkthrough of the README install + first-run path (uv,
  keyring setup, healthcheck).
- rc tag pipeline fully green (including `integration-cert-issuance`);
  stable tag: GitLab release, GitHub release, PyPI artifact all present;
  `uv tool install certinext` from PyPI works and `certinext --help` shows
  the subcommand tree.
- ums-certinext-scripts pin raised and released (phase 5) before or with
  the stable announcement.

## Implementation record — docs slice (2026-07-08)

CI+typing slice landed first via MR !83 (see the roadmap). This slice is the
documentation half of phase 6, on child branch `refactor/phase-6-docs`
(per-phase pattern, off `feat/pydantic-typer-refactor` at `622848d`).

- **README**: fixed the two stale bits a straight restructure would have
  missed — the Requirements section still listed `tabulate` as a runtime
  dependency (removed in phase 4) and the "Project structure" file tree
  was entirely pre-1.0 (flat `*_cli.py` files, no `cli/`, `models/`,
  `cli_support.py`, `settings.py`, `healthcheck.py`). Rewrote both, plus
  filled in the Contents ToC (it never listed the Credentials/Python
  library subsections) and added a top-level **AI-agent quickstart**
  section per this doc's spec. The CLI-subcommand/alias-table restructure
  and credentials/known-issues sections were already current from phase 4
  and phase 0 — no changes needed there beyond the dependency line.
- **docs/migrating-to-1.0.md**: new file. Exception base-class before/after,
  `certinext._cli` → `cli_support` table, the 11-script alias table, and an
  explicit "no config/keyring changes required" section backed by reading
  `settings.py`/`_config.py` directly (not just repeating the phase-3 plan's
  claim) — config format, path, precedence, and keyring service/key names
  are all unchanged; only the TOML writer's internal library changed
  (tomlkit), which round-trips transparently.
- **Manual example-accuracy pass (the actual point of this slice byte-for-byte):**
  ran every read-only Python example in the README against the sandbox API.
  Found and fixed one real bug — `order.verify_dcv()` and
  `order.accept_agreement()` in the "DV lifecycle" and end-to-end examples
  are called with zero arguments, but the current signatures are
  `verify_dcv(domain, method)` and `accept_agreement(signer_name,
  signer_place)`; both would raise `TypeError` if copy-pasted. Also found
  the Domain model gained `dcv_expires`, `verified_at`,
  `dcv_expires_soon()`, `dcv_covering_parent()`, `to_row()`, and
  `reinitiate_dcv()` during phase 1 without ever reaching the README, and
  `SslOrder.reject()` and `Organization`'s lazy-loaded detail properties
  (`state_code`, `validation_status`, `org_representatives`, etc.) were
  likewise undocumented. All fixed and re-verified live against sandbox
  (except `reject()`/mutating calls — not exercised live; the signatures
  came from direct source reads, and phase 4 already did a full sandbox DV
  issuance end-to-end). Mutating examples (create-domain, issue-cert,
  deactivate, revoke) were **not** re-run live this session — deliberate
  scope call, see this doc's own note that example accuracy is
  non-durable/manual (IDEA-004 is the real fix).
- **`.claude/skills/` re-verification**: `certinext-api-bugs` had a stale
  claim that `get_pending_dcv()` server-side filtering was "planned for the
  1.0 refactor" — it shipped in phase 1; fixed. `certinext-release` told
  the reader to `git push origin vX.Y.Z`, but this repo has no `origin`
  remote (only `gitlab`/`github`) — that command would fail outright; fixed
  to `git push gitlab`. `first-stable-release` had nothing stale.
- **llms.txt** and **AGENTS.md**: both new, per the llmstxt.org/agents.md
  conventions referenced in this doc's spec. AGENTS.md carries the same
  operational facts as `CLAUDE.md` (publish chain, wishlist awareness) plus
  dev/test/lint/typecheck commands and a note on where models vs. legacy
  modules live, for non-Claude tooling.
- **Verification**: 770 unit tests, ruff, mypy --strict, pyright all green
  (no source code changed this slice, docs/skills only). Fresh-machine
  install walkthrough and the release train itself are **not yet done** —
  next slice.

Not done in this slice (explicitly out of scope, next up): the release
train (1.0.0aN → rcN → 1.0.0 stable) and its fresh-machine verification
pass, and closing out the roadmap/issues/milestone.

## Closing note (2026-08-21)

The release train this document describes as outstanding completed some
time ago without this doc being updated: `v1.0.0` and `v1.1.0` are both
tagged and released, and the repo is now well past them (on `v1.2.0rc2`
tagged this same day). Marking this phase — and the roadmap — done and
archiving. Issue #19 and the `v1.0.0` milestone are still open on GitLab;
closing those is a separate, explicit step (not folded into this doc edit).

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
