---
status: planned
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

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
