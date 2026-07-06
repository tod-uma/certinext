# Plan roadmap: certinext 1.0 pydantic/typer refactor

Rewrite the library onto our current Python stack — pydantic v2 models,
a single typer CLI, httpx transport, pydantic-settings config, rich output
(ADR 0003) — while re-validating every catalogued vendor-API workaround
against sandbox and (read-only) production, because the vendor patches and
regresses without notifying us (ADR 0005 context; issue #6 is fresh proof).
Target version: **1.0.0**, developed as `1.0.0aN` pre-releases on branch
`feat/pydantic-typer-refactor`. Starting state, to be exact: the branch tip
`f8bac80` is one commit (the 1.0.0a1 version bump) on top of `main`'s
`8564993` — so it already *contains* everything shipped through 0.3.0rc9,
including the sortBy-paging fix, but carries **no refactor code yet**.

Decisions ratified 2026-07-02 (Tod): full modernization stack → ADR 0003;
single `certinext` app with alias entry points → ADR 0004; lenient models +
live-payload corpus → ADR 0005; long-lived feature branch → below.

**Tracking:** GitLab milestone %v1.0.0 groups all refactor work; every
refactor issue carries the ~"refactor-v1" label so v0.3 bug triage can
filter it out (vendor bugs keep ~"vendor-bug"). One issue per phase — see
the table. Wishlist issues #7–#12 are deliberately *outside* the milestone
(post-1.0 by definition; the ~"wishlist" label separates them).

## Phases

| Phase | Document | Issue | Status | depends-on | implements-adr |
| --- | --- | --- | --- | --- | --- |
| 0 — Guardrails & probe suite (**lands on `main`**) | [phase-0-guardrails-and-probe-suite.md](phase-0-guardrails-and-probe-suite.md) | #13 | planned | — | 0005 |
| 1 — Pydantic models | [phase-1-pydantic-models.md](phase-1-pydantic-models.md) | #14 | done | phase-0 | 0003, 0005 |
| 2 — httpx transport & exceptions | [phase-2-httpx-transport.md](phase-2-httpx-transport.md) | #15 | planned | phase-1 | 0003 |
| 3 — pydantic-settings config | [phase-3-pydantic-settings-config.md](phase-3-pydantic-settings-config.md) | #16 | planned | phase-0 | 0003 |
| 4 — typer CLI + rich | [phase-4-typer-cli.md](phase-4-typer-cli.md) | #17 | planned | phase-1, phase-2, phase-3 | 0003, 0004 |
| 5 — Consumer migration | [phase-5-consumer-migration.md](phase-5-consumer-migration.md) | #18 | planned | phase-4 | — |
| 6 — Docs, CI, release | [phase-6-docs-ci-release.md](phase-6-docs-ci-release.md) | #19 | planned | phase-4, phase-5 | — |

```text
phase-0 (on main, merges into the branch)
  ├──> phase-1 ──> phase-2 ──┐
  ├──> phase-3 ──────────────┼──> phase-4 ──> phase-5 ──> phase-6
  └───────────────────────────┘
```

### Sequencing notes

- **Phase 0 is an inversion**: it is numbered first but lands on `main`, not
  on the refactor branch — its outputs (capped consumer pin, validated
  healthcheck, probe suite + payload corpus, corrected docs) must protect the
  0.3.x line too, and merging `main` into the branch afterward brings them
  along. Nothing on the refactor branch may be merged to `main` before
  phase 0's pin cap ships (see the trap below).
- **Phase 2 after phase 1 is a choice, not a hard dependency** — transport
  and models are independent, but sequencing them serializes the test churn
  in `tests/` (both phases rewrite overlapping test modules).
- **Phase 3 is parallel-safe** with phases 1–2; it touches only
  `_config.py`/`_keyring.py` territory.
- **Phase 6 is continuous** — docs/CI expectations listed there accrue per
  phase; the document exists so the final release gate is explicit.

## Branch and merge strategy (ratified 2026-07-02)

Fixes to 0.3.x land on `main` and ship from `main` exactly as today; the
refactor lives on the long-lived `feat/pydantic-typer-refactor` branch.

<details>
<summary>Why a long-lived branch instead of flipping main to 1.0?</summary>

- Vendor-bug fixes are urgent and operational (the chain-order bug broke IIS
  in production); the refactor is not urgent. The fix path must stay cheap —
  no maintenance-branch/backport dance for every fix.
- Once a module is rewritten, `git merge` stops helping for that module in
  *either* model; the porting cost is symmetric. What differs is who pays
  overhead per fix, and the branch model puts it on the refactor.
- Rejected: trunk flip (main becomes 1.0.0aN, `release/0.3.x` cut from
  v0.3.0rc9) — cleaner CI story for the refactor, but every 0.3.x fix
  immediately needs a backport, and `publish-main` would push 1.0 dev builds
  to the GitLab registry while consumers' pins are still being capped.

</details>

Discipline:

- **Merge `main` into the branch before starting each phase**, and after any
  `main` fix touching a module the current phase is rewriting.
- **Ported-fixes log** — whoever is implementing the current phase appends a
  row at the moment a `main` fix cannot be merged cleanly and has to be
  re-implemented by hand on the branch (empty rows are good news: merges
  still apply):

| main commit  | what | branch port |
| ------------ | ---- | ----------- |
| *(none yet)* |      |             |

## Version/pin trap (do not reorder past phase 0)

No stable release of certinext exists on any index — every published version
is a pre-release. Under [PEP 440 / the version-specifier spec](https://packaging.python.org/en/latest/specifications/version-specifiers/#handling-of-pre-releases)
and [uv's pre-release resolution](https://docs.astral.sh/uv/concepts/resolution/#pre-release-handling),
`ums-certinext-scripts`' pin `certinext>=0.2.2rc1` (itself naming a
pre-release, which opts uv in) **will resolve to 1.0.0aN the moment one is
published** to the GitLab registry or PyPI. Phase 0 caps that pin before any
1.0.0aN artifact exists.

## Open questions (answers change phases 4–5)

1. **What parses the CLIs today?** Do any cron jobs, monitoring, or runbooks
   consume stdout or exit codes of the eleven scripts beyond `--json`?
   (Known: healthcheck exit codes are monitoring-relevant.) Until audited,
   phase 4 treats all stdout formats as load-bearing.
2. **Sandbox seeding**: multi-page pagination probes need >200 domains;
   sandbox had ~107 (2026-06-24). Seed more, or accept prod(read-only)-only
   evidence for multi-page behavior?
3. **Probe cadence**: is the phase-0 probe suite also scheduled (cron/CI) or
   run on demand only?
4. **TOML writer**: keep the hand-rolled `_config.py` renderer or adopt
   [tomlkit](https://tomlkit.readthedocs.io/en/latest/) for round-tripping?
   (Phase 3 sub-decision.)
5. **Python floor**: bump `requires-python` to `>=3.11` at 1.0? Drops the
   `tomli` backport dependency, and 3.10 reaches end-of-life 2026-10 —
   likely before 1.0.0 stable ships. Recommended unless a consumer is stuck
   on 3.10 ([Python release status](https://devguide.python.org/versions/)).

## Wishlist-aware design

Deferred ideas live in [docs/wishlist/](../../wishlist/README.md). Keep them
in mind while implementing: prefer designs that keep parked ideas cheap
rather than foreclosing them. Concretely for this refactor: phase 4's
thin-presentation rule exists so IDEA-001 (Textual TUI) and IDEA-002 (MCP
server) can reuse the operations layer, and IDEA-005 (async client) is why
transport code should not weld itself to blocking-only assumptions where the
sync/async-neutral choice is free.

## References

- ADRs: [0003](../../adr/0003-adopt-pydantic-typer-httpx-settings-rich-for-1.0.md),
  [0004](../../adr/0004-single-cli-app-with-alias-entry-points.md),
  [0005](../../adr/0005-lenient-models-validated-against-live-payload-corpus.md),
  [0002 (vendor bugs → GitLab issues)](../../adr/0002-track-vendor-api-bugs-in-gitlab-issues.md)
- Survey evidence (2026-07-02, session-local): 24-item workaround inventory,
  consumer surface audit, tests/CI survey — condensed into phase 0's
  assumption register and phase 1's compatibility surface.
- [pydantic](https://docs.pydantic.dev/latest/) · [typer](https://typer.tiangolo.com/) ·
  [httpx](https://www.python-httpx.org/) ·
  [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) ·
  [rich](https://rich.readthedocs.io/en/stable/)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
