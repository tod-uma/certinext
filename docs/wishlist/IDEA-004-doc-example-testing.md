# IDEA-004: Execute README/docs code examples in CI

- **Status:** Proposed (coordinating issue: #10)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

The 2026-07-02 refactor survey flagged that README examples are kept
accurate only by hand — there is no doctest or example-execution
infrastructure, and the README is ~1700 lines of hand-maintained samples.
The refactor's phase 6 schedules one manual verification pass; this idea is
the durable fix.

## The idea

Run documentation code blocks as tests in CI using
[sybil](https://sybil.readthedocs.io/) (parses code blocks out of Markdown
and executes them under pytest) or
[mktestdocs](https://github.com/koaning/mktestdocs). API-calling examples
run against recorded/mocked responses (the phase-0 corpus fixtures are the
natural stub data) so CI needs no credentials; a marked subset may
optionally run live against sandbox.

## Why not now

The README is about to be restructured twice (phase 6 rewrite, possibly
IDEA-003's site split) — instrumenting examples before the text settles
means building the harness twice. Pick up after phase 6 (or fold into
IDEA-003 if that lands first).

## Pros

- "Docs that lie" becomes a CI failure instead of a user bug report.
- Compounds with IDEA-003: every page of the docs site stays executable.

## Cons / costs

- Examples must be written runnable-first (fixtures/session stubs), which
  constrains their style.

## Effort

Small-medium once the docs are stable.

## Open questions & caveats

- sybil vs mktestdocs (sybil is the more maintained/general choice).
- How to stub `session()` cleanly in examples without cluttering them.

## Next steps

None until phase 6 of the refactor completes.

## References

- [sybil](https://sybil.readthedocs.io/) ·
  [mktestdocs](https://github.com/koaning/mktestdocs)
- Related: IDEA-003 (docs site)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
