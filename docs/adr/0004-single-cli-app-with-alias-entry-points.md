---
status: accepted
date: 2026-07-02
---

# Ship one `certinext` CLI app; keep the eleven script names as aliases through 1.x

## Context and problem statement

The package installs eleven separate console scripts (`certinext-domains`,
`certinext-issue-cert`, `certinext-healthcheck`, ...), all argparse, sharing
plumbing through the private `certinext/_cli.py`. Typer's natural shape is a
single application with subcommands. Cron jobs and runbooks may invoke the
old script names, and we have not audited what parses their output. What CLI
shape does 1.0 ship?

## Considered options

- One `certinext` typer app with subcommands, old names kept as thin alias
  entry points
- Keep eleven separate scripts, typer internals only
- One app, old names removed at 1.0 (clean break)

## Decision outcome

Chosen: **one app + aliases** (`certinext domains list`,
`certinext issue-cert`, `certinext healthcheck`, ...), with the eleven
existing console-script names retained as thin aliases that delegate to the
corresponding subcommand. Aliases are removed no earlier than 2.0. Ratified
2026-07-02.

Invariants the new CLI must preserve regardless of shape: data on stdout,
diagnostics on stderr (including prompts — the `prompt_stderr()` discipline);
`--json` output formats byte-compatible with 0.3.x; exit-code semantics
(the healthcheck's exit codes are monitoring-relevant).

### Consequences

- Good: 1.0 is the only cheap moment to consolidate; subcommands give shared
  options, one help tree, and shell completion for free.
- Good: aliases mean no cron job or runbook breaks at upgrade time.
- Bad: aliases keep eleven entry points in `pyproject.toml` for the life of
  1.x, and help text/usage strings change even under the aliases (typer
  formats differently than argparse).
- Neutral: the audit of "what parses our CLI output" (roadmap open question)
  still has to happen before any output format changes.

## Pros and cons of the options

### One app + aliases (chosen)

- Good, because consolidation without a flag-day for operations.
- Bad, because dual surface to test during 1.x.

### Keep eleven scripts

- Good, because lowest operational risk.
- Bad, because it forgoes the consolidation opportunity permanently — nobody
  re-litigates CLI shape in a minor release.

### One app, clean break

- Good, because simplest packaging.
- Bad, because every runbook/cron invocation must be updated in lock-step
  with the upgrade, and we don't yet know where they all are.

## More information

- [typer docs — subcommands](https://typer.tiangolo.com/tutorial/subcommands/)
- [Python packaging — entry points / console scripts](https://packaging.python.org/en/latest/specifications/entry-points/)
- Plan: `docs/plans/pydantic-typer-refactor/phase-4-typer-cli.md`

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
