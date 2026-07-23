# IDEA-008: Root-level (shared) CLI option set instead of per-command repetition

- **Status:** Proposed (coordinating issue: #23)
- **Created:** 2026-07-22
- **Updated:** 2026-07-23

## Context

Raised 2026-07-22 while adding `--log-format` (ADR 0007): the flag had to be
declared individually in all 10 `certinext/cli/*.py` command files (plus
re-exporting `LogFormatOption` through `cli/_shared.py`), the same repetitive
pattern every other shared option (`--verbose`, `--json`, `--profile`,
`--sandbox`, ...) already follows. There is no single place that declares
"every certinext command gets these options" — each command or command-group
callback lists them itself.

## The idea

A genuinely shared, root-level option set: declare `--verbose`,
`--log-format`, `--json`, and the connection options once, and have every
command/group inherit them, instead of repeating the `Annotated` parameter
in each of the 10 files.

## Why not now

This isn't a simple "move the options to the root `typer.Typer()` callback"
change. Click/Typer only accept a parent-level option *before* the
subcommand token by default (`certinext --verbose accounts`, not
`certinext accounts --verbose`). The current per-command duplication exists
*because* ADR 0004 committed to flag-anywhere compatibility with the old
0.3.x argparse scripts (`certinext domains get maine.edu --sandbox` must
keep working) — `cli/__init__.py`'s `_hoist_group_options()` already
rewrites argv to fake that flexibility. A real fix has to keep that
flag-anywhere behavior while still deduplicating the declarations, which
means redesigning how options attach to commands, not just relocating them.
It's also orthogonal to whatever prompted adding the next option (a logging
fix, in this case) and touches all 10 command files plus the hoisting logic
plus every downstream repo that imports `certinext.cli_options` — a
refactor in its own right, not a drive-by.

## Pros

- Every future shared option (this is the second time this exact
  duplication has been paid, after the original 1.0 connection options) is
  a one-line change instead of a 10-file mechanical edit.
- Removes the risk of an option being wired into some commands but missed
  in others (already almost happened once during the `--log-format` rollout).

## Cons / costs

- Redesigning the option-attachment mechanism while preserving flag-anywhere
  positioning is nontrivial — it's the reason the current duplication exists
  in the first place, not an oversight.
- Touches all 10 command files, `cli/_shared.py`, `cli/__init__.py`'s
  hoisting logic, and needs re-verification against every downstream
  consumer of `certinext.cli_options` (`nm`, `ums-certinext-scripts`,
  `certinext-zabbix`).

## Effort

Medium-to-large: a full design pass on how typer/click support (or don't
support) flag-anywhere shared options is needed before estimating the
mechanical part.

## Open questions & caveats

- Is there a typer/click-native pattern (e.g. a custom `Context` /
  `resilient_parsing` approach, or a Click `Group` subclass) that gives
  flag-anywhere positioning without argv rewriting, or is
  `_hoist_group_options()` the only way to get this UX in click's model?
- Would deduplicating the *declaration* still require every command function
  to accept the parameter (so it reaches the function body), or can it be
  fully centralized via `ctx.obj`, changing how command bodies read option
  values?

## Next steps

Revisit the next time a new shared option needs adding, or if the
per-command duplication causes a real miss (an option wired into some
commands but not others).

[IDEA-009](IDEA-009-syslog-aware-logging.md) (syslog/journald-aware logging
mode, 2026-07-23) is the second concrete option waiting on this: it needs a
bidirectional override flag, and doing that as another 10-file mechanical
edit is exactly the cost this idea exists to avoid.

## References

- [typer docs — subcommands](https://typer.tiangolo.com/tutorial/subcommands/)
- [Click docs — commands and groups](https://click.palletsprojects.com/en/stable/commands/)
- [ADR 0004 — single CLI app with alias entry points](../adr/0004-single-cli-app-with-alias-entry-points.md) (the flag-anywhere compatibility commitment this duplication serves)
- [ADR 0007 — logfmt default for non-interactive logging](../adr/0007-logfmt-default-for-non-interactive-logging.md) (where this cost was paid most recently)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
