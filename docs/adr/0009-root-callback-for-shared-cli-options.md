---
status: accepted
date: 2026-08-04
---

# Centralize shared CLI options on the root `app` callback, resolved via `ctx.obj`

## Context and problem statement

Every one of the 11 `certinext` command surfaces (9 leaf commands with an
identical pattern, the `domains` group callback, plus `setup-defaults` and
`setup-keyring` which partially deviate) redeclares the same shared typer
options — `--profile`, `--sandbox`, `--base-url`, `--token-url`,
`--account-number`, `--client-secret`, `--json`, `--verbose`,
`--log-format` — then calls `setup_logging()` and `connect()` by hand. This
is the second time this exact duplication has been paid (once for the 1.0
connection options, again for `--log-format` in ADR 0007), and was tracked
as [IDEA-008](../wishlist/IDEA-008-root-level-cli-option-set.md). The
observability-logging plan
(`docs/plans/observability-logging/certinext.md`) adds two more shared
options (`--log-mode`, `--debug-log-path`) and would be a third repetition
without a fix — this is what forced the decision now rather than later.

ADR 0004 committed to flag-anywhere positioning (`certinext domains get
maine.edu --sandbox` must keep working the same as `certinext domains
--sandbox get maine.edu`), which the current `cli/__init__.py`'s
`_hoist_group_options()`/`_find_group_index()` argv-rewriting shim exists
to serve. Any centralization design has to preserve that.

## Considered options

- **Root-level `@app.callback()` + `ctx.obj`** (chosen): move every shared
  option onto the single root callback in `cli/_app.py`. It stores the raw
  values on a `ctx.obj` dataclass and calls `setup_logging()` exactly once
  per process. Commands needing a session call a `session(ctx)` helper
  (mirroring the `_session(ctx)` pattern `domains.py` already uses) so
  session-building stays lazy — a usage error still never triggers a
  credential prompt. The hoisting shim simplifies: since shared options now
  live in exactly one place, it just moves any recognized shared-option
  token to immediately after `argv[0]`, regardless of subcommand nesting
  depth (e.g. `setup keyring`) — the current per-entity-group bookkeeping
  (`ENTITY_GROUP_NAMES`, searching for a group name at an arbitrary argv
  position) goes away entirely.
- **A Click `Command`/`Group` subclass injecting shared params invisibly.**
  Rejected: typer builds its click params from function-signature
  introspection, so a subclass can't hand a command function parameters the
  function itself doesn't declare, without abandoning typer's normal
  binding model.
- **A per-command decorator applying the shared param set.** Rejected:
  still requires per-file wiring of the `setup_logging()`/`connect()` calls
  even if the option *declarations* were deduplicated, so it doesn't close
  the actual gap — the repeated boilerplate, not just the `Annotated`
  parameter lines.

## Decision outcome

Chosen: **root-level callback + `ctx.obj`.** It fully centralizes both the
option declarations and the `setup_logging()`/session-building call sites,
and composes cleanly with the observability-logging plan's `--log-mode`
and `--debug-log-path` (Phases 2–3), which now become one-line additions to
the root callback instead of an 11-file edit.

### Consequences

- Good: every future shared option is a one-line change instead of an
  11-file mechanical edit; removes the risk of an option landing on some
  commands but not others (already nearly happened during the
  `--log-format` rollout, ADR 0007).
- Good: `_hoist_group_options()` gets simpler, not more complex — one
  hoist target (`argv[0]`) instead of per-entity-group lookup.
- Bad / accepted tradeoff: `setup-keyring` (today: only `--profile`/
  `--sandbox`, no `connect()`/`setup_logging()` call at all) and
  `setup-defaults` (today: 8 of 10 shared options, defers session-building
  via `resolve_connection()` + `build_session()` instead of `connect()`)
  will show the full shared-option set in their `--help` output even
  though they ignore most of the values. Explicitly accepted rather than
  adding a per-command opt-out list — true uniformity is what IDEA-008
  asked for by name, and the unused flags are harmless (silently ignored).

## More information

- [typer docs — subcommands](https://typer.tiangolo.com/tutorial/subcommands/)
- [typer docs — using a Context](https://typer.tiangolo.com/tutorial/commands/context/)
- [Click docs — commands and groups](https://click.palletsprojects.com/en/stable/commands/)
- [ADR 0004 — single CLI app with alias entry points](0004-single-cli-app-with-alias-entry-points.md) (the flag-anywhere commitment this design preserves)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md) (where IDEA-008 was first raised)
- [IDEA-008 — root-level CLI option set](../wishlist/IDEA-008-root-level-cli-option-set.md) (implemented by this ADR)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
