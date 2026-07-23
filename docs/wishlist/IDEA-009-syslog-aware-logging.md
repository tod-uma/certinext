# IDEA-009: Syslog/journald-aware logging mode

- **Status:** Proposed (coordinating issue: #24)
- **Created:** 2026-07-23
- **Updated:** 2026-07-23

## Context

Raised 2026-07-23 while discussing `setup_logging()`'s non-interactive output
(ADR 0007). Scripts running as systemd units already have `timestamp` and
`pid` stamped onto every line by journald/syslog before it reaches Splunk
(the `dcv-update[1988202]:` syslog header in ADR 0007's own example). The
app-level `timestamp` field and the `pid` bound via
`structlog.contextvars.bind_contextvars(pid=os.getpid())` (see
`zabbix_push_cli.py`, `dcv_update_cli.py`) duplicate that.

## The idea

Auto-detect that a run is under systemd (`INVOCATION_ID` env var, set for
every systemd-invoked run whether or not stdout/stderr feed journald
directly; `JOURNAL_STREAM` when they do) and drop the redundant `timestamp`
and `pid` fields from non-interactive output in that case — reusing the
existing `_drop_keys_processor()` helper in `certinext/cli_support.py`.

Needs a manual override in **both directions**, since detection can be
wrong for the operator's actual intent, not just for the transport:
- Force the extra fields **on** even though it's running under systemd (e.g.
  someone debugging a unit interactively wants pid/timestamp anyway).
- Force syslog-mode **on** even though it's running under cron — classic
  cron has no environment signal to detect, so a user piping cron output
  into `logger(1)` needs to opt in explicitly.

## Why not now

Blocked on [IDEA-008](IDEA-008-root-level-cli-option-set.md). A bidirectional
override needs a CLI flag, and any new shared flag today means hand-declaring
it in all 10 `certinext/cli/*.py` command files (the same repetition
`--log-format` just paid, per ADR 0007's consequences). Building this before
IDEA-008 lands means doing that 10-file mechanical edit now and touching it
again once the root-level option mechanism exists. This is the second
concrete option-need IDEA-008's own "Next steps" was waiting for.

## Pros

- Removes duplicate `timestamp`/`pid` fields from the common case (systemd
  unit → journald/syslog → Splunk) with zero configuration.
- The override covers both real mismatches between transport and intent:
  interactive debugging under systemd, and cron piped through `logger(1)`.

## Cons / costs

- Detection only covers systemd (`INVOCATION_ID`/`JOURNAL_STREAM`); classic
  cron and manual `logger(1)` piping are invisible to the process, so those
  paths always need the explicit override, not just fallback to auto-detect.
- `setup_logging()` is duplicated (not shared) between `certinext` and `nm`
  — see [ADR 0007](../adr/0007-logfmt-default-for-non-interactive-logging.md)
  consequences and `nm/cli_support.py`'s parallel copy — so both need the
  change, kept in sync by hand.

## Effort

Small once IDEA-008 exists: the detection + field-dropping logic is a
few lines reusing `_drop_keys_processor()`; the override flag becomes a
one-line root-level option instead of a 10-file edit.

## Open questions & caveats

- Exact flag shape: a tri-state (`--log-mode auto|syslog|verbose`, or
  similar) vs. two independent boolean flags. Decide once IDEA-008 settles
  how root-level options are declared.
- Whether `nm`'s independent `setup_logging()` copy gets the same treatment
  in lockstep, or on its own schedule.

## Next steps

Revisit once IDEA-008 (root-level CLI option set) is accepted/implemented.

## References

- [systemd.exec — `INVOCATION_ID`, `JOURNAL_STREAM`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#%24INVOCATION_ID)
- [ADR 0007 — logfmt default for non-interactive logging](../adr/0007-logfmt-default-for-non-interactive-logging.md)
- [IDEA-008 — root-level (shared) CLI option set](IDEA-008-root-level-cli-option-set.md)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
