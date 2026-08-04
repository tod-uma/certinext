---
status: accepted
date: 2026-08-04
---

# Tri-state `--log-mode auto|syslog|verbose` for syslog/journald-aware output

## Context and problem statement

[IDEA-009](../wishlist/IDEA-009-syslog-aware-logging.md) noted that
systemd-unit output already gets a timestamp and PID stamped on by
journald/syslog before it reaches Splunk (see ADR 0007's own example), so the
structlog-level `timestamp` field and any `pid` bound via
`structlog.contextvars.bind_contextvars` duplicate that. IDEA-009 was blocked
on [IDEA-008](../wishlist/IDEA-008-root-level-cli-option-set.md) because a
correct fix needs a bidirectional override (force the fields on even under
systemd for interactive debugging; force them off even without a systemd
signal for classic cron piped through `logger(1)`), and adding a tenth shared
flag before IDEA-008 landed meant hand-editing all 10 `certinext/cli/*.py`
files a third time. ADR 0009 closed that blocker; this ADR settles the flag
shape itself (`docs/plans/observability-logging/README.md` D4).

## Considered options

- **Tri-state `--log-mode auto|syslog|verbose`** (chosen): one option, three
  explicit values.
- **Two independent boolean flags** (e.g. `--force-syslog-mode` /
  `--force-verbose-mode`): covers the same three effective states (plus an
  invalid fourth: both set) but needs conflict handling and two flags to
  document instead of one.

## Decision outcome

Chosen: **tri-state `--log-mode`**, default `auto`. Resolution:

- `auto` + systemd detected (`INVOCATION_ID` or `JOURNAL_STREAM` env var,
  either is sufficient) → drop `timestamp` and `pid`.
- `auto` + not detected → unchanged (current behavior).
- `syslog` → always drop, regardless of detection — the override classic cron
  needs, since it has no env signal to auto-detect.
- `verbose` → always keep, even under systemd — for interactively debugging a
  unit's output.

Implemented in `certinext.cli_support.setup_logging()` as a `LogMode` enum
(mirroring `LogFormat`) plus `_systemd_invoked()` and
`_effective_syslog_mode()` helpers; only affects non-interactive output,
reusing the existing `_drop_keys_processor()` — interactive (TTY) output is
untouched regardless of `log_mode`. Wired onto the root callback (ADR 0009)
as a one-line addition, exactly what IDEA-008 was meant to unblock.

### Consequences

- Good: a single documented flag with three explicit states, no
  both-set-at-once ambiguity to guard against.
- Good: the common case (systemd unit → journald → Splunk) needs zero
  configuration to drop the duplicate fields.
- Neutral: detection only covers systemd; classic cron/manual `logger(1)`
  piping remains invisible to the process and always needs the explicit
  `syslog` override — this was already known going in (IDEA-009 cons).
- Bad / accepted: `nm`'s independent `cli_support.py` copy needs the same
  change by hand (D6) — no shared module between the two (see ADR 0007
  consequences).

## More information

- [IDEA-009 — syslog/journald-aware logging mode](../wishlist/IDEA-009-syslog-aware-logging.md) (implemented by this ADR)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md)
- [ADR 0009 — root callback for shared CLI options](0009-root-callback-for-shared-cli-options.md) (the mechanism this flag is wired through)
- [systemd.exec — `INVOCATION_ID`/`JOURNAL_STREAM`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#%24INVOCATION_ID)
- `docs/plans/observability-logging/README.md` (decision D4)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
