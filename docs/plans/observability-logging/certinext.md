---
status: in-progress
depends-on: []
implements-adr: [0009, 0010]
---

# `certinext` sub-plan — shared options, syslog-aware output, debug-log file

Repo: `python-libs/certinext`. Master: [README.md](README.md) (decisions
D1–D7, dependency graph, per-repo paths). This sub-plan covers the **library
side**: Phase 1 (IDEA-008), and the `cli_support.py` half of Phases 2 & 3.
Wiring into downstream CLIs and the `nm` copy are in their own sub-plans.

Start with `/start-work` on this repo (branch e.g. `feat/observability-logging`).
Bump version per the version-scheme skill (this is a feature → minor bump from
the current stable line; confirm the exact number at start).

## Phase 1 — IDEA-008: root-level shared CLI options (D3: full redesign)

**Problem:** every shared option (`--verbose`, `--log-format`, `--json`,
`--profile`, `--sandbox`, and now `--log-mode` + `--debug-log-path`) is declared
by hand in all 10 `certinext/cli/*.py` command files. There is no single place
that says "every command gets these." See
[IDEA-008](../../wishlist/IDEA-008-root-level-cli-option-set.md) for the full
context.

**Constraint that makes this non-trivial:** ADR 0004 committed to *flag-anywhere*
positioning (`certinext domains get maine.edu --sandbox` must keep working),
which is why `cli/__init__.py`'s `_hoist_group_options()` rewrites argv today.
The redesign must **preserve flag-anywhere** while deduplicating the
declarations.

**Steps:**
1. Read `cli/__init__.py` (`_hoist_group_options`), `cli/_shared.py`, and 2–3
   representative `cli/*.py` command files to map exactly how options reach
   command bodies today.
2. Decide the centralization mechanism (open question from IDEA-008 — resolve it
   here, record as ADR):
   - a Click `Group`/`Command` subclass that injects the shared params, or
   - a decorator applied to each command, or
   - `ctx.obj`-based propagation with a root callback.
   Whichever is chosen must keep flag-anywhere working (keep or adapt
   `_hoist_group_options`, don't silently drop it).
3. Implement so the shared set is declared **once** and inherited. Command
   bodies still receive the values they need (via signature or `ctx.obj` —
   the ADR records which).
4. Re-verify every one of the 10 commands still accepts each shared flag in
   both positions (before and after the subcommand token).

**Verify:** full `certinext` test suite green; add/extend tests asserting
flag-anywhere for at least one shared flag on a sample of commands; `mypy` +
`ruff` clean.

<details>
<summary>Why full redesign now instead of hand-wiring two more flags (D3)</summary>

This is the second time the 10-file duplication has been paid (first for the
1.0 connection options, again for `--log-format` in ADR 0007). Phases 2 & 3 add
two *more* shared flags. Doing IDEA-008 properly makes those two — and every
future shared option — a one-line change, and unblocks the same flags for `nm`
and the downstream CLIs. Hand-wiring would pay the 10-file cost a third time and
still leave the debt.
</details>

## Phase 2 — IDEA-009: syslog/journald-aware output (D4: `--log-mode`)

In `certinext/cli_support.py`, `setup_logging()`:
1. Add a `log_mode` param, tri-state `auto | syslog | verbose` (an `Enum`, like
   `LogFormat`). Default `auto`.
2. Detect systemd via env: `INVOCATION_ID` (set for every systemd-invoked run)
   or `JOURNAL_STREAM` (set when stdout/stderr feed journald directly).
3. Resolve effective mode:
   - `auto` + systemd detected → **syslog mode** (drop `timestamp` + `pid`).
   - `auto` + not detected → current behavior (keep both).
   - `syslog` → force drop (for cron piped to `logger(1)`, which has no
     detectable env signal).
   - `verbose` → force keep, even under systemd (interactive unit debugging).
4. In syslog mode, drop `timestamp` and `pid` from **non-interactive** output
   only, reusing the existing `_drop_keys_processor()` helper. Interactive/TTY
   output is unchanged.

**Verify:** unit tests for all four resolution branches (monkeypatch
`INVOCATION_ID`/`JOURNAL_STREAM`); assert dropped/kept keys in rendered output.

References: [systemd.exec — `INVOCATION_ID`/`JOURNAL_STREAM`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#%24INVOCATION_ID),
[ADR 0007](../../adr/0007-logfmt-default-for-non-interactive-logging.md).

## Phase 3 — Debug-log file (D2 JSON, D5 always-on, D7 no default path)

In `certinext/cli_support.py`, `setup_logging()`:
1. Add `debug_log_path: Path | None = None`. **No default** (D7) — off unless
   the caller passes one.
2. When set, attach a **second** stdlib handler at `DEBUG` level, **independent
   of `verbose`** (D5): a plain `logging.FileHandler` appending to the path
   (rotation is logrotate's job per D1 — do **not** use `RotatingFileHandler`).
3. That handler's formatter renders **JSON, one object per line** (D2), with
   full `exc_info` (the traceback) embedded as a single escaped string field so
   a multi-line stack trace is one Splunk event. Reuse
   `structlog.processors.format_exc_info` + `JSONRenderer` in the handler's
   `ProcessorFormatter` chain; keep the existing stderr handler exactly as is.
4. Both handlers share the `correlation_id` contextvar, so a journal line and
   its file traceback join on `correlation_id`.
5. The `structlog.make_filtering_bound_logger(level)` wrapper currently drops
   DEBUG events before they reach any handler when `verbose < 3`. **This is the
   crux:** the file must receive DEBUG even at verbosity 0. Set the wrapper
   level to `DEBUG` whenever `debug_log_path` is set, and gate the *stderr*
   handler's visible level separately (handler-level filtering), so the journal
   still shows only INFO+ but the file gets everything. Verify
   `log_caught_exception`'s paired `log.debug(..., exc_info=True)` actually
   lands in the file on an unattended (verbose=0) run.

**Verify:** a test that runs a command which raises, with `debug_log_path` set
and `verbose=0`, asserts the file contains a JSON line with the traceback and
matching `correlation_id`, while stderr stays free of the traceback. `mypy` +
`ruff` clean.

<details>
<summary>Why a separate always-on file instead of just raising journal verbosity</summary>

The whole failure mode (2026-08-03 incident) is that an unattended run logs a
one-liner and the traceback is unreachable without reproducing at `-vvv`. Making
the journal always-DEBUG would flood syslog/Splunk with per-request noise (the
reason httpx et al. are capped at WARNING below `-vvvv`). A dedicated DEBUG file,
rotated by logrotate, keeps the journal clean while guaranteeing the traceback
exists somewhere for the next failure.
</details>

## ADRs to write (during implementation)

These decisions keep applying beyond this change — promote from the master's
D-table to ADRs (per the adr skill), and fill each phase's `implements-adr`:
- **IDEA-008 mechanism** (how shared options attach while preserving
  flag-anywhere) — the design chosen in Phase 1 step 2.
- **Syslog-aware logging + `--log-mode`** (D4) — supersedes/extends the
  IDEA-009 wishlist item; mark IDEA-009 implemented.
- **Debug-log sidecar: JSON, always-on, logrotate-managed, no library default
  path** (D1, D2, D5, D7).

## Documentation to update in this repo

- `README.md` / `docs/` logging section: the new `--log-mode` and
  `--debug-log-path` options and their env vars.
- Changelog / annotated tag message (feedback: tag messages carry the
  changelog).
- Mark [IDEA-008](../../wishlist/IDEA-008-root-level-cli-option-set.md) and
  [IDEA-009](../../wishlist/IDEA-009-syslog-aware-logging.md) as implemented,
  pointing at the new ADRs.
- `AGENTS.md` if the option surface changes materially.

## Hand-off to downstream

After this ships and is tagged, the downstream sub-plans (nm, certinext-zabbix,
ums-certinext-scripts) bump their `certinext` pin to this version and wire the
two new options into their CLIs (Phase 4), then the Ansible role does Phase 5.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 4.8,
> `claude-opus-4-8`) from a conversation with Tod Detre on 2026-08-03. May
> contain inaccuracies or hallucinated details; verify against current sources.
