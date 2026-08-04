---
status: accepted
date: 2026-08-04
---

# Always-on JSON debug-log sidecar file, independent of `--verbose`, no library default path

## Context and problem statement

On 2026-08-03 `certinext-zabbix`'s systemd units failed with
`event="maximum recursion depth exceeded while decoding a JSON object..."`
and nothing else — no traceback, no exception type. The `RecursionError` was
caught by a broad `except (RuntimeError, CertiNextAPIError)` branch that
logged only `str(exc)`; the paired `log.debug(..., exc_info=True)` call that
would have shown the real traceback is dropped by
`structlog.make_filtering_bound_logger()` before it reaches any handler
unless the run is at `-vvv` — impossible for an unattended systemd timer.
This is a live, ongoing failure mode: the prod push had sent zero data for
6-7 days at the time this was diagnosed (see
`docs/plans/observability-logging/README.md`'s Origin section). What should
give an unattended run a durable, ingestible traceback without flooding the
normal journal/Splunk stream?

## Considered options

- **A dedicated always-on JSON-lines debug file, off by default** (chosen):
  a second stdlib handler at DEBUG level, attached only when a path is
  configured, writing one JSON object per line independent of `--verbose`.
- **Raise the journal's default level to DEBUG.** Rejected: floods
  syslog/Splunk with per-request noise — the same reason httpx/httpcore are
  already capped at WARNING below `-vvvv` — trading one problem for a worse
  one.
- **Keep JSON as the only, unconfigurable debug destination (status quo).**
  Rejected: the original problem (unattended failures losing their
  traceback) persists.

## Decision outcome

Chosen: **a second, always-on JSON-lines handler, gated only by whether a
path is configured — never by `-v`.** Settled decisions (from
`docs/plans/observability-logging/README.md` D1, D2, D5, D7):

- **D2 — format:** JSON, one object per line. A multi-line traceback embeds
  as a single escaped `exception` string field (via
  `structlog.processors.format_exc_info` in the handler's own
  `ProcessorFormatter` chain) so it's one Splunk event with no
  `LINE_BREAKER`/`SHOULD_LINEMERGE` tuning. Operational (stderr) logs keep
  logfmt by default (ADR 0007) — this is a separate stream, not a mode
  switch on the existing one.
- **D5 — always-on:** the file handler is DEBUG-level and independent of
  `--verbose`. The crux: `structlog.make_filtering_bound_logger()` normally
  drops DEBUG calls before any handler sees them below `-vvv`, so
  `setup_logging()` sets the *wrapper* level to DEBUG whenever
  `debug_log_path` is set (opening the gate for every handler), then caps
  the stderr handler specifically at the verbosity-derived level via
  `Handler.setLevel()` — handler-level filtering, not logger-level — so the
  journal stays exactly as concise as before while the file gets everything.
- **D1 — rotation:** logrotate, managed by the Ansible role that deploys
  each script — not `logging.handlers.RotatingFileHandler`. Oneshot timers
  reopen the file each run, so plain rotation needs no `copytruncate`
  handling.
- **D7 — no library default path:** `debug_log_path: Path | None = None` on
  `certinext.cli_support.setup_logging()`; off unless a caller passes one. A
  shared library must not invent a host filesystem location — each
  downstream repo owns its own env var and path (`CERTINEXT_ZABBIX_DEBUG_LOG`,
  `CERTINEXT_SCRIPTS_DEBUG_LOG`, `NM_DEBUG_LOG`, `CERTINEXT_DEBUG_LOG` for
  `certinext`'s own bundled CLI, default off since that CLI is mostly
  interactive).

Both the stderr and debug-file handlers share the same `correlation_id`
contextvar (via `structlog.contextvars.merge_contextvars` in both pre-chains),
so a concise journal line and its full-traceback file entry join on
`correlation_id`.

### Consequences

- Good: an unattended run's traceback is never lost, without touching what
  operators see in the journal at default verbosity.
- Good: Splunk-ready with zero per-sourcetype configuration once ingesting
  the file, consistent with ADR 0007's constraint (no bespoke extraction
  config).
- Bad / accepted: two logging outputs to reason about instead of one — a
  reader has to know the debug file exists to find the traceback. Documented
  per-repo in each downstream sub-plan and the deployment docs.
- Bad / accepted: `nm`'s independent `cli_support.py` copy needs the same
  handler wiring by hand (D6) — no shared module between the two repos.
- Neutral: does not fix the suspected root cause (`zabbix_utils`'s unbounded
  proxy-group-redirect recursion) — this is purely an observability change;
  the debug log is what will let the next failure be diagnosed with an
  actual traceback instead of a bare `RecursionError` string.

## More information

- `docs/plans/observability-logging/README.md` (decisions D1, D2, D5, D7; Origin section)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md)
- [ADR 0009 — root callback for shared CLI options](0009-root-callback-for-shared-cli-options.md) (the mechanism `--debug-log-path` is wired through)
- [ADR 0010 — log-mode tri-state for syslog-aware output](0010-log-mode-tri-state-for-syslog-aware-output.md) (the sibling flag added alongside this one)
- [structlog — processors & filtering bound logger](https://www.structlog.org/en/stable/api.html)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
