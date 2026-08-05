---
status: accepted
date: 2026-08-05
---

# Attach a truncated traceback to the operational log line, at top-level handlers only

## Context and problem statement

`log_caught_exception()` deliberately withholds the traceback from the line
operators actually see. It emits a concise `error`/`error_type`/`hint` line at
the requested level, then pairs it with `log.debug(..., exc_info=True)` — which
lands only in the debug-log sidecar (ADR 0011), never in the journal.

Consequence: the one-line error text reaches Splunk, the stack does not.
Because ADR 0012 also settled that the sidecar is host-local and deliberately
not ingested, triage of any unattended failure requires SSH to the host. The
proposal was to add the formatted traceback to the operational line as a
quoted `exception=` logfmt field, correlated to the run by `correlation_id`,
for zero aggregator-side configuration.

Two things were checked before deciding, because both were assumed rather than
verified in the original proposal:

- **The mechanism already exists.** `structlog.processors.format_exc_info` is
  already in the stderr chain, and structlog 25.5.0's `LogfmtRenderer`
  unconditionally escapes newlines (`value.replace("\n", "\\n")`). Passing
  `exc_info=True` on the operational call already produces a correctly quoted,
  single-line `exception="Traceback...\n..."` field. No escaping processor is
  needed, and no risk of journald splitting the message on real newlines.
- **The helper's existing restraint is load-bearing.** Its docstring records
  the reason: *"Cron-fed logs must never carry a raw traceback — one bad run can
  dump one per domain/attempt, turning a syslog alert into a multi-KB stack
  dump."* That is not hypothetical: `zabbix_push_cli.py` calls it **inside a
  per-domain loop**, so one systemic failure emits one stack per domain.

  How big a single stack gets depends on the recursion's *shape*, which is worth
  recording because the intuitive answer is wrong. CPython collapses consecutive
  *identical* frames into `[Previous line repeated N more times]`, so a direct
  self-call recursing to the 1000-frame limit formats to only ~431 bytes.
  A cycle through two alternating frames does **not** collapse: measured at
  ~50KB by depth 300, six times over rsyslog's 8K cap. So the cap is a real
  hazard for some recursion shapes and a non-issue for others, and the
  per-domain multiplication is the more reliable driver either way.

So: how does an unattended run get its stack into the journal without
reproducing the flood that the current design exists to prevent?

## Decision drivers

- Triage should not require host access for the common case.
- rsyslog's default `$MaxMessageSize` is 8K, and it truncates the *tail* —
  which is where the exception and innermost frames are.
- A per-domain loop multiplies whatever one call emits.
- ADR 0011 already rejected "raise the journal's default level to DEBUG" for
  flooding; an unconditional `exception=` on every error line is a narrower
  version of that same rejected option.

## Considered options

- **Opt-in per call site, truncated** (chosen): a keyword argument, enabled
  only at handlers that can fire at most once per run, with the traceback
  trimmed to its last frames before it is logged.
- **Unconditional `exception=` on every error line** (the original proposal).
  Rejected: floods the journal from the per-domain loop, blows the 8K cap, and
  the surviving fragment is the least useful part.
- **Leave it as-is and rely on the sidecar.** Rejected: ADR 0012 made the
  sidecar host-local, so this keeps SSH on the critical path for every error.

## Decision outcome

Chosen: **an opt-in `include_traceback` argument on `log_caught_exception`,
default off, with the traceback truncated to its last frames.**

- **Default off.** Every existing call keeps today's behaviour; nothing changes
  for the per-domain loop.
- **Enabled only at top-level handlers** — the `except` branches wrapping a
  whole run, which fire at most once. In `certinext-zabbix` that is the two
  outermost branches in `zabbix_push_cli.py`; the per-domain calls stay off.
- **Truncate in Python, not in rsyslog**, and bound it *twice*. Letting rsyslog
  do the cutting at 8K discards the tail, which is exactly the innermost frames
  and the exception itself.
  - `traceback.format_exception(..., limit=-10)` keeps the innermost 10 frames.
  - A **character cap** (`TRACEBACK_BYTE_LIMIT`, 4000) then bounds the whole
    string, keeping the end. This is the bound that actually holds, because
    `limit` is applied to *each* traceback in a `__cause__`/`__context__` chain
    — so the frame limit multiplies with chain length rather than capping the
    total. Measured on a real `httpx.ConnectError` (chained from `httpcore`),
    the 10-frame limit alone trimmed 4715 characters to 4570, about 3%; since
    essentially every httpx failure is chained, that is the common path, not an
    edge case. With the character cap the same traceback renders as a
    4316-character logfmt line — escaping inflates it about 1.08x — leaving
    roughly half the 8K budget spare.
- **The paired DEBUG record is unchanged**, so the sidecar keeps the full,
  untruncated traceback. The journal gets a triage-grade summary; the file
  stays the full-fidelity copy.
- **`hint` is dropped when the traceback is attached**, since "re-run with
  -vvv" is not the next step when the stack is already on the line.

### Consequences

- Good: the common triage question — *what blew up?* — is answerable from the
  aggregator, with no monitor stanza, sourcetype, or app-side configuration,
  because logfmt `key=value` extraction already applies to these lines.
- Good: joins to the sidecar on `correlation_id` when the last 10 frames
  aren't enough.
- Bad / accepted: a deep traceback still costs ~1-2KB on one journal line per
  failed run. Bounded by truncation and by firing once per run.
- Bad / accepted: this narrows, but does not eliminate, the concern ADR 0011
  raised about journal volume. The mitigation is entirely a call-site
  discipline — nothing in the helper prevents a future caller from enabling it
  inside a loop.
- Neutral: does not change what the debug sidecar contains or where it goes;
  ADR 0012 stands.

### Confirmation

`index=linux process=certinext-zabbix-push exception=*` returns rows after a
failed run, and the per-domain warning lines from the same run carry no
`exception` field. `tag=error` / `eventtype=nix_errors` are applied
automatically to `level=error` rows, so no aggregator-side config is needed to
find them.

## Pros and cons of the options

### Opt-in per call site, truncated (chosen)
- Good, because the flood risk is addressed structurally: the loop call sites
  simply don't pass the flag.
- Good, because truncating in Python keeps the useful end of the stack.
- Bad, because correctness depends on call-site discipline, which no test
  enforces.

### Unconditional on every error line
- Good, because there is nothing to remember at call sites.
- Bad, because the per-domain loop turns one failure into N stack dumps.
- Bad, because rsyslog truncation keeps the least informative part.

### Rely on the sidecar only (status quo)
- Good, because the journal stays minimal.
- Bad, because ADR 0012 made the sidecar host-local, so every error needs SSH.

## More information

- [ADR 0011 — always-on debug-log sidecar](0011-always-on-json-debug-log-sidecar.md) (the paired DEBUG record, and the rejected "journal at DEBUG" option)
- [ADR 0012 — debug log host-local, console format](0012-debug-log-host-local-console-format.md) (why the sidecar alone is no longer sufficient for triage)
- [ADR 0013 — shared `log_caught_exception` helper](0013-shared-log-caught-exception-helper.md) (why this change lands in one place)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md) (why `exception=` extracts with no config)
- [`traceback.format_exception` — negative `limit` keeps the last frames](https://docs.python.org/3/library/traceback.html#traceback.format_exception)
- [structlog — `LogfmtRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.processors.LogfmtRenderer)
- [rsyslog — `$MaxMessageSize` global directive](https://www.rsyslog.com/doc/configuration/global/index.html)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
