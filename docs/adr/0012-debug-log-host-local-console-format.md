---
status: accepted
date: 2026-08-04
---

# Keep the debug-log sidecar out of Splunk; render it with `ConsoleRenderer`, format configurable

Supersedes **D2 only** of
[ADR 0011](0011-always-on-json-debug-log-sidecar.md). That ADR's D1
(logrotate-managed rotation), D5 (always-on, independent of `--verbose`), and
D7 (no library default path) remain in force and are not re-litigated here.

## Context and problem statement

ADR 0011's D2 chose JSON-lines for the debug sidecar with an explicitly
Splunk-shaped justification: a multi-line traceback embeds as a single escaped
`exception` string so it's *"one Splunk event with no
`LINE_BREAKER`/`SHOULD_LINEMERGE` tuning."*

That premise no longer holds. `/var/log/certinext-*/debug.log` is being
blacklisted from ingestion in `Splunk_TA_nix/local/inputs.conf`: JSON behind a
syslog header does not field-extract under the `syslog` sourcetype, and a
learned sourcetype line-merges it into mangled blobs. So the file's only
consumer is a human reading it over SSH — the exact reader JSON serves worst,
because an escaped multi-line traceback renders as one unreadable line.

Two questions, taken together: should the file be ingested at all, and what
format serves the reader it actually has?

## Decision drivers

- The file's only consumer is a person on an SSH session with `less`/`grep`.
- Getting a readable traceback is the reason the file exists at all.
- DEBUG-level volume (httpx per-request lines, every 15 minutes, indefinitely)
  weighed against how rarely the file is read.
- Reversibility, if ingesting it is ever revisited.

## Considered options

**Ingestion:** ingest the file into Splunk, or leave it host-local
(status quo, already blacklisted).

**Format:** JSON-lines (status quo, ADR 0011 D2), logfmt, or
`structlog.dev.ConsoleRenderer`.

## Decision outcome

Chosen: **leave the file host-local, and render it with `ConsoleRenderer`
(colors off) by default, with the format configurable and JSON retained.**

- **Non-ingestion is deliberate, not incidental.** The blacklist stands. The
  trade is DEBUG volume against read frequency, and the volume loses. Note
  this is *not* justified by "the traceback is covered elsewhere" — the file's
  distinctive value is the DEBUG event stream *preceding* a failure, which
  nothing else captures.
- **Format:** `ConsoleRenderer` with `colors=False` passed explicitly — the
  file is not a TTY and ANSI escapes must not be relied on being
  autodetected away. Real newlines are the only thing that makes a stack
  trace readable; verified this session, `LogfmtRenderer` escapes `\n` to a
  literal `\n`, so logfmt would be unreadable *and* unparseable — worst of
  both, rejected.
- **Configurability:** a separate enum and `setup_logging()` parameter
  (e.g. `debug_log_format`), not a widened `LogFormat`. The two streams have
  different consumers and different correct defaults (stderr → logfmt for
  machines per ADR 0007; debug file → console for a human), and sharing one
  enum leaks every future value into the other stream's help text, which
  ADR 0007 deliberately narrowed.
- **No CLI flag for now.** A `--debug-log-format` option across four CLIs is
  surface that probably goes unused. If operators need the knob, add a
  per-repo env var alongside the path they already resolve that way
  (`CERTINEXT_ZABBIX_DEBUG_LOG_FORMAT`), consistent with ADR 0011's D7.

### Consequences

- Good: a traceback reads as actual frames instead of one escaped line.
- Good: the debug file now looks exactly like `-vvv` on a terminal, collapsing
  three render formats to two. This pays back part of ADR 0011's accepted
  *"two logging outputs to reason about"* cost.
- Good: no DEBUG-volume license cost in Splunk.
- Good: JSON stays selectable, so revisiting ingestion doesn't require
  re-litigating this decision.
- **Bad / accepted: logrotate retention is now the entire forensic window.**
  This is the load-bearing consequence. The incident that motivated ADR 0011
  ran undetected for 6-7 days, so a retention period near that length
  discards the evidence just as someone starts looking. The window must be
  sized deliberately against that detection lag rather than inherited from a
  template default; the number belongs to the Ansible role that deploys the
  rotation.
- Bad / accepted: the pre-failure DEBUG stream stays host-local — no retention
  beyond logrotate, no cross-host correlation, and it is lost if a host is
  reimaged.
- Bad / accepted: `compress` means `zless`/`zgrep` for anything but the current
  file, which cuts against the readability this ADR is buying;
  `delaycompress` at least keeps `.1` plain.
- Bad / accepted: migration cost across three repos — three tests that parse
  the file as JSON (`certinext`, `nm`, `ums-certinext-scripts`), the `jq`
  recipe in `nm`'s README, and the deployment docs in both script repos.
- Neutral: whether the operational journal line should carry a truncated
  `exception=` field is a **separate, still-open decision** about a different
  stream. It can be rejected without invalidating this ADR.

### Confirmation

`debug.log` opened in `less` on a deployed host shows multi-line tracebacks
with no ANSI escapes; the `Splunk_TA_nix` blacklist remains in place; JSON is
still selectable via the new parameter.

## Pros and cons of the options

### `ConsoleRenderer` (chosen)
- Good, because tracebacks render as real multi-line frames — the only option
  that fixes the actual complaint.
- Good, because it is already the interactive renderer, so the wiring is
  proven and operators read one format instead of two.
- Bad, because the file is no longer machine-parseable without work.
- Caveat: if `rich` is present in the deployed venv, `ConsoleRenderer` may
  hand tracebacks to rich's formatter — wide, box-drawn output that reads
  worse in `less`. Verify on the target host and pin `exception_formatter` if
  so.

### JSON-lines (status quo, ADR 0011 D2)
- Good, because parseable, and ready if ingestion is ever turned on.
- Bad, because the traceback is one escaped line, needing `jq -r '.exception'`
  to be readable at all.
- Bad, because its stated justification was Splunk ingestion that isn't
  happening.

### logfmt
- Bad, because `LogfmtRenderer` escapes newlines to literal `\n`, so the
  traceback is just as unreadable as JSON.
- Bad, because it gives up JSON's parseability without buying readability.

## More information

- [ADR 0011 — always-on JSON debug-log sidecar](0011-always-on-json-debug-log-sidecar.md) (D2 superseded here; D1/D5/D7 still in force)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md) (why the stderr stream's option surface stays narrow)
- [ADR 0010 — log-mode tri-state for syslog-aware output](0010-log-mode-tri-state-for-syslog-aware-output.md)
- [structlog — `ConsoleRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.dev.ConsoleRenderer)
- [structlog — `LogfmtRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.processors.LogfmtRenderer)
- [structlog — console output & exception formatting](https://www.structlog.org/en/stable/console-output.html)
- [logrotate(8) man page](https://man7.org/linux/man-pages/man8/logrotate.8.html)
- [Splunk — props.conf reference (`KV_MODE`, sourcetype field extraction)](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
