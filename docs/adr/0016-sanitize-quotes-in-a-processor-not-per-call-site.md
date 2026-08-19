---
status: accepted
date: 2026-08-19
---

# Strip double quotes in a logfmt processor, not per call site

## Context and problem statement

ADR 0015 substituted single quotes for double quotes so Splunk's automatic
`key=value` extraction could read the `exception=` field. It applied the
substitution inside `format_truncated_traceback`, because a traceback's `File
"..."` lines were the guaranteed source of quotes that prompted the incident.

That fixed the field it was aimed at and left every other field on the same line
exposed. Reviewed against the current code, only `format_truncated_traceback`
sanitizes anything. In `log_caught_exception` itself:

- `fields["error"] = str(exc)` is raw.
- `**context` is raw, and is open-ended — any call site may attach any value.

The exposure is not confined to that helper. `fatal_api_error`
(`log.error(message, error=str(exc))` plus `log.debug("Full response body",
body=exc.body)`), the `log.warning("Ignoring connection settings",
error=str(exc))` in `build_session`, two `message=str(exc)` calls in
`healthcheck.py`, and roughly eight `error=str(exc)` calls in `cli/issue_cert.py`
are all unsanitized. So is the `exception` field that
`structlog.processors.format_exc_info` builds from the paired
`log.debug(event, exc_info=exc)` record when stderr is at DEBUG.

The trigger is realistic rather than theoretical. `CertiNextAPIError.__str__`
falls through to `f"HTTP {self.status_code}: {self.body}"` for a non-dict body,
and a proxy or gateway returning an HTML error page instead of JSON supplies a
body that is wall-to-wall double quotes. The vendor's own `detail`/`title`
strings can carry them too, and a Python dict repr switches to double quotes as
soon as a value contains an apostrophe.

The consequence is the one ADR 0015 already documented: Splunk ends the value at
the first `\"` and parses the rest of the line as further key/value pairs,
corrupting **every** field — `correlation_id` included. The failure destroys
precisely the fields needed to investigate the error that carried the quote.

## Decision drivers

- One escaped quote anywhere on a line damages all of its fields, so partial
  coverage is close to no coverage.
- The exposed surface is open-ended. `**context` cannot be audited field by field
  the way `exception` was, and new call sites are added routinely.
- The debug-log sidecar must stay byte-exact (ADR 0012), so whatever is done
  cannot be global to both output paths.
- JSON output is already correct. JSON escaping is understood by every JSON
  parser, so a fix that also rewrites JSON would lose fidelity for no gain.

## Considered options

- **A `_sanitize_quotes` processor on the logfmt chain** (chosen).
- **Sanitize at each call site.** Rejected: about fifteen edits that must be
  repeated by every future call site, and it cannot cover `**context` in
  principle — the value arrives already built by the caller.
- **Sanitize inside `log_caught_exception` only.** Rejected: it is the busiest
  producer of these fields but not the only one; `fatal_api_error` and the
  `issue_cert` handlers bypass it entirely.

## Decision outcome

Chosen: **enforce the substitution centrally, in a structlog processor
registered on the logfmt stderr chain only.**

- `_sanitize_quotes` rewrites `"` to `'` in every **value** of the event dict.
  Keys are left alone — they are code-defined identifiers, while values carry
  vendor bodies, exception messages and arbitrary caller context.
- A non-string value is rewritten only when its rendered form actually contains a
  quote. This deliberately preserves `LogfmtRenderer`'s own `bool` handling,
  which emits a bare key for `True` and `false` for `False`; coercing every value
  to `str` first would leak Python's `True`/`False` into the log.
- It is appended **after** `format_exc_info`, so that processor's `exception`
  field is covered, and immediately **before** the renderer, so nothing can enter
  the event dict after sanitization.
- It is registered **only when the renderer is `LogfmtRenderer`**. JSON output
  keeps its quotes and its fidelity.
- The interactive `ConsoleRenderer` chain is untouched. It is read by a person at
  a TTY and never reaches Splunk.
- The debug-log sidecar is untouched. It is a separate `ProcessorFormatter` with
  its own processor list, which is what makes this scoping possible at all.
- **ADR 0015's substitution inside `format_truncated_traceback` stays.** It is now
  redundant on this chain, and deliberately so: it is idempotent, and it keeps the
  Splunk-safety guarantee part of that function's own contract for any caller
  that logs its return value outside the chain. A comment on the function says so,
  to stop a future reader removing it on the grounds that the processor covers it.

This **extends** ADR 0015 rather than superseding it. Every decision in 0015 —
no default frame limit, trimming the middle, the sidecar staying byte-exact —
stands unchanged; only the *scope* of the quote substitution widens.

### Consequences

- Good: every field on a logfmt line is now protected, including fields added by
  call sites that do not exist yet.
- Good: the fix is one function rather than fifteen edits, and cannot be
  half-applied.
- Bad / accepted: values on the visible line no longer match their Python
  representation exactly — now true for all fields, not just `exception`. The
  sidecar remains the byte-exact copy and ADR 0012 keeps it host-local, so
  recovering exact text still needs SSH.
- Bad / accepted: a value's own meaningful double quotes are silently rewritten.
  For the affected data — API error bodies and exception messages — the quotes are
  syntax rather than content, so this costs nothing in practice.
- Neutral: ADR 0015's deferred option of moving the sourcetype to JSON
  (`--log-format json` plus `KV_MODE = json`) is unaffected and remains the
  stronger long-term answer. It was not re-weighed here; this ADR reduces the
  urgency rather than closing it off.
- Neutral: the substitution now runs on every line rather than only lines
  carrying a traceback. The fast path is an `in` test per value.

### Confirmation

`tests/test_log_caught_exception.py` covers it. Five tests pin the regression —
quotes in `error`, in `**context`, in the `event` message, in a non-string dict
value, and the realistic `CertiNextAPIError`-with-an-HTML-body case, which also
asserts that `correlation_id` and the fields after the quoted value survive. All
five were confirmed to fail with the processor removed. Three further tests pin
the boundaries: bools keep the renderer's bare-key/`false` form, JSON output
keeps its quotes, and the sidecar keeps its quotes when the visible line is
sanitized.

Assertions test for the absence of `\"` — the escaped *inner* quote that is the
corrupting construct — not for the absence of `"`. `LogfmtRenderer` legitimately
wraps any value containing whitespace in double quotes, so asserting on `"`
alone fails against correct output.

Still not confirmed, as in ADR 0015: that extraction works end to end in Splunk.
That needs a real failure to land on the line.

## Pros and cons of the options

### A processor on the logfmt chain (chosen)
- Good, because coverage is total and automatic for future fields.
- Good, because it can be scoped to one output path, leaving the sidecar
  byte-exact and JSON untouched.
- Good, because it follows the pattern already in the file — `_drop_keys_processor`
  and `_reorder_log_keys_processor` are custom processors on this same chain.
- Bad, because sanitization becomes invisible at the call site; a reader of
  `log.error(...)` cannot see that values are rewritten downstream.

### Sanitize at each call site
- Good, because the transformation is visible where the value is produced.
- Bad, because it cannot cover `**context`, whose values arrive pre-built.
- Bad, because it rots — every new call site must remember, and nothing enforces
  it.

### Sanitize inside `log_caught_exception` only
- Good, because it is the single busiest producer of `error` and context fields.
- Bad, because `fatal_api_error`, `build_session`, `healthcheck` and the
  `issue_cert` handlers all log these fields without going through it.

## More information

- [ADR 0015 — trim the middle, strip double quotes](0015-traceback-trim-the-middle-not-the-head.md) (this ADR extends its quote decision; its truncation decisions stand)
- [ADR 0012 — debug log host-local, console format](0012-debug-log-host-local-console-format.md) (why the sidecar stays byte-exact)
- [ADR 0013 — shared `log_caught_exception` helper](0013-shared-log-caught-exception-helper.md) (the helper whose `error`/`**context` fields were exposed)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md) (why logfmt is the chain that needs this and JSON does not)
- [structlog — writing custom processors](https://www.structlog.org/en/stable/processors.html)
- [structlog — `LogfmtRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.processors.LogfmtRenderer)
- [structlog — `ProcessorFormatter` for stdlib logging](https://www.structlog.org/en/stable/standard-library.html#structlog.stdlib.ProcessorFormatter)
- [Splunk — automatic key/value field extraction](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutfields)
- [Splunk — `props.conf` (`KV_MODE`)](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf)
- [logfmt — the format's original description](https://brandur.org/logfmt)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
