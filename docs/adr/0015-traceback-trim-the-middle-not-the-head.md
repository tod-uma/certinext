---
status: accepted
date: 2026-08-05
---

# Trim an over-long traceback from the middle, and strip its double quotes

## Context and problem statement

ADR 0014, accepted earlier the same day, bounded the `exception=` field on the
operational log line two ways: `traceback.format_exception(..., limit=-10)` to
keep the innermost ten frames, then a 4000-character cap keeping the *end*.
Both trims discard the head on the reasoning that the tail — the exception line
and the frames nearest the fault — is the part worth having.

A real failure the same afternoon showed that reasoning does not hold for the
one exception shape ADR 0011 was originally written for. A
`certinext-zabbix-push` sandbox run died with `RecursionError`, and the journal
line's `exception=` field contained exactly ten frames — all of them
`logging` and `structlog` internals, ending at `structlog.dev._pad`. Nothing in
it named the fault. The actual cause, recovered only from the debug-log sidecar
over SSH, was a 965-frame self-recursion in `zabbix_utils`'
`Sender.__send_to_cluster` following a Zabbix proxy-group redirect that pointed
at itself.

The error is that on a deep stack the innermost frames are not the fault — they
are whatever incidental code happened to occupy frame ~1000 and trip the limit.
Here that was structlog's own log formatter, called *by* the failing library.
ADR 0014 reasoned carefully about how *big* a recursive traceback gets and not
at all about *which* frames its budget would buy.

Two measurements settle it:

- The complete traceback for that incident was **3971 characters** — already
  inside `TRACEBACK_BYTE_LIMIT`. CPython's collapsing of consecutive identical
  frames into `[Previous line repeated N more times]`, which ADR 0014 documented,
  is what keeps it small. So the frame limit bought no size reduction on the
  exact case it most damaged.
- ADR 0014 measured the frame limit trimming a chained `httpx.ConnectError` by
  about 3%. That was already recorded as marginal; the character cap was
  identified there as "the bound that actually holds".

A second, independent problem surfaced from the same log line. Splunk's
automatic `key=value` extraction does not understand a backslash-escaped quote
inside a quoted value. `LogfmtRenderer` correctly emits
`exception="...File \"/usr/lib64/...\", line 1706..."`, but Splunk ends the
field at that first `\"` and parses the remainder as further key/value pairs —
corrupting **every** field on the line, not just this one. ADR 0014's
confirmation criterion (`exception=*` returns rows) did not hold in practice.

## Decision drivers

- Triage should not require host access for the common case — unchanged from
  ADR 0014, and precisely what failed here.
- The frame limit's stated job, bounding size, is already done by the character
  cap plus CPython's frame collapsing.
- The head and the tail of a stack answer different questions: which code path
  was running, versus what finally raised.
- The line has to survive Splunk's KV extractor, not only rsyslog's byte cap.
  A field that corrupts its neighbours is worse than an absent field.

## Considered options

For the frame budget:

- **No default frame limit; trim the middle when over budget** (chosen).
- **Keep the innermost-frames limit** (status quo from ADR 0014). Rejected: on a
  deep stack the innermost frames are the wrong ones at *any* limit, and the
  size problem the limit addressed does not exist once frame collapsing is
  accounted for.

For the quotes:

- **Replace `"` with `'` in the helper** (chosen).
- **Switch the sourcetype to JSON** (`--log-format json` plus `KV_MODE = json`).
  Not rejected on merit — Splunk parses JSON natively, escapes included, and this
  is the stronger long-term answer. Deferred because it changes the shape of
  every log line and needs the Ansible deployment and the Splunk app changed in
  lockstep, which is a larger piece of work than the failure warranted.
- **`KV_MODE = none` with explicit `EXTRACT-` regexes.** Rejected: the most
  work and the most brittle, with no advantage over the JSON option.

## Decision outcome

Chosen: **bound the visible traceback by characters only, trimming from the
middle so both ends survive, and substitute single quotes for double quotes.**

- **`limit` defaults to `None`.** No frame limit is applied. The argument is
  retained as a passthrough to `traceback.format_exception`, so a caller can
  still ask for one; its per-chain-link multiplication is documented rather than
  relied on.
- **The character cap trims the middle.** `_TRACEBACK_HEAD_FRACTION` (0.35)
  splits the budget, weighted toward the tail because the final exception line
  is the single most useful fragment and the head needs only a few frames to
  establish the code path. Both cuts snap to line boundaries so neither end is a
  half-rendered frame, and the elision marker sits between them on its own line.
- **Double quotes become single quotes.** Applied to the visible line only.
- **The paired DEBUG record is unchanged** — the sidecar keeps the full,
  byte-exact traceback, quotes included. The substitution is a transport
  concession, not a change to the record of what failed.

### Consequences

- Good: a deep-recursion journal line now names both the call site and the raise
  site. Replayed against the real incident, the whole 3971-character traceback
  survives untrimmed and renders as a 4046-character logfmt value — inside
  rsyslog's 8K cap.
- Good: every field on the line extracts in Splunk again, with no
  aggregator-side configuration.
- Bad / accepted: the visible traceback is no longer byte-identical to Python's
  output. The sidecar is the byte-exact copy, and ADR 0012 keeps it host-local,
  so recovering exact text still needs SSH.
- Bad / accepted: the middle is genuinely lost for a traceback that exceeds the
  budget. That requires a recursion shape CPython cannot collapse — alternating
  frames — which ADR 0014 measured at ~50KB by depth 300.
- Neutral: ADR 0014's substantive decision stands. `include_traceback` is still
  opt-in and still belongs only at handlers that fire at most once per run.

### Confirmation

`tests/test_log_caught_exception.py` pins all three behaviours: a
directly-recursive 900-frame stack fits whole and contains both `_caught` and
`_raise_deeply`; an alternating-frame stack exceeds the budget and comes back
with the head, the elision marker and the exception line; and the output
contains no double quotes while the sidecar's copy still does.

Not yet confirmed: that `exception=*` extraction now works end to end in
Splunk. That needs a real failure to land on the line, and the incident that
prompted this was resolved on the Zabbix side. Check it on the next one.

## Pros and cons of the options

### No default frame limit; trim the middle (chosen)
- Good, because the two questions a stack has to answer — which path, what
  raised — are both answerable from one line.
- Good, because it removes a mechanism whose measured benefit was ~3% and whose
  worst case was total loss of the diagnosis.
- Bad, because a non-collapsing deep recursion now loses its middle rather than
  its head, so a repeated-frame count may be the only evidence of depth.

### Keep the innermost-frames limit
- Good, because the exception line and raise site are guaranteed present.
- Bad, because on the deep-stack case it guarantees *only* those, and they may
  be unrelated to the fault.

### Replace double quotes (chosen)
- Good, because it needs no Splunk-side change and fixes every repo using the
  helper at once.
- Good, because frame lines stay readable — `File '/usr/lib64/...'`.
- Bad, because the visible text no longer matches Python's output exactly.

### Switch the sourcetype to JSON
- Good, because Splunk parses it natively and no substitution is needed.
- Bad, because it changes every line's shape and needs coordinated Ansible and
  Splunk app changes.

### `KV_MODE = none` with explicit extractions
- Good, because it leaves the log format untouched.
- Bad, because hand-written regexes per field are brittle and must track the
  field set.

## More information

- [ADR 0014 — traceback on the operational log line](0014-traceback-on-the-operational-log-line.md) (whose truncation mechanics this replaces; its opt-in decision stands)
- [ADR 0011 — always-on debug-log sidecar](0011-always-on-json-debug-log-sidecar.md) (the paired DEBUG record; a `RecursionError` was the originating incident there too)
- [ADR 0012 — debug log host-local, console format](0012-debug-log-host-local-console-format.md) (why the sidecar alone doesn't answer triage)
- [ADR 0007 — logfmt default for non-interactive logging](0007-logfmt-default-for-non-interactive-logging.md) (the `exception=` field's rendering, and the "extracts with no config" claim this ADR qualifies)
- [`traceback.format_exception` — the `limit` argument](https://docs.python.org/3/library/traceback.html#traceback.format_exception)
- [CPython — recursive-call collapsing in `StackSummary.format`](https://docs.python.org/3/library/traceback.html#traceback.StackSummary.format)
- [Splunk — automatic key/value field extraction](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutfields)
- [Splunk — `props.conf` (`KV_MODE`)](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Propsconf)
- [structlog — `LogfmtRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.processors.LogfmtRenderer)
- [rsyslog — `$MaxMessageSize` global directive](https://www.rsyslog.com/doc/configuration/global/index.html)
- [`zabbix_utils` — Zabbix's official Python library (the unbounded redirect recursion)](https://github.com/zabbix/python-zabbix-utils)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
