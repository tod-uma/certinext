---
status: accepted
date: 2026-07-22
---

# Default non-interactive log output to logfmt, not JSON; add --log-format to opt back into JSON

## Context and problem statement

`dcv-update`'s cron/systemd output is one JSON object per line, prefixed with
a syslog header (`Jul 22 17:35:23 lv-o-cert-util dcv-update[1988202]: {...}`)
once it reaches Splunk. Splunk was only extracting the syslog-header fields
(`host`, `source`, `pid` via the syslog TA) — none of the JSON body fields
(`level`, `event`, `correlation_id`, `domain`, ...) were showing up as
searchable fields. What should `certinext.cli_support.setup_logging()` emit
for non-interactive (redirected/cron) output, and should this be
configurable per run?

Splunk's automatic field extraction parses `key=value` pairs anywhere in an
event by default (`kv_mode=auto`) regardless of what else is on the line.
Automatic JSON extraction only fires when the *entire* raw event is valid
JSON (or a sourcetype is explicitly configured with `KV_MODE=json`) — and a
syslog-prefixed line never satisfies that, which is why the JSON body was
invisible to Splunk without a sourcetype-specific `props.conf` change. The
requirement going in was explicit: no per-sourcetype Splunk configuration
just for these logs.

An Explore-agent search of `dcv-update`'s log-consuming code confirmed no
other tooling parses these lines (the Zabbix push feature reads the
CertiNext API directly, not the log stream), so the render format was safe
to change. All logged fields across every script built on this shared
`setup_logging()` are flat scalars — no nested objects/lists — so nothing is
lost representing them as `key=value` pairs.

Checked against the actual receiving app: the local `Splunk_TA_nix`
(`Splunk/apps/Splunk_TA_nix/default/props.conf`, `[syslog]` stanza) sets no
`KV_MODE` override for this sourcetype, so it inherits Splunk's `auto`
default rather than disabling extraction — consistent with `key=value`
pairs being extractable with no further Splunk-side configuration.

## Considered options

- Switch the non-interactive structlog renderer from `JSONRenderer` to
  `LogfmtRenderer`, made the new default, with `--log-format json` to opt
  back into the old JSON body.
- Leave the renderer as JSON and add Splunk-side `props.conf`
  (`SEDCMD` to strip the syslog prefix + `KV_MODE=json`) for the affected
  sourcetype.
- Keep JSON as the only, unconfigurable format (status quo).

## Decision outcome

Chosen: **switch the default to logfmt, keep JSON available via
`--log-format json`.** This satisfies "no special Splunk extraction" because
`kv_mode=auto` already parses `key=value` pairs out of the box, syslog
header or not. `structlog.processors.LogfmtRenderer` handles quoting values
with spaces (e.g. the `event` field) correctly, so no hand-rolled formatting
was needed.

The renderer switch lives in the one shared `certinext.cli_support.setup_logging()`
used by every CLI built on it (certinext's own bundled CLI, nm, and every
downstream script: `ums-certinext-scripts`, `certinext-zabbix`), so it
changed non-interactive log output for all of them at once, not just
`dcv-update`.

### Consequences

- Good: Splunk (and any other `key=value`-aware log aggregator) auto-extracts
  every logged field with zero sourcetype configuration.
- Good: `--log-format json` preserves the old behavior for any consumer that
  still wants a JSON body, without a code change on their end.
- Bad: this is a default-behavior change across 4 repos sharing this code
  (`certinext`, `nm`, `ums-certinext-scripts`, `certinext-zabbix`); any script
  or dashboard that assumed JSON log lines must add `--log-format json`.
- Bad: rolling the new `--log-format` flag out to `certinext`'s bundled CLI
  meant repeating it across all 10 command files individually — the CLI has
  no shared root-level option set, only per-command/per-group declarations
  plus a custom argv-hoisting shim (ADR 0004). Tracked as
  [IDEA-008](../wishlist/IDEA-008-root-level-cli-option-set.md).
- Neutral: this only removes the syslog-prefix obstacle to auto-extraction —
  it would not help on a sourcetype whose `props.conf` sets `KV_MODE=none`
  (which disables both JSON and `key=value` auto-extraction). Confirmed this
  doesn't apply here: the local `Splunk_TA_nix` app's `[syslog]` stanza sets
  no `KV_MODE` override.

## Pros and cons of the options

### Switch to logfmt, JSON opt-in (chosen)

- Good, because it works with Splunk's default `kv_mode=auto` with no
  per-sourcetype configuration.
- Good, because `LogfmtRenderer` is a maintained structlog processor, not
  hand-rolled quoting logic.
- Bad, because it's a default-behavior change for every consumer of the
  shared `setup_logging()`, across 4 repos.

### Splunk-side props.conf change (KV_MODE=json + SEDCMD)

- Good, because it requires no code change.
- Bad, because it is exactly the "special field extraction for just these
  logs" the requirement ruled out, and it would need to be repeated per
  sourcetype/per Splunk environment (sandbox, prod, any future indexer).

### Keep JSON only (status quo)

- Bad, because the original problem (fields invisible in Splunk) persists.

## More information

- [structlog — `LogfmtRenderer` API reference](https://www.structlog.org/en/stable/api.html#structlog.processors.LogfmtRenderer)
- [Splunk docs — Configure automatic key-value field extraction](https://docs.splunk.com/Documentation/Splunk/9.4.2/Knowledge/Automatickey-valuefieldextractionsatsearch-time)
- [ADR 0004 — single CLI app with alias entry points](0004-single-cli-app-with-alias-entry-points.md) (the argv-hoisting shim this decision had to extend)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Sonnet 5,
> `claude-sonnet-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
