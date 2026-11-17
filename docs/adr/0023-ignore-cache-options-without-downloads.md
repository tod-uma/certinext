---
status: accepted
date: 2026-11-17
---

# Ignore cache options when no certificates are downloaded

## Context and problem statement

The archived replacement-report cache plan rejected `--cache` without
`--inspect` to avoid silently ignoring an option. That rule also blocked
report-field lookups and ordinary listings when a shared wrapper supplied
cache options, even though those commands download no certificates.

## Considered options

- Reject cache options when downloads are off, as the archived plan specified.
- Accept them with an operator notice and leave the cache disabled.

## Decision outcome

Chosen: accept cache options with a structured warning when downloads are off.
This supersedes the archived plan's rejection rule and the unconditional
"implies cache" wording in [ADR 0022](0022-share-certificate-download-cache-for-lookup.md).
It applies to `replacement-report` without `--inspect`, `list-certificates`
without `--sans`, and `lookup-certificate` for non-scanning fields. The notice
also applies to explicit `--no-cache`, as requested, even though it can recur
in scheduled wrappers. Structured logging lets operators filter or route it.

The unused options do not create or validate a cache directory. When downloads
are enabled, `--no-cache` still conflicts with an implied cache flag, and a
cache directory naming a file remains an error. Parser-level option validation
still applies regardless of whether downloads are enabled.

## More information

- [ADR 0022](0022-share-certificate-download-cache-for-lookup.md)
- [structlog documentation](https://www.structlog.org/en/stable/)

---
> **AI-assistant disclaimer:** Drafted by Codex (GPT-6) from a conversation with
> Tod Detre. May contain inaccuracies; verify specifics against current sources
> before relying on them.
