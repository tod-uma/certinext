---
status: accepted
date: 2026-11-24
---

# A binary format that is the only requested output fails the command

## Context and problem statement

[ADR 0001](0001-non-fatal-format-downloads.md) made binary format downloads
non-fatal: a failed DER download or write logs a warning and the command
continues. Its stated justification is that "the primary PEM output is
written by a separate, still-fatal path".

That premise fails when `--der-out` is the only output flag. Then no PEM is
written, the stdout PEM is suppressed, and a failed DER download or write
ended with exit 0 and no certificate file anywhere. An external review
(Codex, R2b finding 9) reported it; the existing test
`test_write_outputs_binary_unwritable_path_warns_and_continues` pinned that
behaviour.

## Considered options

- Exit 1 when DER is the only requested output and it fails.
- Keep ADR 0001 unchanged for every case.

## Decision outcome

Chosen: **exit 1 when DER is the only requested output and it fails.**
Beside any PEM output (`--cert-out`, `--chain-out`, `--fullchain-out`,
`--output`, `--all-formats-out`) a DER failure stays a warning, as ADR 0001
decided. This narrows ADR 0001 to the case its own justification covers; it
does not replace it.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5.5,
> `claude-opus-5-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
