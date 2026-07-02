# IDEA-001: Textual TUI for browsing/operating CertiNext

- **Status:** Proposed (coordinating issue: #7)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

Admins today either use the vendor's web interface or juggle eleven CLI
tools. Tod wants a way for a user/admin to browse and operate CertiNext
entirely from the terminal — no web UI. Raised 2026-07-02 while planning the
1.0 pydantic/typer refactor.

## The idea

A [Textual](https://textual.textualize.io/) terminal UI, launched as
`certinext tui` (packaged as an optional extra, e.g. `certinext[tui]`):

- Browse domains with live filtering; drill into DCV status, attempt
  history, expiry.
- Browse orders/certificates and the ledger; download certs.
- Run common operations: DCV verify/reinitiate/method change, an issue-cert
  wizard, a healthcheck dashboard.
- Profile/sandbox switching using the same config/keyring machinery as the
  CLI.

It sits on the 1.0 library's operations layer — the refactor plan's phase 4
deliberately keeps subcommand bodies as thin presentation over library
functions so a TUI (and IDEA-002's MCP server) reuses the same operations
without duplicating logic.

## Why not now

The 1.0 refactor is already maximal scope (full stack swap, ADR 0003); a TUI
would ride on surfaces (models, settings, operations layer) that don't exist
until phases 1–4 land. Revisit after 1.0.0 stable. What would change the
calculus: finishing phase 4, or a concrete admin request for web-UI-free
operation.

## Pros

- Web-UI-free, keyboard-driven, works over SSH.
- Reuses the exact library layer — no second implementation of vendor
  workarounds.

## Cons / costs

- New UI surface to test and maintain; Textual dependency.
- The sync client blocks; Textual needs blocking calls in
  [workers](https://textual.textualize.io/guide/workers/) (fine), or
  IDEA-005's async client (nicer).

## Effort

Medium-large. A read-only browser is a modest first milestone; mutating
flows (issue-cert wizard) are the long tail.

## Open questions & caveats

- Read-only first release, mutating flows later?
- Does Textual's test harness (Pilot) fit our CI?
- Depends on IDEA-005 or worker-thread discipline for responsiveness.
- Responsiveness plan: v1 uses app-state (fetch once, filter in memory,
  explicit refresh) — a library-level cache is IDEA-006 and only if
  app-state proves insufficient.

## Next steps

None until 1.0.0 stable ships (see
`docs/plans/pydantic-typer-refactor/README.md`).

## References

- [Textual docs](https://textual.textualize.io/)
- [Textual workers (blocking calls)](https://textual.textualize.io/guide/workers/)
- Related: IDEA-002 (MCP server), IDEA-005 (async client)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
