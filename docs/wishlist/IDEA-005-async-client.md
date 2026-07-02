# IDEA-005: Async client variant (httpx.AsyncClient)

- **Status:** Proposed (coordinating issue: #11)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

The 1.0 refactor moves transport to httpx (ADR 0003) but keeps the client
synchronous. A future TUI (IDEA-001) and MCP server (IDEA-002) are
concurrency-friendly consumers where an async client would shine. Raised
2026-07-02.

## The idea

An `AsyncCertiNextSession`/`AsyncCertiNextClient` built on
[`httpx.AsyncClient`](https://www.python-httpx.org/async/), mirroring the
sync accessor surface. Because 1.0 already standardizes on httpx, the
transport layer is the *same library* — the work is the parallel accessor
surface, not a second HTTP stack.

## Why not now

The most speculative of the current ideas: Textual can run the sync client
in [worker threads](https://textual.textualize.io/guide/workers/) and MCP
tool calls are mostly short, so neither consumer strictly needs it.
Maintaining dual sync/async surfaces roughly doubles the accessor test
matrix. Revisit only when a concrete consumer measurably suffers under the
threaded-sync approach.

## Pros

- Natural fit for TUI/MCP concurrency; httpx makes it cheap at the
  transport level.

## Cons / costs

- Dual surface maintenance forever; sync/async drift risk (would need
  either code generation or a shared core with thin sync/async shells).

## Effort

Medium — the accessor/model layer is the bulk, and it must be kept from
drifting.

## Open questions & caveats

- Shared-core pattern vs generated async variant?
- Does the OrderWorkflow state machine need an async twin, or is it
  CLI-only?

## Next steps

None. Gate on a real performance complaint from IDEA-001/002.

## References

- [httpx async support](https://www.python-httpx.org/async/)
- Related: IDEA-001 (TUI), IDEA-002 (MCP server)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
