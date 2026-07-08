# IDEA-006: Optional response caching layer

- **Status:** Proposed (coordinating issue: #12)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

Raised 2026-07-02 during 1.0 refactor planning: should the rewrite include
caching to reduce API calls, especially ahead of the TUI (IDEA-001)?
Decision was to defer the cache but make the refactor *cache-ready*: phase 2
keeps all HTTP through one client choke point so a cache can wrap it later,
and phase 0's corpus capture records **response headers**, which tells us
whether the vendor emits `ETag`/`Last-Modified`/`Cache-Control` at all.
(The one cache the library already has — OAuth token reuse in `auth.py` —
stays, and is unrelated.)

## The idea

An **opt-in, off-by-default** caching layer, shaped by what the phase-0
header evidence shows:

- If the vendor emits validators/cache headers: RFC 9111 caching via
  [hishel](https://hishel.com/) wrapping the httpx transport — near drop-in.
- If not: a small app-level TTL cache for near-static data only (catalog
  products, org lists), never for volatile state (DCV status, order status).
- Hard exclusions either way: `certinext-healthcheck` and the probe suite
  never cache — they exist to observe the live vendor.

## Why not now

- CLIs are one-shot processes: in-memory caching buys nothing, and a disk
  cache of vendor state in an operational cert tool risks acting on stale
  DCV/order status — worse than a slow call. No rate-limit pain observed.
- Correct invalidation couples every mutating verb method
  (`Domain.verify()`, `reinitiate_dcv()`, ...) to the cache — cross-cutting
  complexity in a behavior-preserving rewrite, and it breaks the wire-call
  parity assertions the 1.0 test migration leans on.
- A cache bug is indistinguishable from vendor drift, undermining the
  probe/healthcheck truth story (ADR 0005).
- The TUI's v1 need is app-state (fetch once, filter in memory, explicit
  refresh), not a library cache.

Pick this up when a concrete consumer (TUI, MCP server, or a rate-limited
batch job) measurably suffers, and after the phase-0 header evidence exists.

## Pros

- Snappier TUI/MCP; kinder to a flaky vendor; headroom under rate limits.

## Cons / costs

- Staleness in operational decisions; invalidation complexity; muddies
  live-observation guarantees unless exclusions are airtight.

## Effort

Small (hishel drop-in, *if* the vendor emits caching headers) to medium
(app-level TTL + invalidation rules).

## Open questions & caveats

- Does the vendor emit `ETag`/`Last-Modified`/`Cache-Control`? (Answered by
  the phase-0 corpus header capture.)
- Which data is safe to cache? Catalog: clearly. Domain list: only with
  explicit refresh semantics. DCV/order status: never.

## Next steps

None until phase 0 lands (header evidence) and a consumer demonstrates need.

## References

- [hishel — HTTP caching for httpx](https://hishel.com/)
- [RFC 9111 — HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111)
- Related: IDEA-001 (TUI), IDEA-002 (MCP server); refactor phase 0 (header
  capture), phase 2 (transport seam)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
