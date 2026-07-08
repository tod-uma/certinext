# IDEA-002: MCP server exposing certinext operations to AI agents

- **Status:** Proposed (coordinating issue: #8)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

Tod wants the library and tools to be as usable by AI assistants as by
humans (2026-07-02, during 1.0 refactor planning). CLIs are usable by agents
but lossy (text parsing, per-invocation auth); the
[Model Context Protocol](https://modelcontextprotocol.io/) is the native way
to hand an assistant a tool surface.

## The idea

A `certinext-mcp` server (optional extra or sibling package) exposing:

- **Read-only tools, enabled by default:** list/search domains, pending
  DCV, domain detail + DCV history, order/certificate status, ledger,
  healthcheck.
- **Mutating tools, explicitly gated** (flag/config allowlist, off by
  default): DCV verify/reinitiate, issue-cert, deactivate.
- Sandbox/prod selection surfaced in every tool result so an agent can't
  confuse environments; same config/keyring machinery as the CLI.

Like IDEA-001, it consumes the 1.0 operations layer (refactor phase 4's
thin-presentation rule) — tools are wrappers, not reimplementations. The
pydantic models double as tool result schemas almost for free.

## Why not now

Needs the 1.0 models/operations layer to exist first; shipping it against
0.3.x dicts would mean building it twice. Revisit after 1.0.0 stable — or
earlier if an internal agent use case (e.g. DCV triage) gets urgent.

## Pros

- Strongest possible "usable by AI" story; schema-validated results instead
  of stdout scraping.
- Gated-mutation design makes the safety posture explicit.

## Cons / costs

- New deployment/runtime surface (stdio server per user vs shared);
  credential handling for agents needs care.
- MCP SDK dependency and protocol churn.

## Effort

Medium. Read-only server over the 1.0 library is small; gating + packaging
+ docs is the real work.

## Open questions & caveats

- stdio-per-user (keyring creds) vs a shared server (its own auth)?
- Which mutating operations are ever appropriate to expose?
- Benefits from IDEA-005 (async client) for concurrent tool calls.

## Next steps

None until 1.0.0 stable. First concrete step then: read-only server with
list-domains/pending-dcv/healthcheck.

## References

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- Related: IDEA-001 (TUI), IDEA-005 (async client)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
