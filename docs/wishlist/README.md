# Wishlist

Deferred ideas — things we've decided *not to do yet* but don't want to lose.
Each idea records why it was deferred and what would make it worth picking
up. **Consult this index when making code changes and improvements**: prefer
designs that keep parked ideas cheap rather than foreclosing them, and note
in the MR when a change materially advances or blocks one. Ideas are living documents: update status, reasoning, and the Updated
date freely. When one graduates, it becomes (or links to) an ADR in
[docs/adr/](../adr/); ADRs are immutable, ideas are not.

**Statuses:** Proposed → Exploring → Accepted → ADR NNNN | Rejected |
Superseded by IDEA-NNN. While an idea is Proposed/Exploring it has a
coordinating GitLab issue (per
[ADR 0002](../adr/0002-track-vendor-api-bugs-in-gitlab-issues.md)'s
issues-for-coordination convention); the issue closes when the idea reaches
a terminal state. Numbering is sequential and never reused.

## Ideas

| ID | Idea | Status | Issue | Created |
| --- | --- | --- | --- | --- |
| [IDEA-001](IDEA-001-textual-tui.md) | Textual TUI for browsing/operating CertiNext | Proposed | #7 | 2026-07-02 |
| [IDEA-002](IDEA-002-mcp-server.md) | MCP server exposing certinext operations to AI agents | Proposed | #8 | 2026-07-02 |
| [IDEA-003](IDEA-003-docs-site-llms.md) | Docs site (mkdocs + API reference) with llms-full.txt | Proposed | #9 | 2026-07-02 |
| [IDEA-004](IDEA-004-doc-example-testing.md) | Execute README/docs code examples in CI | Proposed | #10 | 2026-07-02 |
| [IDEA-005](IDEA-005-async-client.md) | Async client variant (httpx.AsyncClient) | Proposed | #11 | 2026-07-02 |
| [IDEA-006](IDEA-006-response-caching.md) | Optional response caching layer | Proposed | #12 | 2026-07-02 |
| [IDEA-007](IDEA-007-users-roles-accessor.md) | Users/roles/permissions accessor (`UsersAccessor`) | Proposed | #22 | 2026-07-22 |
| [IDEA-008](IDEA-008-root-level-cli-option-set.md) | Root-level (shared) CLI option set instead of per-command repetition | Proposed | #23 | 2026-07-22 |
| [IDEA-009](IDEA-009-syslog-aware-logging.md) | Syslog/journald-aware logging mode (drop redundant timestamp/pid) | Proposed | #24 | 2026-07-23 |
| [IDEA-010](IDEA-010-windows-ci-runner.md) | Windows CI runner leg | Proposed | #25 | 2026-08-04 |
| [IDEA-011](IDEA-011-order-cleanup-cli.md) | `orders cleanup` CLI command for cancelling stale orders | Proposed | #26 | 2026-08-07 |
| [IDEA-012](IDEA-012-retire-chain-normalization-default.md) | Revisit whether chain normalization should stay on by default | Proposed | #30 | 2026-08-19 |
| [IDEA-013](IDEA-013-enforce-ruff-format.md) | Run `ruff format` and enforce it in CI | Proposed | #33 | 2026-08-26 |
