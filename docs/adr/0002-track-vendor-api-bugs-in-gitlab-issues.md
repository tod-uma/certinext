---
status: accepted
date: 2026-06-25
---

# Track vendor API bugs in GitLab issues, with vendor-ticket cross-references

## Context and problem statement

Our CertiNext integration regularly hits vendor-side API bugs (e.g. `/domains` pagination ordering, substring `search`) that take weeks of back-and-forth with CertiNext support to resolve. We had been tracking these informally — across memory notes, the README, the `certinext-api-bugs` skill, and email — with no single place showing a bug's live status or which vendor support ticket it maps to. This bit us: we conflated two issues across vendor tickets #131110 and #127335 before catching it. Where should known vendor API bugs be tracked, and how do we keep them tied to the vendor's own tickets while staying visible to downstream (PyPI/GitHub) users?

## Decision drivers

- Live status needs coordination features flat files lack: assignment, a comment timeline, open/closed state, MR linkage (`Closes #N`).
- Each bug must stay tied to its vendor support ticket number(s) and their history.
- Downstream users install from PyPI and land on the **GitHub** mirror — they need to see the known issue + workaround, but **GitLab issues do not mirror to GitHub** (repository mirroring carries Git refs only).
- Avoid two-sources-of-truth drift.

## Considered options

- GitLab issues (+ README "known issues" for public visibility)
- Markdown issue files under `docs/`
- GitHub issues on the mirror
- Status quo: README + `certinext-api-bugs` skill + memory notes only

## Decision outcome

Chosen: **GitLab issues as the system of record for vendor API bug status** — one issue per bug, with the vendor support ticket number(s) and status timeline kept in the issue (description + comments). The code workaround links to the issue, and the issue is closed by the MR that removes the workaround. The **README "known issues" section** (and the `certinext-api-bugs` skill) remain the durable, GitHub-visible record of the quirk + workaround, because GitLab issues don't reach the mirror. We do **not** duplicate issue tracking into `docs/`.

### Consequences

- Good: one place for live status, coordination, and vendor-ticket traceability; closing an issue is wired to removing its workaround.
- Neutral: the README known-issues section is maintained in parallel — but that content is durable "how to cope" guidance, not live status, so it doesn't drift the way a second tracker would.
- Bad: GitHub-mirror users can't see the GitLab tracker; accepted, since vendor correspondence is internal and the README covers what they need.
- The vendor ticket number(s) must be kept accurate in each issue (the #131110/#127335 mix-up is the cautionary tale).

### Confirmation

Issues #1–#3 created in `sysadmin/python-libs/certinext` on 2026-06-25, each citing its vendor ticket; the README "known issues" section and `certinext-api-bugs` skill carry the public record.

## Pros and cons of the options

### GitLab issues (+ README known-issues)
- Good, because native coordination (assignees, comments, labels, MR `Closes #`), queryable, single source of truth for status.
- Good, because the vendor ticket # and timeline live in one thread.
- Bad, because not visible on the GitHub mirror → requires the parallel README section.

### Markdown files under `docs/`
- Good, because they mirror to GitHub and live with the code.
- Bad, because no status/assignment/threaded discussion; drifts against the real tracker; reinvents an issue tracker, badly.

### GitHub issues on the mirror
- Bad, because the public repo is a one-way mirror and GitLab is where we work; issues don't sync between the two, and vendor back-and-forth shouldn't be public.

### Status quo (README + skill + memory)
- Good, because zero setup and already GitHub-visible.
- Bad, because no live status or coordination — exactly what let the #131110/#127335 conflation happen.

## More information

- [GitLab issues](https://docs.gitlab.com/ee/user/project/issues/)
- [GitLab repository mirroring](https://docs.gitlab.com/ee/user/project/repository/mirror/) — mirrors the Git repository (branches/tags/commits); issues, merge requests, and labels are not mirrored.
- Repo publish chain (`CLAUDE.md`): GitLab auto-mirrors to GitHub and GitHub Actions publishes to PyPI — the reason downstream users see GitHub, not GitLab.
- Issues created: `sysadmin/python-libs/certinext#1` (pagination ordering), `#2` (substring `search`), `#3` (`get_list` sortBy paging).

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 4.8, `claude-opus-4-8`) from a conversation with Tod Detre. May contain inaccuracies or hallucinated details; verify specifics against current sources before relying on them.
