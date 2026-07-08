# IDEA-003: Docs site (mkdocs + API reference) with llms-full.txt

- **Status:** Proposed (coordinating issue: #9)
- **Created:** 2026-07-02
- **Updated:** 2026-07-02

## Context

Documentation today is one ~1700-line README plus docstrings; there is no
rendered API reference and nothing purpose-built for LLM ingestion. Raised
2026-07-02 alongside the 1.0 refactor's goal of making the library easy for
humans and AI to pick up. (The cheap subset — a hand-curated `llms.txt` and
an `AGENTS.md` — is already in the refactor plan's phase 6, not deferred
here.)

## The idea

- [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) site:
  split the README monolith into guide pages; generate the API reference
  from our (mandatory) docstrings via
  [mkdocstrings](https://mkdocstrings.github.io/).
- Publish via GitLab Pages, and/or GitHub Pages on the mirror so PyPI users
  land somewhere useful.
- Generate `llms-full.txt` from the built site per the
  [llms.txt convention](https://llmstxt.org/) so an assistant can ingest the
  full API surface in one fetch.

## Why not now

Phase 6 of the refactor already rewrites the README; standing up a site
*during* the rewrite doubles the docs churn. Do it against the settled 1.0
docs. What changes the calculus: 1.0.0 shipping, or a second external
consumer appearing.

## Pros

- Docstring investment (house rule) becomes a browsable reference for free.
- llms-full.txt makes "point your agent at the docs" a one-liner.

## Cons / costs

- A docs build + Pages deployment to maintain; nav/structure design work.

## Effort

Medium. mkdocstrings over existing docstrings is quick; carving the README
into pages well is the slow part.

## Open questions & caveats

- GitLab Pages, GitHub Pages, or both (mirror already exists)?
- Version the docs per release or latest-only?

## Next steps

None until the phase-6 README rewrite settles.

## References

- [mkdocs-material](https://squidfunk.github.io/mkdocs-material/) ·
  [mkdocstrings](https://mkdocstrings.github.io/) ·
  [llms.txt](https://llmstxt.org/) ·
  [GitLab Pages](https://docs.gitlab.com/user/project/pages/)
- Related: IDEA-004 (doc-example testing)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
