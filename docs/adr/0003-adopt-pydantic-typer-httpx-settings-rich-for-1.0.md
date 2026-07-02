---
status: accepted
date: 2026-07-02
---

# Adopt pydantic v2, typer, httpx, pydantic-settings, and rich for the 1.0 rewrite

## Context and problem statement

The library grew organically through 0.1–0.3: `requests` for HTTP, raw-dict
responses wrapped in `@property` accessor classes, eleven separate argparse
CLIs sharing a private `_cli.py` helper module, a hand-rolled TOML
config loader/renderer in `_config.py`, and `tabulate` for table output. Our
newer Python conventions standardize on typer, pydantic, and structlog
(structlog is already in use). Version 1.0.0 is the one cheap moment to make
coordinated breaking changes. How much of the modern stack does 1.0 adopt?

## Decision drivers

- Vendor payloads are quirky and drift silently (see ADR 0005); typed models
  with an explicit leniency policy beat ad-hoc dict access.
- Eleven argparse CLIs duplicate parsing/plumbing that typer expresses
  declaratively.
- Consistency with our org-wide Python script conventions (typer, pydantic,
  structlog).
- The rewrite must carry across 735 existing tests and one production
  consumer (`ums-certinext-scripts`).

## Considered options

- Full stack: pydantic v2 + typer + httpx + pydantic-settings + rich
- Minimal: pydantic models + typer CLIs only (keep requests, hand-rolled
  config, tabulate)
- Incremental adoption inside the 0.x line (no coordinated 1.0)

## Decision outcome

Chosen: **full stack**, because each remaining hand-rolled layer (HTTP
session/auth plumbing, TOML config merge/render, table formatting) is exactly
the kind of code the standard libraries replace, and doing it in one major
version means consumers absorb one breaking change instead of several.
Ratified 2026-07-02.

### Consequences

- Bad: `CertiNextAPIError` can no longer subclass `requests.HTTPError`.
  Anything catching `requests` exceptions around certinext calls breaks, and
  the healthcheck CLI's ordered exception classification must be rewritten in
  the same change (see the phase 2 plan).
- Bad: essentially every module and test is rewritten, so `git merge` from
  the 0.3.x line stops working per-module as the rewrite proceeds. Mitigated
  by the ported-fixes log in the plan roadmap
  (`docs/plans/pydantic-typer-refactor/README.md`).
- Good: validated, typed responses; declarative CLIs; config parsing with
  documented precedence; one dependency set aligned with our other tools.
- Neutral: `tabulate` and `requests` drop out of the dependency tree; `rich`
  comes in via typer's ecosystem.

### Confirmation

1.0.0 ships with no imports of `requests`, `argparse`, or `tabulate` in
`certinext/`; `pyproject.toml` lists pydantic, typer, httpx,
pydantic-settings.

## Pros and cons of the options

### Full stack (chosen)

- Good, because one coordinated break instead of a drip of them across 1.x.
- Good, because hand-rolled config/HTTP/auth code carries our maintenance
  burden and standard libraries carry their own.
- Bad, because the diff is maximal and the 0.3.x merge-ability window closes
  fastest.

### Minimal (pydantic + typer only)

- Good, because a smaller, more reviewable 1.0.
- Bad, because the requests exception hierarchy and hand-rolled config would
  then need their own breaking change later — a second 2.0-scale event.

### Incremental inside 0.x

- Bad, because each step is a breaking change for consumers under a version
  scheme that promises none.

## More information

- [pydantic v2 docs](https://docs.pydantic.dev/latest/)
- [typer docs](https://typer.tiangolo.com/)
- [httpx docs](https://www.python-httpx.org/)
- [pydantic-settings docs](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [rich docs](https://rich.readthedocs.io/en/stable/)
- [structlog docs](https://www.structlog.org/en/stable/)
- Plan roadmap: `docs/plans/pydantic-typer-refactor/README.md`

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
