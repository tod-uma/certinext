---
status: accepted
date: 2026-11-24
---

# Public API surface: root exports and every non-underscore module are stable through 1.x

## Context and problem statement

`certinext/__init__.py` lists its exports in `__all__`, but several modules
outside it are importable under public-looking names: `certificate_lookup`,
`replacement`, `healthcheck`, `domain_cert_count`, `settings`,
`cli_support` and `cli_options`. Nothing said which of them a consumer may
rely on, and 1.5 is the release that freezes the API for an rc series.

The two in-house consumers already import beyond the root package. At
`0ec0ea4`, certinext-zabbix and ums-certinext-scripts import from
`certinext.exceptions`, `certinext.orders`, `certinext.models.domains` and
`certinext.cli_support` (`LogFormat`, `TRACEBACK_HINT`,
`log_caught_exception`). An external review (Codex, R2b finding 2)
recommended marking the CLI-helper modules internal. That would declare
modules in active consumer use unsupported, so it was not adopted.

Which modules does certinext promise to keep compatible?

## Considered options

- Public names are stable: the root `certinext` exports plus every module
  whose name has no leading underscore.
- Root exports plus an explicit allow-list of modules, with everything else
  documented as internal even without an underscore.
- Defer the decision past the rc.

## Decision outcome

Chosen: **public names are stable.**

- **Stable through 1.x:** everything in `certinext.__all__`, and every module
  and public (non-underscore) name in a module whose own name has no leading
  underscore: `certinext.client`, `certinext.session`, the accessor modules,
  `certinext.models.*` (except `models._base`), `certinext.exceptions`,
  `certinext.retry`, `certinext.csr`, `certinext.settings`,
  `certinext.cli_support`, `certinext.cli_options`,
  `certinext.certificate_lookup`, `certinext.replacement`,
  `certinext.healthcheck` and `certinext.domain_cert_count`.
- **Internal, may change in any release:** any module or name with a leading
  underscore (`certinext._v3`, `certinext._chain`, `certinext._serial`,
  `certinext.models._base`, and so on), and the `certinext.cli` package,
  which is the command-line application rather than a library.

The rule matches Python's own convention, so it needs no list to keep in
sync. Adding a new public-named module now means committing to it.

### Consequences

- Good: what consumers already import is covered, without a migration.
- Good: one rule, readable from the import path alone.
- Bad: the stable surface is wide. `cli_support` and `cli_options` carry
  CLI plumbing that now cannot change incompatibly before 2.0.
- Neutral: a helper meant to stay private must get an underscore before it
  ships, as `_serial.py` did in the same change.

### Confirmation

The README's "Supported API" section states the rule. A review of a new
module checks its name against it.

## Pros and cons of the options

### Public names are stable

- Good, because consumers' existing imports stay supported.
- Good, because the rule follows Python's underscore convention.
- Bad, because it freezes more than the root package.

### Root exports plus an allow-list

- Good, because the stable surface is exactly what is listed.
- Bad, because a list drifts from the code, and an unlisted module with a
  public name invites the imports it forbids.

### Defer past the rc

- Good, because it costs nothing now.
- Bad, because the rc would freeze an API whose boundary is unwritten.

## More information

- [PEP 8 — Public and internal interfaces](https://peps.python.org/pep-0008/#public-and-internal-interfaces)
- [Semantic Versioning 2.0.0](https://semver.org/)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5.5,
> `claude-opus-5-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
