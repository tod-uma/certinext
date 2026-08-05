---
status: accepted
date: 2026-08-05
---

# Promote `log_caught_exception` from a per-repo copy into `certinext.cli_support`

## Context and problem statement

`log_caught_exception()` — the helper that turns a caught exception into one
concise operational line plus a paired DEBUG record carrying the traceback —
exists as a private copy in two downstream repos:
`certinext-zabbix/_cli_shared.py` and
`ums-certinext-scripts/_cli_shared.py`. As of 2026-08-05 the two copies are
byte-identical, `_TRACEBACK_HINT` constant included.

ADR 0014 changes that helper's behaviour. Editing it means making the same
edit twice, identically, in two repos — with no test that would catch the two
copies drifting apart afterwards.

ADR 0011's D7 established that this library must *not* invent host filesystem
locations, which is why `debug_log_path` has no default. That reasoning has
been applied by analogy to keep other CLI scaffolding downstream too. So:
does a logging helper belong in the shared library, or is it the same kind of
thing D7 kept out?

## Decision drivers

- ADR 0014 requires editing both copies identically, right now.
- The copies are already provably identical, so extraction is a pure move
  rather than a reconciliation of drifted behaviour.
- D7's constraint is specifically about *host environment* assumptions, not
  about shared code in general.

## Considered options

- **Move it into `certinext.cli_support`** (chosen).
- **Keep the two copies and edit both** (status quo). Rejected: it doubles
  every future change to error-path logging and nothing detects drift. The
  copies are identical today only because nobody has edited one in isolation
  yet.

## Decision outcome

Chosen: **move `log_caught_exception` and `_TRACEBACK_HINT` into
`certinext.cli_support`**, alongside `setup_logging()`, and have both
downstream repos import it instead of defining it.

D7 does not apply. D7 is about a shared library declining to guess a *host
filesystem path* — an environment fact only the deployer knows. A logging
helper encodes no environment assumption; it is exactly the kind of behaviour
a shared library should own, and it already travels with `setup_logging()`,
whose processor chain determines where its two records end up.

The helper takes the bound logger as its first argument rather than reaching
for a module-level one, so it stays usable from any caller's own logger and
carries no import-time coupling to a configured logging setup.

### Consequences

- Good: ADR 0014's behaviour change lands once, not twice.
- Good: removes the drift risk between two copies that no test covered.
- Bad / accepted: downstream repos must raise their `certinext` floor to the
  release containing the helper before deleting their local copy — a
  version-pin coordination step, of the kind that already caught this project
  out once (a floor was pinned that did not contain the API being imported).
- Bad / accepted: error-path log wording now changes for both scripts at once
  when the library changes, rather than per repo. Acceptable: identical
  wording was the existing state, maintained by hand.
- Neutral: `nm` gains nothing here — its library code never calls
  `log.error`, so it has no equivalent helper to converge (its independent
  `cli_support.py` copy stays a mirror only for `setup_logging`, per D6).

### Confirmation

Both downstream repos import `log_caught_exception` from
`certinext.cli_support` and define no local copy; `grep` for
`_TRACEBACK_HINT` finds it in the library only.

## More information

- [ADR 0011 — always-on debug-log sidecar](0011-always-on-json-debug-log-sidecar.md) (D6 on `nm`'s independent copy; D7 on no library default path)
- [ADR 0014 — truncated traceback on the operational line](0014-traceback-on-the-operational-log-line.md) (the change that forced this)
- [structlog — bound loggers](https://www.structlog.org/en/stable/bound-loggers.html)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
