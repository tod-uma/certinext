---
status: accepted
date: 2026-08-24
---

# Connection destination settings fail closed; issuance defaults warn and continue

## Context and problem statement

`config.toml` holds two key families in the same `[defaults]` / `[profiles.NAME]`
sections. Issue-cert defaults (`IssuanceDefaults`) merge key by key and, per the
long-standing rule in `_checked()`, degrade a bad value into a warning so one
typo never blocks issuance. Connection settings (`ConnectionSettings` —
`sandbox`, `base_url`, `token_url`) name *one destination*, so a
fix earlier the same day (commit `69ac2b0`) made them inherit atomically: the
most specific section declaring any of them decides all of them.

Applying the warn-and-continue rule to the second family turned out to be unsafe.
The atomic overlay discards the inherited destination as soon as a section
*declares* an endpoint key — before the value is validated. A rejected value
therefore left the connection settings empty, and the bottom of
`resolve_connection()`'s precedence chain is the built-in **production**
endpoint:

```toml
[defaults]
sandbox = true

[profiles.sandbox]
sandbox = "yes"        # rejected by the strict boolean — and declaring it
                       # already discarded the inherited sandbox destination
```

A profile the operator believed pointed at sandbox resolved to the live API. The
two families need different failure semantics: for issuance defaults the
fallback is a harmless unset field, while for a destination the fallback is
production.

## Decision drivers

- The README already states the invariant: a profile believed to point at
  sandbox must never silently resolve to production because of a typo.
- Warn-and-continue is right for issuance defaults and must not be disturbed.
- `resolve_connection()` already has the escape hatch: an explicit `--sandbox`
  or `--base-url` pins the endpoint, so the failure can safely downgrade to a
  warning there.

## Considered options

Two rules were weighed (beyond the status quo of warning and continuing, which
is the defect above):

- **A — raise only when nothing in the section validates.** The formulation
  recommended by the external review that reported the bug.
- **B — require the section to still name a host.**

## Decision outcome

Chosen: **B**. A section that declares connection keys must, after validation,
still name a host — a valid `base_url`, or a valid `sandbox` (either boolean;
`sandbox = false` names production deliberately). Otherwise
`connection_settings()` raises `ConfigError`, which the CLIs already surface as
exit 2 with an explicit refusal to fall back to production.

Option A is a strict subset and leaves the same hole open whenever one unrelated
key happens to validate: `sandbox = "yes"` alongside a valid `token_url` yields a
non-empty result, passes A's check, and resolves to the production base URL
paired with a sandbox token endpoint. The distinction that makes B correct is
that only `sandbox` and `base_url` choose a host; `token_url` says where a
chosen host's OAuth endpoint lives, so it can never stand in for one.

### Consequences

- Good: no combination of invalid endpoint values can select production. The
  guard is expressed as an invariant about the *result* rather than a count of
  rejected keys, so it does not need revisiting per key.
- Good: per-key tolerance survives where it is safe — `base_url` with a
  malformed `token_url` keeps the base URL and derives the token endpoint from
  it via `_derive_token_url()`.
- Bad: a section declaring **only** `token_url` now raises. Accepted knowingly —
  under atomic inheritance that config already resolved silently to the
  production base URL, so this converts a silent fail-open into a loud exit 2.
- Neutral: the two families now diverge in failure semantics as well as in
  inheritance. Both divergences have the same root cause — a destination is not
  a bag of independent fields — so they are documented together in
  `_config.py`'s module docstring.

### Confirmation

`tests/test_config.py` pins each branch: the all-invalid section, the mixed
valid/invalid section that option A would have missed, the `token_url`-only
section, the partial-invalid section that must still warn rather than raise, and
explicit `sandbox = false` as a deliberate production destination. Verified
end-to-end against the live sandbox API, not only in unit tests: the mistyped
profile exits 2, and the same config with `--sandbox` warns and connects to
sandbox.

## Pros and cons of the options

### A — raise only when nothing in the section validates

- Good, because it is the smallest possible change and fixes the reported case.
- Bad, because the check is on the *emptiness* of the result rather than on
  whether a destination was actually named, so an unrelated valid key silently
  re-opens the fall-through to production.

### B — require the section to still name a host

- Good, because it states the property that actually matters and covers every
  combination of invalid values.
- Good, because it also catches a section that names no host even when all its
  values are valid.
- Bad, because it rejects a `token_url`-only section that older key-by-key
  inheritance accepted.

## More information

- [MADR](https://adr.github.io/madr/) — the format this record follows.
- [pydantic — strict mode and boolean parsing](https://docs.pydantic.dev/latest/concepts/strict_mode/)
  — why `sandbox = "yes"` is rejected rather than coerced.
- [TOML v1.0.0 specification](https://toml.io/en/v1.0.0) — the config file format.
- Related: [0005](0005-lenient-models-validated-against-live-payload-corpus.md)
  — where leniency *is* the right default, and why that reasoning does not
  extend to a connection destination.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5,
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
