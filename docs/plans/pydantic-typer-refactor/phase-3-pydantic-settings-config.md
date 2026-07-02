---
status: planned
depends-on: [phase-0]
implements-adr: [0003]
---

# Phase 3 — pydantic-settings config

Tracking: issue #16 · milestone %v1.0.0 · label ~"refactor-v1"

Replace the hand-rolled `_config.py` (TOML load/merge/save, precedence
logic) with
[pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/).
Parallel-safe with phases 1–2 (disjoint modules).

## Deployed state that must keep working unchanged

Users have this on their machines today; 1.0 must read it as-is, no
migration step:

- `config.toml` at `%APPDATA%\certinext\` / `$XDG_CONFIG_HOME/certinext/`,
  `[defaults]` + `[profiles.NAME]` sections, two key families
  (issue-cert defaults vs connection keys `sandbox`/`base_url`/`token_url`),
  `CERTINEXT_CONFIG` path override.
- Env vars: `CERTINEXT_CLIENT_ID`, `CERTINEXT_CLIENT_SECRET`,
  `CERTINEXT_PROFILE`.
- Keyring service names: `certinext` / `certinext-<profile>`
  ([keyring docs](https://keyring.readthedocs.io/en/latest/)) — stored
  credentials must resolve identically.

## The trap: nonstandard precedence

Credential precedence is **explicit CLI arg → OS keyring → env var →
interactive prompt** — keyring *outranks* env. pydantic-settings defaults to
init-args → env → dotenv → file-secrets; replicating our order requires
[`settings_customise_sources`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/#customise-settings-sources)
with a custom keyring source placed above the env source. Endpoint
resolution precedence likewise: CLI flag → `--sandbox` → profile config →
production defaults. Encode both orders in tests *first* (they exist in
`tests/test_config.py`/`tests/test_keyring_helpers.py` — port, don't relax).

## Sub-decision: TOML writer

`certinext-setup-defaults` *writes* config.toml via the hand-rolled
`_render`. pydantic-settings only reads. Options: keep `_render`, or adopt
[tomlkit](https://tomlkit.readthedocs.io/en/latest/) for comment/format
round-tripping. Roadmap open question #4 — decide at implementation, record
in this doc.

## Implementation steps

1. `CertiNextSettings` model(s): connection + defaults families, profile
   overlay semantics (profile section overrides `[defaults]`) reproduced
   exactly; `tomllib`/`tomli` stays for parsing unless tomlkit is adopted
   ([tomllib docs](https://docs.python.org/3/library/tomllib.html)).
2. Custom keyring settings source; wire the precedence orders.
3. Port `setup-defaults` write path (per sub-decision) and
   `setup-keyring` unchanged semantics.
4. Delete `_config.py` internals it replaces; keep public helper names used
   elsewhere in the package until phase 4 rewires the CLIs.

## Verification

- Golden-file tests: real-shaped config.toml fixtures (copy the current
  test cases) load to identical effective settings pre/post refactor;
  precedence tests green; `setup-defaults` round-trips a file with both
  families + profiles without data loss.
- Manual check on this dev machine: existing `%APPDATA%\certinext\config.toml`
  and keyring entries resolve identically (`certinext-healthcheck --sandbox`
  connects with no flags).

## Documentation expectations

README credentials section re-verified line-by-line (precedence is
user-facing); docstrings per house style; migration guide states "no config
changes required" — and that claim must be *true*.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
