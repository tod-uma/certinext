---
status: done
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

## Sub-decision: TOML writer — **tomlkit adopted** (ratified 2026-07-06, Tod)

`certinext-setup-defaults` *writes* config.toml; pydantic-settings only
reads. Decided: adopt [tomlkit](https://tomlkit.readthedocs.io/en/latest/)
for the write path; the hand-rolled `_render` is deleted.

<details>
<summary>Why tomlkit, and why only for writes?</summary>

- Comment/format preservation in hand-edited config files is a real UX
  gain — the old writer's header comment literally apologized for
  destroying comments on every save.
- tomlkit is used **only** in `save_defaults()` (read-modify-write).
  All *read* paths stay on `tomllib`/`tomli`: tomlkit's wrapper types
  are dict/str/int subclasses but its `Bool` cannot subclass Python's
  `bool`, so letting parsed tomlkit values flow into the strict pydantic
  family models (`StrictBool`) would break validation subtly.
- Windows gotcha found in testing: `Path.write_text` translates `\n` to
  `\r\n`, but tomlkit output already carries the parsed file's own line
  endings — double translation corrupts `\r\n` into `\r\r\n`. The writer
  passes `newline=""` to disable translation.

</details>

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

## Implementation notes (2026-07-06)

- New module `certinext/settings.py`: `IssuanceDefaults` and
  `ConnectionSettings` (the two config-file key families; strict field
  types so wrong-typed values degrade into warnings, never coerce),
  `KeyringSettingsSource`, and `CertiNextSettings` whose
  `settings_customise_sources` orders init → keyring → env — the
  nonstandard precedence, now pinned by `tests/test_settings.py`.
- `_config.py` keeps every public helper name/signature; per-key
  validation delegates to the family models (`model_validate` one key at
  a time, so one bad entry still can't block the rest). `_validate`,
  `_toml_literal`, and `_render` are gone.
- `_cli.py`: `_resolve` (arg → keyring → env → prompt) became
  `_require_credential` — just the prompt/error tail; the first three
  steps live in `CertiNextSettings`. The explicit `--account-number`
  skips-stored-secret rule moved into `KeyringSettingsSource`.
- The `--sandbox`/endpoint resolution stays in `apply_sandbox()` on
  purpose: it is conditional mapping (flag → known URLs), not source
  precedence, and phase 4 rewires it anyway. Its tests pass unchanged.

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
