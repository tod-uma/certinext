---
status: accepted
date: 2026-11-20
---

# Move the CLI's dependencies into a `cli` extra

## Context and problem statement

[ADR 0003](0003-adopt-pydantic-typer-httpx-settings-rich-for-1.0.md) made
typer, rich and tomlkit core dependencies, because the library and its CLI
shipped together. Only the CLI needs them: typer and rich for commands and
tables, tomlkit for writing `config.toml`
([ADR 0006](0006-tomlkit-for-config-writes-tomllib-for-reads.md)).

The planned Splunk modular input vendors the library into an app package.
Every extra dependency there is code to vendor, to keep current for a
Python version Splunk picks, and to pass AppInspect. Two library modules
also imported CLI packages at import time: `healthcheck` (rich, for its
result table) and `_config` (tomlkit, which `cli_support` pulls in).

## Considered options

- **Keep them core.** Simplest, and the vendoring cost stays.
- **Split the CLI into its own distribution.** Clean, but the CLI and the
  library release together and share internals; two packages double the
  release work for no user benefit yet.
- **A `cli` extra** in the same distribution.

## Decision outcome

Chosen: a `cli` extra holding typer, rich and tomlkit. The `dev` extra lists
them too, so CI's `uv sync --extra dev` is unchanged.

- **The library imports none of them at import time.** `healthcheck`
  imports rich inside the two table functions; `_config` imports tomlkit
  inside the write path only (reads use `tomllib`/`tomli`). `cli_support`
  therefore works without the extra, apart from saving stored defaults.
- **`certinext.cli` fails clearly.** Imported without the extra, it raises
  an `ImportError` naming the missing package and the install command.
  `certinext.cli_options` is typer-specific and simply needs the extra.
- **A test enforces it.** `tests/test_cli_extra.py` imports the library
  modules in a fresh interpreter with the three packages blocked, and
  checks that `pyproject.toml` keeps them out of the core dependencies.

This supersedes ADR 0003's dependency placement only; its choice of
libraries stands.

### Consequences

- **Breaking for CLI installs.** `uv tool install certinext` (no extras)
  installs a `certinext` command that exits with the install hint. The
  README now uses `certinext[cli,csr,keyring]` everywhere. Release notes
  for 1.5 must say so.
- **Consumers that build on the CLI** (certinext-zabbix and
  ums-certinext-scripts import `certinext.cli._app`, `cli._shared` and
  `cli_options`) should depend on `certinext[cli]`. Today they declare
  `typer` themselves, which brings rich, so imports keep working; only
  tomlkit (the embedded `setup defaults` write) would be missing. Their
  dependency change is a follow-up in each repo.

## More information

- [ADR 0003](0003-adopt-pydantic-typer-httpx-settings-rich-for-1.0.md)
- [ADR 0006](0006-tomlkit-for-config-writes-tomllib-for-reads.md)

---
> **AI-assistant disclaimer:** Drafted by Claude (Opus 5.5) from a conversation
> with Tod Detre. May contain inaccuracies; verify specifics against current
> sources before relying on them.
