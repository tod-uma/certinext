---
status: accepted
date: 2026-07-07
---

# tomlkit for config-file writes, tomllib for reads

## Context and problem statement

`certinext-setup-defaults` (and `--save-defaults`) rewrite the user's
`config.toml`. The hand-rolled `_render` writer destroyed comments and
formatting on every save — its own header comment apologized for it.
Phase 3 of the 1.0 refactor (roadmap open question #4) had to decide:
keep the hand-rolled writer or adopt a round-tripping TOML library?

## Considered options

- Keep the hand-rolled `_render` (zero new dependencies, tested,
  documented comment loss)
- Adopt [tomlkit](https://tomlkit.readthedocs.io/en/latest/) for the
  write path

## Decision outcome

Chosen: **tomlkit, for the write path only** (ratified by Tod,
2026-07-06). Comment/format preservation in a hand-edited config file is
a real UX gain worth one pure-Python dependency.

The scope limit is the durable rule: **read paths stay on
[`tomllib`](https://docs.python.org/3/library/tomllib.html)/`tomli`**.
tomlkit's wrapper types subclass `str`/`int`/`dict`, but its `Bool`
*cannot* subclass Python's `bool` — letting tomlkit-parsed values flow
into the strict pydantic family models (`StrictBool`) or `isinstance`
checks would fail subtly. Only `save_defaults()`'s read-modify-write
cycle parses with tomlkit.

### Consequences

- Good: user comments and layout in `config.toml` survive saves
  (pinned by `test_save_defaults_preserves_comments`).
- Bad: one more runtime dependency; two TOML parsers in the tree.
- Watch out: the writer must pass `newline=""` to `Path.write_text` —
  tomlkit output carries the parsed file's own line endings, and
  newline translation would corrupt `\r\n` into `\r\r\n` on Windows.

## More information

- [tomlkit documentation](https://tomlkit.readthedocs.io/en/latest/)
- [tomllib — stdlib TOML parser](https://docs.python.org/3/library/tomllib.html)
- Decision context: `docs/plans/pydantic-typer-refactor/phase-3-pydantic-settings-config.md`

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
