---
status: in-progress
depends-on: [phase-1, phase-2, phase-3]
implements-adr: [0003, 0004]
---

# Phase 4 — typer CLI + rich

Tracking: issue #17 · milestone %v1.0.0 · label ~"refactor-v1"

Consolidate the eleven argparse CLIs into one `certinext`
[typer](https://typer.tiangolo.com/) application with subcommands, keeping
the old script names as alias entry points (ADR 0004). Replace `tabulate`
with [rich](https://rich.readthedocs.io/en/stable/) tables.

## Command mapping

| Old script | New subcommand |
| --- | --- |
| certinext-accounts | `certinext accounts` |
| certinext-domains | `certinext domains ...` |
| certinext-ledger | `certinext ledger` |
| certinext-list-certificates | `certinext list-certificates` |
| certinext-pending-dcv | `certinext pending-dcv` |
| certinext-domain-cert-count | `certinext domain-cert-count` |
| certinext-issue-cert | `certinext issue-cert` |
| certinext-parent-dcv-status | `certinext parent-dcv-status` |
| certinext-healthcheck | `certinext healthcheck` |
| certinext-setup-keyring | `certinext setup keyring` |
| certinext-setup-defaults | `certinext setup defaults` |

Aliases: each old console-script name stays in `[project.scripts]`, mapped
to a shim that invokes the app with the subcommand pre-selected
([entry points spec](https://packaging.python.org/en/latest/specifications/entry-points/)).
Removal no earlier than 2.0.

## Compatibility rules (ADR 0004 invariants)

- **stdout = data, stderr = everything else.** Rich console writes to
  stderr for diagnostics/progress; tables that *are* the data go to stdout.
  Prompts stay on stderr (`prompt_stderr` semantics — typer's
  `typer.prompt` writes prompts to stdout by default; wrap it or use
  `rich.prompt` on a stderr console. Do not regress this; it was a shipped
  bug fix).
- **Human/table stdout is NOT load-bearing** — roadmap open question #1
  was answered 2026-07-07 (Tod): nothing in UMS parses CLI stdout, and the
  default output may change under the 1.0 major bump. Rich tables need not
  mimic tabulate's formatting.
- **`--json` output stays byte-compatible** with 0.3.x — not because a
  consumer demands it (none audited), but because phase 1's `as_dict()`
  raw-payload identity makes parity nearly free. Golden-file tests per
  command pin it as a **regression guard, not a contract**: a deliberate
  improvement may change a golden, with a migration-guide note.
- **Exit codes preserved**, healthcheck's especially (monitoring-relevant;
  its non-zero classes are DENIED/NOT_FOUND/SERVER_BUG/NETWORK, EMPTY under
  `--strict`).
- **Flag names preserved** under both app and aliases; connection flags
  (`--profile`, `--sandbox`, `--base-url`, `--token-url`, `--account-number`,
  `--client-secret`) become shared typer options (callback/context pattern —
  [typer docs](https://typer.tiangolo.com/tutorial/commands/callback/)).
  Where typer forces a rename, keep the old spelling as a hidden alias.
- structlog setup (TTY console vs JSON renderer) carries over unchanged.

## Shared plumbing replacement

`_cli.py`'s argparse helpers (`add_connection_args`, `apply_sandbox`,
`build_session`, `add_requestor_args`, `add_json_output_arg`,
`fatal_api_error`) are the template for the typer-shared layer. **Design the
replacement as a public module** (working name `certinext.cli_support`) —
phase 5 migrates external consumers who import `certinext._cli` today onto
it; the session-building logic (`build_session` atop phase 3 settings)
is the part they actually need.

To be explicit: `cli_support` is a **new API, not an argparse emulation** —
it does not preserve argparse `Namespace` shapes or dest names
(`args.account_number`, `args.client_secret`, ...). External code and tests
pinned to those (ums-certinext-scripts' mocked tests do this) were coupling
to certinext internals; phase 5 owns replacing them with contract tests
against `cli_support`. The *end-user* flag spellings are what this phase
preserves, not the in-process namespace.

## Design rules beyond compatibility

- **Thin presentation layer:** subcommand bodies do argument handling and
  rendering only; every operation they perform lives in an importable
  library function. This is load-bearing for wishlist IDEA-001 (Textual
  TUI) and IDEA-002 (MCP server), which must reuse the operations layer
  without reimplementing vendor workarounds — treat "could the TUI call
  this?" as a review question for every subcommand.
- **Uniform `--json`:** every data-producing subcommand gets `--json`
  (additive where a 0.3.x script lacked it) — machine/agent consumers
  should never need to scrape tables.

## Implementation steps

1. App skeleton + shared connection options + structlog wiring; port
   **healthcheck first** (it's the instrument — validate parity early:
   same probes, same classifications, same exit codes, `--json` identical).
2. Port read-only commands (accounts, ledger, domains, pending-dcv,
   list-certificates, domain-cert-count, parent-dcv-status).
3. Port setup commands (keyring, defaults).
4. Port `issue-cert` last (972 lines, most flags, interactive paths,
   `--raw-chain`/format outputs — bring `tests/test_issue_cert_output.py`
   along wholesale).
5. Alias shims + `pyproject.toml` entry points; `typer` + `rich` in deps,
   `tabulate` + `types-tabulate` out.
6. Snapshot tests: `--help` trees recorded (they *will* differ from
   argparse; the snapshot documents the new contract), `--json` goldens
   pinning the 0.3.x format as a regression guard (deliberate changes
   allowed with a migration-guide note).

## Verification

- All CLI unit tests ported and green; `--json` golden tests pass; alias
  smoke test (`certinext-healthcheck --sandbox` == `certinext healthcheck
  --sandbox`, same exit code and stdout).
- Live: `certinext healthcheck` (prod, read-only) and `--sandbox` green;
  one sandbox `issue-cert` end-to-end run (covers R11/R12 paths on the new
  stack).
- Grep gates: no `import argparse`, no `import tabulate` in `certinext/`.

## Documentation expectations

README CLI section restructured around subcommands with an alias table;
shell-completion install note
([typer completion docs](https://typer.tiangolo.com/tutorial/options-autocompletion/));
migration guide lists any flag divergences (target: none).

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
