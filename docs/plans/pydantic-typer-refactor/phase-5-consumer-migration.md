---
status: planned
depends-on: [phase-4]
implements-adr: []
---

# Phase 5 — Consumer migration

Tracking: issue #18 · milestone %v1.0.0 · label ~"refactor-v1"

Move the known consumers onto the 1.0 surface. Work happens in
`ums-certinext-scripts` and this repo's `examples/`; nothing here blocks
tagging 1.0.0rcN, but 1.0.0 *stable* should not ship before the production
consumer is proven against it.

## Consumer inventory (survey, 2026-07-02)

- **ums-certinext-scripts** (production, packaged): `dcv_update.py`,
  `top_domains.py`. Attribute-only access (pydantic-safe given phase 1's
  frozen surface) **but** imports `certinext._cli.add_connection_args/
  apply_sandbox/build_session` — a private surface phase 4 deletes — and its
  mocked tests pin those helpers' flag/dest names (`args.account_number`,
  `args.client_secret`) and `get_list(pattern=...)`. Pin capped at `<1` in
  phase 0.
- **examples/dns_txt_dcv.py** (this repo): mirrors dcv_update.py patterns;
  pre-existing TODO to sync it with dcv_update improvements — fold in here.
- **dcv-inheritance-recon/** ad-hoc scripts (unpinned, not a git repo, heavy
  private-API + dict access): explicitly **not migrated**. They pinned
  nothing, they probe 0.3.x behavior, and phase 0's probe suite supersedes
  most of them. Note this in their directory (one-line README) rather than
  silently leaving them to break.

## Implementation steps

1. In ums-certinext-scripts: replace `certinext._cli` imports with the
   public `certinext.cli_support` (phase 4) equivalents — for these scripts
   that means session construction from profile/keyring/env and the shared
   connection flags. Keep the scripts argparse-based if that's the least
   change; migrating them to typer is optional scope, decided there, not
   here (they follow the org script conventions doc when touched).
2. Update their mocked tests for whatever the new helper surface exposes
   (the old flag-dest pins were testing `certinext` internals — replace with
   contract tests against `cli_support`).
3. Raise the pin: `certinext>=1.0.0rc1,<2` once an rc exists; run their
   suite + a `--dry-run`/read-only `dcv_update` invocation against sandbox.
4. Update `examples/dns_txt_dcv.py` to 1.0 surface + the parked
   improvements (`--sandbox`, helper usage), honoring the R08 resolution
   (challenge-host question) from phase 0.
5. Drop a `dcv-inheritance-recon/README.md` breadcrumb: scripts target
   certinext 0.3.x; superseded by `tests/test_probes.py`.

## Verification

- ums-certinext-scripts CI green against 1.0.0rcN; sandbox smoke of
  dcv_update read path; examples pass ruff/pyright (they're in the include
  lists).

## Documentation expectations

ums-certinext-scripts README notes the new minimum certinext version;
CHANGELOG entries in both repos; migration guide (phase 6) links here as
the worked example.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
