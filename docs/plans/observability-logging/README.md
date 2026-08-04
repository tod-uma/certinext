# Observability & logging overhaul — roadmap

**Goal:** give the CertiNext CLI family production-grade diagnostics without
polluting operational logs, and pay down the shared-CLI-option debt that was
blocking the logging work.

Three tracked wishlist items, implemented together because 1 unblocks the clean
form of 2 and 3:

- [IDEA-008](../../wishlist/IDEA-008-root-level-cli-option-set.md) — root-level
  (shared) CLI option set instead of per-command repetition.
- [IDEA-009](../../wishlist/IDEA-009-syslog-aware-logging.md) — syslog/journald-aware
  concise output (drop redundant `timestamp`/`pid` under systemd).
- **Debug-log file** — an always-on, Splunk-ingestible traceback/DEBUG sidecar
  file, so an unattended systemd-timer failure never loses its stack trace.
  (No wishlist doc yet; prompted 2026-08-03 by a `RecursionError` in
  `certinext-zabbix` that logged only a bare message — see
  [Context](#origin) below.)

Plus a downstream consumer step: the Ansible role that deploys the scripts
provisions the log dir + logrotate policy.

## Origin

On 2026-08-03 the `certinext-zabbix-push` systemd units failed with
`event="maximum recursion depth exceeded while decoding a JSON object..."` and
nothing else — no traceback, no error type. Root cause was traced to a
`RecursionError` (a `RuntimeError` subclass) caught by
`zabbix_push_cli.py`'s `except (RuntimeError, CertiNextAPIError)` branch, which
logged only `str(exc)`. The immediate fix (route that branch through
`log_caught_exception`) shipped on branch `fix/log-caught-runtime-errors` in
`certinext-zabbix` (v0.1.0rc6). But it exposed the real gap: **the paired DEBUG
traceback `log_caught_exception` emits is dropped before formatting unless the
run is at `-vvv`**, so an unattended run can never produce a traceback. This
roadmap closes that gap and does the two logging-adjacent wishlist items while
the code is open.

The suspected underlying `zabbix_utils` bug (unbounded recursion when a Zabbix
Proxy Group redirect never resolves — `Sender.__send_to_cluster` recurses with
no depth/cycle guard) is **out of scope here** and tracked separately; this
roadmap is about *observability*, not that fix. The debug log is what will let
us confirm that theory from the next real failure.

## Decisions (settled 2026-08-03)

These were decided with the user before planning. Each should become an ADR
during implementation (they keep applying beyond this change) — see per-phase
`implements-adr` once the ADR numbers are minted.

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Log rotation = Linux logrotate, managed by the Ansible role** (not Python `RotatingFileHandler`). | App just appends to a fixed path; retention is ops-tunable without a redeploy. Oneshot timers reopen the file each run, so logrotate needs no `copytruncate` gymnastics. |
| D2 | **Debug-log on-disk format = JSON, one object per line.** Operational logs stay logfmt (ADR 0007). | A multi-line traceback embeds as a single escaped `exc_info` string field → one Splunk event, no `LINE_BREAKER`/`SHOULD_LINEMERGE` tuning. |
| D3 | **IDEA-008 = full redesign**, not a minimal unblock. | It's the second time the 10-file duplication has been paid; doing it properly unblocks IDEA-009's override flag for every repo at once. |
| D4 | **IDEA-009 override = tri-state `--log-mode auto\|syslog\|verbose`.** | One surface, three explicit states: `auto` detects systemd; `syslog` forces concise (cron piped to `logger(1)`); `verbose` forces `timestamp`/`pid` on even under systemd. |
| D5 | **Debug file is always-on when its path is configured** (unset = off), independent of `-v`. | The whole point is never losing a traceback from an unattended run. `-v` still controls only stderr/journal verbosity. |
| D6 | **`nm`'s independent `setup_logging()` copy is updated in lockstep.** | Avoids the known divergence called out in IDEA-009's cons. |
| D7 | **The library (`certinext.cli_support.setup_logging`) has no default debug-log path** — `debug_log_path: Path \| None = None`, off unless the caller passes one. Each repo owns its own path + env var; its Ansible role provisions the dir. | Path is application policy, not library policy. A shared library must not invent a host filesystem location. |

Per-repo debug-log paths (D7):

| Repo / CLI | env var | deployed path |
|---|---|---|
| `certinext-zabbix` (`certinext-zabbix-push`) | `CERTINEXT_ZABBIX_DEBUG_LOG` | `/var/log/certinext-zabbix/debug.log` |
| `ums-certinext-scripts` (`dcv-update`, `certinext-top-domains`) | `CERTINEXT_SCRIPTS_DEBUG_LOG` | `/var/log/certinext-scripts/debug.log` |
| `nm` (its CLI) | `NM_DEBUG_LOG` | per nm's own deploy (TBD in Phase 4) |
| `certinext` own 10-cmd CLI | `CERTINEXT_DEBUG_LOG` | default off; `/var/log/certinext/` if ever deployed (mostly interactive) |

## Structure: master + per-repo sub-plans

This file is the **master plan** (the "generic space"): it owns the settled
decisions (D1–D7), the per-repo path table, the dependency graph, and the
sequencing/fallback logic. It lives in `certinext` because the shared library
and both wishlist items already live here.

Each **repo that will receive commits gets its own sub-plan** on that repo's
branch, holding only that repo's concrete steps + verification and back-linking
here. A session working in one repo opens only its sub-plan + this master, not
the other repos' plans. Only the `certinext` sub-plan is written now (this
branch); the downstream sub-plans are written as the **first step of each
repo's session** tomorrow, from the specs in
[Downstream sub-plan specs](#downstream-sub-plan-specs) below — this avoids
scattering files onto other repos' `main` branches from here.

### Concern phases (map onto the sub-plans)

The three concerns and their dependency graph are cross-repo; each sub-plan
implements the slice of them that lives in its repo.

| Phase | Concern | Status | Depends on | Implements | Lives in |
|-------|---------|--------|------------|------------|----------|
| 1 | Shared root-level CLI options | done (ADR 0009) | — | IDEA-008 | `certinext` |
| 2 | Syslog/journald-aware output (`--log-mode`) | done (ADR 0010, `certinext` side only) | 1 | IDEA-009 | `certinext` lib + `nm` copy |
| 3 | Debug-log file (`--debug-log-path`, JSON) | done (ADR 0011, `certinext` side only) | 1 | (new) | `certinext` lib + `nm` copy |
| 4 | Wire options into each CLI | planned | 2, 3 | IDEA-008/009 | `certinext-zabbix`, `ums-certinext-scripts`, `nm` |
| 5 | Ansible: log dir + logrotate | planned | 4 | D1, D2 | Ansible role |

### Sub-plan index

| Repo | Sub-plan path | Covers phases | Status |
|------|---------------|---------------|--------|
| `certinext` | [`certinext.md`](certinext.md) (this dir) | 1, 2, 3 (library side) | written |
| `nm` | `python-libs/nm/docs/plans/observability-logging.md` | 2, 3 (copy), 4 | to write (start of nm session) |
| `certinext-zabbix` | `certinext-zabbix/docs/plans/observability-logging.md` | 4 + systemd unit | to write (start of session) |
| `ums-certinext-scripts` | `ums-certinext-scripts/docs/plans/observability-logging.md` | 4 (dcv-update, top-domains) | to write (start of session) |
| Ansible role | `<role>/docs/` or role README | 5 | to write (start of session) |

## Dependency graph

```
        ┌─────────────────────────────┐
        │ 1. IDEA-008 shared options  │  (unblocks the clean override/path
        └──────────────┬──────────────┘   flags for 2 & 3)
                 ┌──────┴───────┐
                 ▼              ▼
      ┌────────────────┐  ┌───────────────────┐
      │ 2. syslog-aware│  │ 3. debug-log file │
      │   (--log-mode) │  │  (--debug-log-path)│
      └───────┬────────┘  └─────────┬─────────┘
              └────────┬────────────┘
                       ▼
         ┌──────────────────────────────┐
         │ 4. wire options into all CLIs │
         └───────────────┬───────────────┘
                         ▼
         ┌──────────────────────────────┐
         │ 5. Ansible role: dir+logrotate│
         └──────────────────────────────┘
```

## Sequencing note / fallback

The **debug-log file (Phase 3) is the operationally urgent piece** — it's what
the 2026-08-03 incident actually needed. Phase 1 (IDEA-008) is the largest and
riskiest, and may not finish in one day. If Phase 1 slips, Phase 3 can still
ship for `certinext-zabbix` alone by **hand-wiring `--debug-log-path` as a
single `Annotated` option on that one-command CLI** (the same way
`--zabbix-server` is declared today), bypassing the shared-option mechanism.
That gets the traceback-capture safety net into production without waiting on
the refactor. Do **not** hand-wire it into `certinext`'s 10-command CLI as a
stopgap — that's exactly the duplication Phase 1 exists to remove.

## Downstream sub-plan specs

Each downstream repo's session writes its sub-plan (at the path in the sub-plan
index) as its first step, then implements it. Minimum contents:

### `nm` sub-plan
- Mirror the Phase 2 (`--log-mode` + systemd auto-detect) and Phase 3
  (`--debug-log-path`, JSON handler) changes from `certinext`'s
  `cli_support.py` into `nm`'s **independent** `cli_support.py` copy (D6). Keep
  the two copies behaviorally identical; note in the sub-plan that they are
  hand-synced (no shared module — see IDEA-009 cons / ADR 0007).
- Phase 4: wire `--log-mode` + `--debug-log-path` into nm's CLI. Env var
  `NM_DEBUG_LOG`; confirm nm's deployed log path (TBD — ask, don't assume).
- Verify: nm's own logging tests still pass; add coverage mirroring
  `certinext`'s new tests.

### `certinext-zabbix` sub-plan
- Phase 4 only (library changes come transitively from the `certinext` dep bump
  — pin to the `certinext` version that ships Phases 1–3).
- Wire `--log-mode` + `--debug-log-path` (env `CERTINEXT_ZABBIX_DEBUG_LOG`)
  into the single `zabbix_push_cli.py` command, same `Annotated`/`envvar`
  pattern as `--zabbix-server`.
- Update `examples/systemd/certinext-zabbix-push.service` (+ the `-expiry`
  unit): add `CERTINEXT_ZABBIX_DEBUG_LOG=/var/log/certinext-zabbix/debug.log`
  to the `EnvironmentFile`, and add `/var/log/certinext-zabbix` to
  `ReadWritePaths` (currently only `/tmp`). Do **not** set `PrivateTmp`.
- Update `docs/deployment.md` env-var table.
- **Fallback role:** if Phase 1 (IDEA-008) slips, this is the repo where
  `--debug-log-path` gets hand-wired as a stopgap (see
  [Sequencing note](#sequencing-note--fallback)).

### `ums-certinext-scripts` sub-plan
- Phase 4 for **both** `dcv_update_cli.py` and `top_domains_cli.py` (they share
  the `setup_logging()` call). Env `CERTINEXT_SCRIPTS_DEBUG_LOG`, path
  `/var/log/certinext-scripts/debug.log`.
- This is where the **user-requested TODO** is recorded: "adopt the shared
  logging options (`--log-mode`, `--debug-log-path`) in dcv-update." Add it to
  the repo's TODO/plan surface so it isn't lost if the session is split.
- Update `docs/deployment.md`.

### Ansible role sub-plan (Phase 5)
- For each deployed script's host, create the log dir from the D7 table, owned
  by that unit's service user (e.g. `certinextzbx:certinextzbx` for
  certinext-zabbix), mode `0750`.
- Drop a `/etc/logrotate.d/<name>` policy (D1): daily or size-based, compress,
  a sane `rotate` count, `missingok`, `notifempty`. Oneshot timers reopen the
  file each run, so **no `copytruncate` needed** — plain rotation is safe.
- Set the repo's debug-log env var in the deployed `EnvironmentFile`.
- Add the dir to the unit's `ReadWritePaths`.
- Splunk (D2): the file is JSON-lines; ensure the forwarder's inputs/props
  target it with a JSON sourcetype (`KV_MODE=json`, `SHOULD_LINEMERGE=false`).
  Confirm whether Splunk config is in this role or a separate one — ask.

## Repos touched

- `python-libs/certinext` — `cli_support.py` (shared lib), `cli/*.py` (10 cmd
  files + hoisting logic for IDEA-008), wishlist status updates, ADRs.
- `python-libs/nm` — its parallel `cli_support.py` copy (D6).
- `certinext-zabbix` — `zabbix_push_cli.py` option wiring, systemd unit example,
  deployment docs.
- `ums-certinext-scripts` — `dcv_update_cli.py`, `top_domains_cli.py` option
  wiring, deployment docs; the "adopt shared logging options" TODO the user
  asked to record lives here.
- The Ansible role that deploys the scripts (Phase 5) — path + owner from the
  D7 table.

## References

- [structlog — processors & filtering bound logger](https://www.structlog.org/en/stable/api.html)
- [Python `logging.handlers` — file handlers](https://docs.python.org/3/library/logging.handlers.html)
- [logrotate(8)](https://man7.org/linux/man-pages/man8/logrotate.8.html)
- [systemd.exec — `INVOCATION_ID`, `JOURNAL_STREAM`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#%24INVOCATION_ID)
- [ADR 0007 — logfmt default for non-interactive logging](../../adr/0007-logfmt-default-for-non-interactive-logging.md)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 4.8,
> `claude-opus-4-8`) from a conversation with Tod Detre on 2026-08-03. May
> contain inaccuracies or hallucinated details; verify specifics against
> current sources before relying on them.
