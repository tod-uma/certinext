---
status: in-progress
depends-on: [replacement-report]
implements-adr: [0019]
---

# Plan: opt-in inspection cache and run timestamps for `replacement-report`

**Status:** in progress on branch `feat/replacement-report-cache` (version `1.3.0rc5`), started
2026-10-21. This repo copy supersedes the private plan-mode draft it was moved from.

## Context

`certinext replacement-report --inspect` downloads every valid certificate (order detail plus
certificate, two requests each). With four workers that is ~20 minutes for ~634 certificates in
prod (see [replacement-report.md](replacement-report.md)). The downloads barely change between
runs, so working through the remaining eMudhra-ECC replacements meant waiting 20 minutes per
re-check. Goal: a repeat run in about a minute, without letting stale data decide what still needs
replacing.

Separately, the `--json` field `generated_at` was the run's **start** (the reference "now" read
before the orders report). On a 20-minute run that misstates when the data was complete.

Requirements from Tod (2026-10-21):

- Flags to turn the cache **on and off** explicitly; with neither, **prompt** for which.
- A flag for **where** the cache is stored.
- Run **start and end** times in the report.

Constraints: read-only against the API; the repo is published (GitHub/PyPI), so no real order
numbers or hostnames in tests or docs; IDEA-006 (general response caching) stays parked.

## Decisions

### CLI surface

`--cache/--no-cache` (tri-state, default unset), `--refresh-cache`, `--cache-dir DIR`.
`--refresh-cache` and `--cache-dir` imply `--cache`. Any of the three without `--inspect`, or
`--no-cache` combined with `--refresh-cache`/`--cache-dir`, exits 2. `--no-cache` alone is
always accepted. The choice is resolved before the session is built, so the prompt never
interleaves with a credential prompt.

With none of the flags: on a terminal, ask `Use cached inspections up to 7 days old (faster, may be
stale)? [y/N]` on stderr; off a terminal, stay off and log that.

<details>
<summary>Why Enter means no, and why non-interactive runs stay off</summary>

- Reusing week-old downloads should be a deliberate choice; the safe answer is the default.
- A scheduled or piped run cannot answer a prompt. Blocking it, or failing it, would be worse than
  the rc4 behaviour (always live), so non-interactive runs keep that behaviour.
- `--cache` without `--inspect` would silently do nothing, so it is an error rather than ignored.
  `--no-cache` is harmless anywhere, so wrappers can always pass it.
</details>

### What is cached, and the key

Key: (order number, certificate serial). Entry: the **raw** download payload plus the order
detail's orderer name/email, with `fetched_at` and a layout `version`. Max age 7 days
(`DEFAULT_MAX_AGE`); expired entries are misses and are pruned at the start of each run.

Never cached: any inspection error (API, transport, 429 give-up, unparseable, no chain), rows with
no serial, and order status: the orders report is read live every run.

<details>
<summary>Why these rules</summary>

- Serial in the key: a reissue or rekey under the same order is always a miss.
- Raw payload, not the parsed result: each hit is re-validated and re-parsed, so parser fixes apply
  to cached data. A cached payload that no longer parses is a miss (download again), not an error.
- 7 days: the served `chainPem` can change, and a CA re-rooting is exactly the event this command
  exists for.
- Order status stays live, so a revoked or expired certificate drops out at once. This is what
  keeps the cache inside IDEA-006's "never cache volatile state" rule.
- Errors are not cached so a transient failure never becomes a week-long one.
</details>

### Storage

`certinext._config.cache_dir()`: `%LOCALAPPDATA%\certinext\cache` on Windows,
`$XDG_CACHE_HOME/certinext` (default `~/.cache/certinext`) elsewhere
([XDG base directory spec](https://specifications.freedesktop.org/basedir-spec/latest/),
[Windows known folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid)).
The command adds `replacement-inspect/`, then `production/` or `sandbox/` from `sess.sandbox`.
`--cache-dir DIR` replaces `<base>/replacement-inspect`; the production/sandbox split stays.

One JSON file per entry, named by `sha256(order|serial)`, written atomically via a temp file in the
same directory ([`tempfile.NamedTemporaryFile`](https://docs.python.org/3/library/tempfile.html#tempfile.NamedTemporaryFile))
plus [`os.replace`](https://docs.python.org/3/library/os.html#os.replace). The directory is `0700`
on POSIX. Every cache failure is non-fatal: an unreadable entry is a miss, and a failed write logs
one warning per run.

<details>
<summary>Why these choices</summary>

- Local, not roaming, app data: a cache should not follow the user between machines.
- Per-user, private directory: entries hold orderer names and emails.
- Sandbox and production apart: one must never answer for the other.
- Hashed file names: order numbers and serials never have to be valid, or non-reserved, Windows
  file names.
- Atomic writes: inspection runs on up to 16 threads.
- Windows refuses `os.replace` onto a file another writer is replacing at that moment
  (`WinError 5`, found by the concurrency test), so the replace retries briefly. Within one run
  each certificate has its own key, so this only matters for concurrent runs.
</details>

### Timestamps

Library: `ReplacementReport.generated_at` is renamed `started_at` (still the validity/`days_left`
"now"); new `ended_at` (taken after classification) and `cache` (`CacheStats`, or `None`). JSON
gains `started_at`, `ended_at` and a `cache` block. `generated_at` is kept and now equals `ended_at`.

<details>
<summary>Why keep generated_at, and why days_left stays on the start time</summary>

- Keeping `generated_at` means existing JSON readers don't break; making it the end time means the
  name matches what it holds. The library rename is a breaking change, acceptable in an rc, and
  goes in the tag changelog.
- `days_left` is measured from the moment the orders report was read and validity was decided.
  Measuring it from the end would mix two reference times in one report.
</details>

### Visibility

The summary line appends `N of M inspections from cache (up to 7 days old)`. JSON `cache` has
`enabled`, `dir`, `refreshed`, `max_age_days`, `hits`, `misses`, `writes` (`{"enabled": false}` when
off). Per-row: `CertificateFacts.from_cache` (library only; not added to the CSV/JSON columns).

## Implementation (done on the branch unless noted)

1. `certinext/_config.py`: `cache_dir()`.
2. `certinext/_inspection_cache.py`: `InspectionCache` (`get`, `put`, `prune`, `writes`),
   `CachedInspection`, `DEFAULT_MAX_AGE`; re-exported from `certinext.replacement`.
3. `certinext/replacement.py`: `CertificateFacts.from_cache`, `CacheStats`,
   `ReplacementReport.started_at`/`ended_at`/`cache`; `_inspect_from_cache()` before the download
   loop in `_inspect_into()`, and `cache.put()` after a clean live result; `build_report(cache=)`
   prunes once and logs `Inspection cache` and `Report built` (duration).
4. `certinext/cli/replacement_report.py`: the flags ([typer bool options](https://typer.tiangolo.com/tutorial/parameter-types/bool/)),
   `_resolve_cache()`, `_build_cache()`, the summary-line and JSON additions.
5. Tests in `tests/test_replacement.py`; help golden regenerated.
6. Docs: README (CLI section "Reusing downloads between runs", JSON timestamps, library example,
   module tree), IDEA-006 note, this plan, and
   [ADR 0019](../adr/0019-command-local-opt-in-inspection-cache.md).

## Verification

- `uv run pytest`, `uv run mypy certinext`, `uv run ruff check` (never `ruff format` in this repo).
- Tests cover: warm cache makes zero `ssl-certificates` calls with identical results; expiry and
  prune; refresh; errors, 429 give-ups, unparseable and chainless downloads, and serial-less rows
  are not cached; a new serial is a miss; garbage, unparseable and mismatched entries are misses,
  not errors; an unwritable cache is not fatal; concurrent writes leave only whole files; CLI
  resolution (flags, prompt yes/Enter/EOF, non-terminal), `--cache-dir`, the production/sandbox
  split, the JSON timestamps and the `cache` block.
- **Prod (pending, Tod runs it or approves it):** `certinext replacement-report --inspect --cache
  --json -o run1.json` twice. Expect the second run to take about a minute, `cache.hits` ≈ valid
  count, and verdict counts equal to run 1. Then `--no-cache` to confirm the live path is unchanged.

## Documentation expectations

README and docstrings updated with the code. The tag changelog for `v1.3.0rc5` must call out the
`generated_at` → `started_at` library rename and the JSON `generated_at` meaning change.

## References

- Parent plan: [replacement-report.md](replacement-report.md); [ADR 0018](../adr/0018-classify-replacement-on-configurable-signals.md)
- [IDEA-006](../wishlist/IDEA-006-response-caching.md): general response caching (still parked)
- [`os.replace`](https://docs.python.org/3/library/os.html#os.replace),
  [`tempfile`](https://docs.python.org/3/library/tempfile.html),
  [XDG base directory spec](https://specifications.freedesktop.org/basedir-spec/latest/),
  [Windows known folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid),
  [typer bool options](https://typer.tiangolo.com/tutorial/parameter-types/bool/)

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5.5, `claude-opus-5-5`) from a
> conversation with Tod Detre. May contain inaccuracies; verify specifics before relying on them.
