---
status: accepted
date: 2026-10-21
---

# Cache certificate downloads per command, opt-in, never volatile state

## Context and problem statement

`certinext replacement-report --inspect` downloads every valid certificate (order
detail plus certificate, two requests each). In production that took about 18
minutes for about 665 certificates. The downloads barely change between runs, so
working through the eMudhra ECC replacements
([0018](0018-classify-replacement-on-configurable-signals.md)) meant a long wait
for every re-check. Tod asked for a cache with explicit on/off flags, a prompt
when neither is given, and a flag for where it lives.

The report decides which production certificates get reissued. A cache that
serves stale data and changes a verdict is worse than a slow run. General
response caching ([IDEA-006](../wishlist/IDEA-006-response-caching.md)) is
parked, and its rule is "never cache volatile state". The question is **what
shape of cache is allowed, and where**.

## Decision drivers

- A cached run must never give a verdict a live run would not, without saying so.
- Volatile state (order status, DCV status) is never cached (IDEA-006).
- Scheduled or piped runs keep the always-live rc4 behaviour.
- A cache problem must never abort a long inventory run.
- Entries hold orderer names and emails, so they must stay private to the user.

## Considered options

1. **No cache.** Every `--inspect` run is live (rc4).
2. **General response caching** in the client (IDEA-006).
3. **A narrow, opt-in cache that belongs to one command**, holding only that
   command's certificate downloads.

## Decision outcome

Chosen: **option 3**. A cache in certinext belongs to the command that needs it,
and follows these rules:

- **Opt-in.** `--cache/--no-cache`, `--refresh-cache` and `--cache-dir` (the
  last two imply `--cache`). With no flag, a terminal is asked and Enter means
  no. A non-interactive run stays off.
- **Narrow key.** The key is (order number, certificate serial), so a reissue
  or rekey is always a miss.
- **Raw payload.** The cache stores the raw download, not the parsed result.
  Every hit is re-validated and re-parsed, and a payload that no longer parses
  is a miss.
- **Only clean results.** Errors, 429 give-ups, unparseable or chainless
  downloads, and rows with no serial are never written. Order status is never
  cached: the orders report is read live every run, so a revoked or expired
  certificate drops out at once.
- **Bounded age.** Entries older than 7 days are misses, and each run prunes
  them.
- **Every failure is non-fatal.** An unreadable entry is a miss, a failed write
  logs one warning, and a directory that can't be listed skips pruning.
- **Private and separate.** Entries live in a per-user local cache directory,
  `0700` on POSIX, with production and sandbox kept apart.
- **Visible.** Each run reports its hit/miss counts and the age bound in the
  summary and in the JSON `cache` block.

The full design and its reasoning are in
[the plan](../plans/replacement-report-cache.md).

### Consequences

- Good: a repeat production run went from 18m30s to 38s with identical verdicts
  (665 hits, 3 live misses for new certificates).
- Good: IDEA-006 stays parked. This cache does not open the door to caching
  status.
- Bad: if CertiNext changes a certificate's served chain without changing its
  serial, a cached run shows the old chain for up to 7 days. This is the event
  the report exists for. It is accepted because the cache is opt-in, the run
  says "up to 7 days old", and `--refresh-cache` or `--no-cache` gives a live
  answer. Before acting on a re-root, run live.
- Bad: the orderer name and email are replayed from the cache too, so a
  correction made after issuance shows up only after a refresh. They don't
  affect the verdict.
- Neutral: another command that wants a cache gets its own narrow cache under
  these rules, not a shared layer.

### Confirmation

`tests/test_replacement.py` covers the following:

- a warm cache makes no certificate calls and gives identical results;
- expiry, pruning and refresh;
- failures and rows with no serial are not cached;
- bad, unparseable and mismatched entries are misses;
- an unwritable or unlistable cache is not fatal;
- concurrent writes leave only whole files;
- the CLI flag and prompt rules, and the production/sandbox split.

An external review (GPT-6 via Codex, 2026-10-21) found the unlistable-directory
case, which is now fixed and tested. It also raised the chain and orderer
staleness recorded above as accepted.

## Pros and cons of the options

### 1. No cache
- Good, because every answer is live.
- Bad, because each re-check during the incident took about 18 minutes.

### 2. General response caching (IDEA-006)
- Good, because it would speed up every command.
- Bad, because the hard part is invalidation across endpoints, and caching
  status in a tool that observes the live vendor is exactly the risk IDEA-006
  parked it for. Too big to design during an incident.

### 3. Narrow, opt-in cache for one command
- Good, because its rules can be tight: one key, one payload, nothing volatile.
- Good, because it is off unless someone chooses it, and the run says so.
- Bad, because it can serve a served-chain change late, up to the age bound.

## More information

- [MADR](https://adr.github.io/madr/): the format this record follows.
- [`os.replace`](https://docs.python.org/3/library/os.html#os.replace) and
  [`tempfile.NamedTemporaryFile`](https://docs.python.org/3/library/tempfile.html#tempfile.NamedTemporaryFile):
  atomic entry writes.
- [XDG base directory spec](https://specifications.freedesktop.org/basedir-spec/latest/)
  and [Windows known folders](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid):
  the cache location.
- [typer bool options](https://typer.tiangolo.com/tutorial/parameter-types/bool/):
  the `--cache/--no-cache` flag.
- Related: [0018](0018-classify-replacement-on-configurable-signals.md) (what the
  report classifies on), [IDEA-006](../wishlist/IDEA-006-response-caching.md)
  (general caching, parked; coordinating issue #12 stays open).

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Haiku 5.5,
> `claude-haiku-5-5`) from a conversation with Tod Detre; the design it records
> was done in earlier sessions on 2026-10-21. May contain inaccuracies or
> hallucinated details; verify specifics against current sources before relying
> on them.
