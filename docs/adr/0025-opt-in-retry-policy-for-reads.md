---
status: accepted
date: 2026-11-20
---

# An opt-in retry policy for reads, on the session

## Context and problem statement

The client raised `CertiNextRateLimitError` (with `retry_after`) on a 429 and
retried nothing. Two callers carried their own private 429-only loops:

- `certificate_lookup._retry_rate_limit`, three tries, which also slept once
  more after the last attempt before re-raising;
- `replacement._inspect_into`, three tries per certificate, pausing every
  parallel worker through a shared `_Backoff` while one waited out a 429.

Nothing retried 502/503/504, which is how CertiNext's gateway reports a
short outage. The planned Splunk modular input polls on a schedule, where a
single gateway blip should not lose a run. The token request already has its
own retry in `auth.py`, which stays as it is.

## Considered options

- **Keep per-caller loops.** Every new consumer writes another one, and they
  already disagree on the sleep-after-last-attempt detail.
- **Always retry inside the client.** Changes behaviour for every existing
  consumer, including scripts that want to fail fast.
- **An opt-in `RetryPolicy` on the session**, applied by the client to
  reads only.

## Decision outcome

Chosen: an opt-in `RetryPolicy` on the session.

- **Opt-in.** `certinext.session(retry=RetryPolicy())`,
  `sess.retry = ...`, or `with sess.retrying(policy):` for a block. The
  default stays None: the first failure raises, as before.
- **Reads only.** `CertiNextClient.get` and `get_bytes` retry; `post`,
  `put`, `patch` and `delete` never do. Certificate creation is not
  idempotent ([ADR 0020](0020-multi-ca-domains-fail-closed-and-opt-in-create-recovery.md)),
  and a 429 on a write is left to the caller rather than trusting the
  vendor's "not processed" semantics.
- **Statuses** 429, 502, 503 and 504 by default; callers can change them.
- **Retry on the typed error, not the raw response.** The loop wraps one
  request that already raised `CertiNextAPIError`, so a 429's
  `retry_after` and a 5xx's `Retry-After` header are honoured the same
  way.
- **Waits.** `Retry-After` when present (delta-seconds only), otherwise
  `delay` doubled per retry (5 s, then 10 s), capped at `max_delay`
  (120 s). A `Retry-After` above `max_delay` is not retried at all:
  retrying sooner than asked only earns another 429, and a long wait is
  the caller's decision. **No sleep after the last attempt**; the lookup
  helper's extra sleep is not carried over.
- **A `sleep` hook.** The policy calls `sleep(seconds)`, `time.sleep` by
  default. replacement-report passes `_Backoff.pause_then_wait`, so a retry
  in one worker still pauses all of them and waits out any overlapping
  pause, which is what the old loop did.
- **Both private loops move onto it.** The lookup scan runs under the
  caller's policy if the session has one, otherwise the defaults.
  replacement-report keeps the caller's numbers and swaps in the shared
  pause. Each sets the policy with `sess.retrying(...)` once, before any
  worker starts, and restores the previous one afterwards. Per-row error
  recording stays in replacement-report.

Transport errors (timeouts, connection failures) are not retried: a read
timeout on a slow endpoint is usually not transient, and retrying it would
multiply the wait.

### Consequences

- The lookup scan and replacement-report now also retry 502/503/504, and
  the lookup retries the orders-report read itself. A retried request logs
  one warning with the status, attempt and wait.
- The policy lives on the session's single client, so every accessor and
  every model already returned uses it. Setting it while other threads are
  mid-request is the caller's responsibility; `retrying()` documents
  setting it before starting workers.
- Tests that fake the client below `get` (`_get_json`) still exercise the
  retry loop.

## More information

- [ADR 0020](0020-multi-ca-domains-fail-closed-and-opt-in-create-recovery.md):
  why creates are never retried automatically.
- [RFC 9110 §10.2.3, Retry-After](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3)

---
> **AI-assistant disclaimer:** Drafted by Claude (Opus 5.5) from a conversation
> with Tod Detre. May contain inaccuracies; verify specifics against current
> sources before relying on them.
