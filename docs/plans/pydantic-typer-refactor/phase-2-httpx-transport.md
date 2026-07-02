---
status: planned
depends-on: [phase-1]
implements-adr: [0003]
---

# Phase 2 — httpx transport and exception rebase

Tracking: issue #15 · milestone %v1.0.0 · label ~"refactor-v1"

Replace `requests` with [httpx](https://www.python-httpx.org/) in
`client.py`/`auth.py`, and rebase the exception hierarchy off
`requests.HTTPError`. Sequenced after phase 1 to serialize test churn, not
because of a hard dependency.

## The deliberate break

`CertiNextAPIError` currently subclasses `requests.HTTPError`. It will
subclass plain `Exception` (still named/structured the same:
`.status_code`, `.body`, `.ems_code`, `.field_errors`, `.retry_after`,
`CertiNextConflictError.existing_domain_id` — consumers rely on
`.status_code`/`.body` everywhere). Consequences to handle in this phase,
not discovered later:

- **Healthcheck classification** (`healthcheck_cli.py:290-362`) depends on
  catch *order* because of the old subclassing. Rewrite: catch
  `CertiNextRateLimitError`/`CertiNextAPIError` first (unchanged), then
  `httpx.HTTPError` for transport-level failures
  ([httpx exceptions](https://www.python-httpx.org/exceptions/)), and add an
  explicit clause for pydantic `ValidationError` → classify as SERVER_BUG
  (shape drift is a vendor signal, not a network failure). This closes the
  gap where a 2xx-with-bad-shape could crash the instrument.
- Any consumer catching `requests.exceptions.*` around certinext calls
  breaks — call this out in the migration guide (phase 6). The survey found
  none in ums-certinext-scripts (it catches `CertiNextAPIError`).

## Behavior to preserve exactly

- OAuth2 client-credentials flow: token cached, refreshed 60 s before
  expiry, `invalidate()`, and **retry-exactly-once with a fresh token on
  401** (mid-poll revocation happens in practice).
- Token-endpoint failures raise `RuntimeError` whose message carries the
  status/`invalid_client` markers — the healthcheck string-matches these
  (register R13). If this contract changes, change the healthcheck in the
  same commit.
- 429: `Retry-After` parsed as numeric seconds → `.retry_after`, `None` on
  parse failure (R14).
- RFC 7807 + Spring error-body parsing and the `path`-in-`__str__`
  diagnostics (R15).
- `get_bytes` for binary downloads; per-request bearer header; timeouts at
  least as strict as today.
- OrderWorkflow's 422 download retry loop (R11) sits above the client and
  is untouched.

Implementation choice left open (record which): hand-rolled token handling
ported as-is onto `httpx.Client`, vs a custom
[`httpx.Auth`](https://www.python-httpx.org/advanced/authentication/)
implementation. Prefer whichever keeps the 401-retry-once semantics most
legible; do not add general retry/backoff — that's deliberate (callers and
OrderWorkflow own retries).

Also deliberate: **no response caching in 1.0** (wishlist IDEA-006 records
why). The constraint this phase must honor is the *seam*: all HTTP flows
through the one client choke point, so an RFC 9111 cache (e.g.
[hishel](https://hishel.com/)) can wrap the transport later without touching
accessors or models. Don't scatter ad-hoc `httpx` calls that would bypass
it — the token endpoint call in `auth.py` is the single allowed exception,
as today.

## Implementation steps

1. Rewrite `auth.py` on httpx; port token tests.
2. Rewrite `client.py` (`httpx.Client`, error mapping, `get_bytes`); port
   client tests (MagicMock spec updates).
3. Rebase `exceptions.py`; update healthcheck classification + its tests as
   above.
4. Swap deps: `httpx` in, `requests` + `types-requests` out; sweep for
   remaining `requests` imports (tests included).
5. Merge `main` first if any fix landed since phase 1.

## Verification

- Unit suite green; `pytest -m probe` and `pytest -m integration` green
  against sandbox; `certinext-healthcheck` and `--sandbox` live runs green
  (prod read-only) — same instrument, new transport.
- Grep gates: no `import requests` anywhere in `certinext/`; no
  `requests.HTTPError` in tests.

## Documentation expectations

Migration guide entry (exception base change, examples of before/after
`except` blocks); README error-handling section; docstrings on rewritten
classes per house style.

---
> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Fable 5,
> `claude-fable-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
