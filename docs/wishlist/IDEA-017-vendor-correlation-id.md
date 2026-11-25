# IDEA-017: Show the vendor's `x-correlation-id` in API errors and logs

- **Status:** Proposed
- **Created:** 2026-11-25
- **Updated:** 2026-11-25
- **Coordinating issue:** #45

## Context

CertiNext puts an `x-correlation-id` response header on its API responses
(seen on every successful v3 response checked on 2026-11-25; error responses
were not checked). Vendor support asks for that ID when they trace a call:
their reply on vendor ticket #191815 asked for the request's "request or
correlation ID".

The library already keeps the raw `httpx.Response` on
`CertiNextAPIError.response` (`certinext/exceptions.py`), but nothing shows
the header. Neither the exception message nor any log line includes it. To
answer the vendor, we re-ran the call with a scratch script that printed the
response headers.

The name clashes with our own `correlation_id` log field
([ADR 0011](../adr/0011-always-on-json-debug-log-sidecar.md)), which is a
per-run ID we generate. That ID means nothing to the vendor.

## The idea

- Expose the header on `CertiNextAPIError` (for example a
  `vendor_correlation_id` attribute) and include it in `str(exc)`, so a
  failed call's ID is in every traceback and CLI error line.
- Log it on failed requests. Possibly also log it in the debug sidecar for
  every request, so a call that succeeded but returned wrong data (like the
  empty `reports/certificates` body) can be traced without a re-run.
- Use a field name that cannot be confused with our run `correlation_id`.

## Why not now

It came up while wrapping up the #191815 follow-up on 2026-11-25; there was no
code change open in this repo to carry it, and `main` is at a released rc. It
is worth doing the next time the client or logging code changes, or the next
time the vendor asks for a trace ID.

## Pros

- Vendor tickets get a traceable ID straight from the log, with no re-run.
- A re-run happens later than the original failure, and may not even fail the
  same way.

## Cons / costs

- A new public attribute on the exception, so it is API surface once released.
- One more log field; per-request logging would add volume to the sidecar.

## Effort

Small: read one header in `_raise_api_error`, add an attribute and a log
field, add tests.

## Open questions & caveats

- Do v2 responses and the OAuth token endpoint send the header too? Only v3
  has been checked.
- Failures only, or every request in the debug sidecar?
- Is the ID worth logging to the operational stderr line, or only the sidecar?

## Next steps

1. Check a v2 response, a v3 error response, and a token-endpoint failure
   for the header.
2. Decide the field name and where it is logged, then implement with the next
   client change.

## References

- [httpx `Response.headers`](https://www.python-httpx.org/api/#response)
- Vendor ticket #191815 (CertiNext support), reply of 2026-11-24.

---

> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5.5,
> `claude-opus-5-5`) from a conversation with Tod Detre. May contain
> inaccuracies or hallucinated details; verify specifics against current
> sources before relying on them.
