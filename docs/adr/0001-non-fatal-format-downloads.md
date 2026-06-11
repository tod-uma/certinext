# Non-fatal error handling for optional certificate format downloads

- Status: accepted
- Date: 2026-06-11

## Context

`certinext-issue-cert` can download a certificate in several formats after
issuance: PEM (the primary bundle), DER, and PKCS#7/P7B.  The PEM bundle is
the core deliverable; DER and PKCS#7 are optional extras written when the
caller passes `--der-out`, `--pkcs7-out`, or `--all-formats-out`.

In June 2026 we found that the CertiNext API returns **HTTP 406** for the
PKCS#7 `Accept` header — the format appears unsupported despite appearing in
the OpenAPI spec.  The original code used `fatal_api_error()` (a `NoReturn`
that calls `sys.exit(1)`) for every format download, which meant a PKCS#7
failure would crash the script even though the cert was already issued and the
PEM written successfully.

## Decision

All binary format downloads use a non-fatal wrapper (`_try_download_write_binary`).
On any `CertiNextAPIError` or `OSError`, the wrapper logs a structured warning
and returns `False`; the caller continues writing any remaining formats.
`fatal_api_error` is reserved for failures where no useful work can proceed
(e.g. the issuance request itself failing).

## Consequences

- Callers of `--all-formats-out` get whatever formats succeed rather than
  nothing at all when one format is broken on the server side.
- Failures are visible in structured log output (`log.warning`) but do not
  set a non-zero exit code — callers who need to detect partial failure must
  inspect log output.  This is acceptable because the cert is already issued
  and the primary PEM output is written by a separate, still-fatal path.
- New format download methods added in future should use the same wrapper
  rather than `fatal_api_error`.

## Alternatives considered

- **Keep `fatal_api_error` for all formats:** rejected — a vendor-side gap in
  one optional format should not discard an already-issued certificate.
- **Separate exit codes for partial success:** deferred — adds complexity with
  little practical benefit given structured log output.
