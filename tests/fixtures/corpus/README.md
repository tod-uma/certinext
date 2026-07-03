# CertiNext payload corpus

Sanitized captures of real CertiNext API responses, one JSON file per
endpoint, per environment (`prod/`, `sandbox/`). Each file records the
request (method, path, params), the response status, the **response
headers**, and the JSON body.

These files are:

- the ground-truth fixtures the 1.0 pydantic models must parse (ADR 0005
  Confirmation);
- the shape evidence for assumption-register rows R07 (bare-array vs
  wrapper-dict lists), R08 (DCV field-name variance), and R20 (org list vs
  detail field sets) — see
  `docs/plans/pydantic-typer-refactor/phase-0-guardrails-and-probe-suite.md`;
- the input for deciding wishlist IDEA-006 (caching): whether the API sends
  `ETag` / `Last-Modified` / `Cache-Control`.

## Recapturing

```bash
uv run python scripts/capture_corpus.py            # production (read-only GETs)
uv run python scripts/capture_corpus.py --sandbox  # sandbox
```

Credentials resolve like the integration tests: OS keyring (default profile
for prod, `sandbox` profile for sandbox) or `CERTINEXT_[SANDBOX_]CLIENT_ID` /
`..._CLIENT_SECRET` environment variables.

## Sanitization is a manual gate

The capture script pseudonymizes domain names (label-wise, hierarchy
preserved), org and person names, emails, phone numbers (digit-preserving),
and identifiers (including the vendor's `*Number` variants) with a
**deterministic** salted-hash mapping — recaptures of unchanged server state
diff cleanly. Certificate PEM blobs are left as-is (public via CT logs), and
geography fields (state, locality, country) are kept — they appear verbatim
in publicly-logged OV certificates. The full mapping is documented in the
`scripts/capture_corpus.py` docstring.

**A human must review the diff of this directory before every commit** —
the sanitizer is key-driven and a new/renamed API field carrying a real
domain, name, or email would pass through unsanitized until its key is added
to the mapping.
