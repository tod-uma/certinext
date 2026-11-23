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
  `docs/plans/archive/pydantic-typer-refactor/phase-0-guardrails-and-probe-suite.md`;
- the input for deciding wishlist IDEA-006 (caching): whether the API sends
  `ETag` / `Last-Modified` / `Cache-Control`;
- the `v3-*` files (from 2026-11-23): v3 orders, audit logs, users, roles,
  group members, API credentials and discovered certificates, the shape
  evidence for the v3 accessors.

## Recapturing

```bash
uv run python scripts/capture_corpus.py              # production (read-only GETs)
uv run python scripts/capture_corpus.py --sandbox    # sandbox
uv run python scripts/capture_corpus.py --only v3-   # write only the v3 files
uv run python scripts/capture_corpus.py --profile readonly  # another credential
```

Credentials resolve like the integration tests: OS keyring (default profile
for prod, `sandbox` profile for sandbox, or `--profile`) or
`CERTINEXT_[SANDBOX_]CLIENT_ID` / `..._CLIENT_SECRET` environment variables.

To see *what a credential can read* without capturing payloads, run
`scripts/probe_access.py`: it prints statuses, counts and key names only.

## Sanitization is a manual gate

The capture script pseudonymizes domain names (label-wise, hierarchy
preserved), org and person names, emails, phone numbers (digit-preserving),
and identifiers (including the vendor's `*Number` variants) with a
**deterministic** salted-hash mapping — recaptures of unchanged server state
diff cleanly. Certificate PEM blobs are left as-is (public via CT logs), and
geography fields (state, locality, country) are kept — they appear verbatim
in publicly-logged OV certificates. The full mapping is documented in the
`scripts/capture_corpus.py` docstring.

Names inside free text (audit-log `activity`, role names) are replaced
using the names already pseudonymized under a key during the run, plus
templates for audit lines that name an object directly (credential labels,
groups, users) so even deleted objects are caught. API credential
descriptions become `Cred-<hash>` labels.

After writing, the script runs a **leak check**: it searches every file it
wrote for every raw value it replaced, and exits non-zero with `LEAK` lines
naming the file, the JSON key path and the pseudonym that belonged there
(never the raw value). A `LEAK` means a rule is missing; fix the sanitizer,
don't commit.

**A human must still review the diff of this directory before every
commit.** The sanitizer is key-driven and the leak check only knows values
it saw under a key, so a new or renamed API field carrying a real domain,
name, or email can still pass through unsanitized until its key is added to
the mapping.
